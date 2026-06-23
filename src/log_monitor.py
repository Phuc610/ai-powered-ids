"""
LogMonitor - Giám sát nhật ký từ máy chủ Linux qua SSH
Đồ án IT3930 - AI-Powered IDS - Đào Huy Phúc - 20236051

Chức năng:
  - Kết nối SSH thật tới VirtualBox (Host-Only Network)
  - Đọc /var/log/auth.log hoặc /var/log/secure
  - Parse log bằng regex để trích xuất: IP, username, event_status
  - Đẩy dữ liệu vào DatabaseConnector
"""

import re
import time
import logging
import paramiko
from datetime import datetime
from typing import Optional, List, Dict, Tuple, Callable

from src.database_connector import DatabaseConnector


logger = logging.getLogger(__name__)


# ---- Regex patterns cho từng loại Linux ----
UBUNTU_PATTERNS = {
    "failed": re.compile(
        r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port \d+"
    ),
    "success": re.compile(
        r"Accepted password for (\S+) from ([\d.]+) port \d+"
    ),
    "invalid_user": re.compile(
        r"Invalid user (\S+) from ([\d.]+)"
    ),
    "disconnect": re.compile(
        r"Disconnected from (?:invalid user )?(\S+)? ?([\d.]+)"
    ),
}

CENTOS_PATTERNS = {
    "failed": re.compile(
        r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port \d+"
    ),
    "success": re.compile(
        r"Accepted password for (\S+) from ([\d.]+) port \d+"
    ),
    "invalid_user": re.compile(
        r"Invalid user (\S+) from ([\d.]+)"
    ),
}


class LogMonitor:
    """
    Đảm nhận việc kết nối với máy chủ Linux để múc dữ liệu thô.

    Attributes:
        target_linux_ip (str): Địa chỉ IP máy chủ
        ssh_client (paramiko.SSHClient): Đối tượng thiết lập kết nối SSH
    """

    def __init__(self, config: dict, db: DatabaseConnector):
        server_cfg = config.get("linux_server", {})
        self.target_linux_ip: str = server_cfg.get("host", "192.168.56.101")
        self.ssh_port: int = server_cfg.get("port", 22)
        self.username: str = server_cfg.get("username", "root")
        self.password: str = server_cfg.get("password", "")
        self.ssh_key_path: str = server_cfg.get("ssh_key_path", "")
        self.log_file: str = server_cfg.get("log_file", "/var/log/auth.log")
        self.os_type: str = server_cfg.get("os_type", "ubuntu").lower()

        self.ssh_client: Optional[paramiko.SSHClient] = None
        self.db = db
        self._running = False
        self._last_position = 0  # Vị trí đọc log lần cuối (giống tail -f)

        # Chọn patterns theo OS
        self._patterns = UBUNTU_PATTERNS if self.os_type == "ubuntu" else CENTOS_PATTERNS

    def connect_ssh(self) -> bool:
        """Mở kết nối SSH tới Linux server."""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": self.target_linux_ip,
                "port": self.ssh_port,
                "username": self.username,
                "timeout": 15,
                "banner_timeout": 15,
            }

            if self.ssh_key_path:
                connect_kwargs["key_filename"] = self.ssh_key_path
            else:
                connect_kwargs["password"] = self.password

            self.ssh_client.connect(**connect_kwargs)
            logger.info(f" SSH connected to {self.target_linux_ip}:{self.ssh_port} ({self.os_type})")
            return True

        except paramiko.AuthenticationException:
            logger.error(f" SSH Authentication failed for {self.username}@{self.target_linux_ip}")
        except paramiko.SSHException as e:
            logger.error(f" SSH Error: {e}")
        except Exception as e:
            logger.error(f" Cannot connect to {self.target_linux_ip}: {e}")
        return False

    def read_secure_log(self, lines: int = 500) -> str:
        """Đọc file nhật ký bảo mật từ Linux server."""
        if not self.ssh_client:
            logger.error("SSH not connected. Call connect_ssh() first.")
            return ""
        try:
            # Đọc N dòng cuối của log file (giống tail)
            stdin, stdout, stderr = self.ssh_client.exec_command(
                f"echo '{self.password}' | sudo -S tail -{lines} {self.log_file} 2>/dev/null || "
                f"echo '{self.password}' | sudo -S journalctl -u ssh -u sshd -n {lines} --no-pager 2>/dev/null"
            )
            content = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            if err and "No such file" in err:
                logger.warning(f"Log file not found: {self.log_file}")
            return content
        except Exception as e:
            logger.error(f" Error reading log: {e}")
            self._try_reconnect()
            return ""

    def read_log_stream(self, callback: Callable, poll_interval: float = 5.0):
        """
        Đọc log liên tục (giống tail -f) và gọi callback mỗi khi có dòng mới.
        Dùng cho chế độ realtime monitoring.
        """
        if not self.ssh_client:
            logger.error("SSH not connected")
            return

        self._running = True
        logger.info(f" Starting log stream from {self.log_file}...")

        try:
            channel = self.ssh_client.get_transport().open_session()
            channel.exec_command(f"echo '{self.password}' | sudo -S tail -F {self.log_file} 2>/dev/null")
            channel.setblocking(False)

            buffer = ""
            while self._running:
                try:
                    data = channel.recv(4096)
                    if data:
                        buffer += data.decode("utf-8", errors="replace")
                        lines = buffer.split("\n")
                        buffer = lines[-1]  # Giữ lại dòng chưa đầy đủ
                        for line in lines[:-1]:
                            if line.strip():
                                parsed = self.parse_log_regex(line)
                                if parsed:
                                    callback(parsed)
                    else:
                        time.sleep(poll_interval)
                except Exception:
                    time.sleep(poll_interval)

        except Exception as e:
            logger.error(f" Log stream error: {e}")
        finally:
            logger.info(" Log stream stopped")

    def parse_log_regex(self, log_line: str) -> Optional[Dict]:
        """
        Trích xuất dữ liệu bằng biểu thức chính quy.
        
        Returns:
            Dict với keys: ip_address, username, event_status, raw_log
            hoặc None nếu không match
        """
        log_line = log_line.strip()
        if not log_line:
            return None

        # --- Failed login ---
        m = self._patterns["failed"].search(log_line)
        if m:
            return {
                "ip_address": m.group(2),
                "username": m.group(1),
                "event_status": "Failed",
                "raw_log": log_line
            }

        # --- Successful login ---
        m = self._patterns["success"].search(log_line)
        if m:
            return {
                "ip_address": m.group(2),
                "username": m.group(1),
                "event_status": "Success",
                "raw_log": log_line
            }

        # --- Invalid user ---
        m = self._patterns["invalid_user"].search(log_line)
        if m:
            return {
                "ip_address": m.group(2),
                "username": m.group(1),
                "event_status": "Failed",
                "raw_log": log_line
            }

        return None

    def fetch_and_store_logs(self, lines: int = 200) -> int:
        """
        Đọc log từ server và lưu vào DB.
        Returns: Số dòng log đã lưu thành công
        """
        raw_content = self.read_secure_log(lines)
        if not raw_content:
            return 0

        stored_count = 0
        for line in raw_content.split("\n"):
            parsed = self.parse_log_regex(line)
            if parsed:
                log_id = self.db.insert_log_data(
                    ip_address=parsed["ip_address"],
                    username=parsed["username"],
                    event_status=parsed["event_status"],
                    raw_log=parsed["raw_log"]
                )
                if log_id:
                    stored_count += 1

        logger.info(f" Fetched & stored {stored_count} log entries from {self.target_linux_ip}")
        return stored_count

    def _try_reconnect(self, max_attempts: int = 3):
        """Thử kết nối lại SSH nếu bị mất."""
        for attempt in range(1, max_attempts + 1):
            logger.info(f" Reconnecting SSH... attempt {attempt}/{max_attempts}")
            time.sleep(5)
            if self.connect_ssh():
                logger.info(" SSH reconnected successfully")
                return True
        logger.error(" SSH reconnect failed after max attempts")
        return False

    def stop(self):
        """Dừng log stream."""
        self._running = False

    def disconnect(self):
        """Đóng kết nối SSH."""
        if self.ssh_client:
            self.ssh_client.close()
            logger.info(" SSH connection closed")

    def test_connection(self) -> Dict:
        """Kiểm tra kết nối và lấy thông tin server."""
        if not self.connect_ssh():
            return {"success": False, "error": "Cannot connect"}
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(
                "uname -r && hostname && uptime"
            )
            info = stdout.read().decode().strip()
            return {"success": True, "server_info": info, "ip": self.target_linux_ip}
        except Exception as e:
            return {"success": False, "error": str(e)}
