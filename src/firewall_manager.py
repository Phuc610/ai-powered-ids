"""
FirewallManager - Quản lý tường lửa
Đồ án IT3930 - AI-Powered IDS - Đào Huy Phúc - 20236051

Chức năng:
  - block_ip(): Thực thi khóa IP qua iptables/firewalld (trên Linux)
               hoặc simulation mode (trên Mac/Windows)
  - generate_audit_trail(): Lưu vết hành động chặn vào DB
  - Hỗ trợ cả SSH tới Linux server để chạy lệnh iptables từ xa
"""

import logging
import platform
from datetime import datetime, timedelta
from typing import Optional, Dict, List

import paramiko

from src.database_connector import DatabaseConnector


logger = logging.getLogger(__name__)


class FirewallManager:
    """
    Thực thi lệnh OS để chặn kết nối.

    Attributes:
        rule_template (str): Mẫu câu lệnh iptables/firewalld
    """

    # Template lệnh iptables
    IPTABLES_DROP_TEMPLATE = "iptables -I INPUT -s {ip} -j DROP"
    IPTABLES_UNBLOCK_TEMPLATE = "iptables -D INPUT -s {ip} -j DROP"
    FIREWALLD_BLOCK_TEMPLATE = "firewall-cmd --add-rich-rule='rule family=ipv4 source address={ip} drop' --permanent && firewall-cmd --reload"
    FIREWALLD_UNBLOCK_TEMPLATE = "firewall-cmd --remove-rich-rule='rule family=ipv4 source address={ip} drop' --permanent && firewall-cmd --reload"

    def __init__(self, config: dict, db: DatabaseConnector,
                 ssh_client: Optional[paramiko.SSHClient] = None):
        fw_cfg = config.get("firewall", {})
        self.mode: str = fw_cfg.get("mode", "simulation")  # "real" hoặc "simulation"
        self.block_duration_hours: int = fw_cfg.get("block_duration_hours", 24)
        self.whitelist_ips: List[str] = fw_cfg.get("whitelist_ips", ["127.0.0.1"])
        self.linux_config: dict = config.get("linux_server", {})
        self.os_type: str = self.linux_config.get("os_type", "ubuntu")
        self.password: str = self.linux_config.get("password", "")
        self.host: str = self.linux_config.get("host", "")
        self.port: int = self.linux_config.get("port", 22)
        self.username: str = self.linux_config.get("username", "root")

        self.rule_template: str = self.IPTABLES_DROP_TEMPLATE
        self.db = db
        self._ssh_client = ssh_client  # Dùng SSH để chạy iptables từ Mac → Linux

        # Đếm số lần block trong session
        self._block_count = 0

        logger.info(f"  FirewallManager initialized | mode={self.mode} | "
                    f"duration={self.block_duration_hours}h")

    def set_ssh_client(self, ssh_client: paramiko.SSHClient):
        """Gán SSH client (dùng chung với LogMonitor)."""
        self._ssh_client = ssh_client

    def block_ip(self, ip_address: str, rule_id: int, risk_score: float,
                 reason: str = "AI Detection") -> Optional[int]:
        """
        Thực thi khóa IP.

        Args:
            ip_address: IP cần block
            rule_id: ID luật bảo mật bị vi phạm
            risk_score: Điểm rủi ro từ AI (0.0 - 1.0)
            reason: Lý do chặn

        Returns:
            block_id nếu thành công, None nếu thất bại
        """
        # Kiểm tra whitelist
        if ip_address in self.whitelist_ips:
            logger.info(f" IP {ip_address} is whitelisted, skipping block")
            return None

        # Kiểm tra đã block chưa
        if self.db.is_ip_blocked(ip_address):
            logger.info(f"  IP {ip_address} already blocked")
            return None

        # Tính thời gian mở khóa
        release_at = None
        if self.block_duration_hours > 0:
            release_at = datetime.now() + timedelta(hours=self.block_duration_hours)

        # Thực thi lệnh block
        success = self._execute_firewall_command(ip_address, action="block")

        if success:
            # Lưu vào DB
            block_id = self.db.insert_blocked_ip(
                ip_address=ip_address,
                rule_id=rule_id,
                risk_score=risk_score,
                release_at=release_at
            )
            if block_id:
                self._block_count += 1
                self.generate_audit_trail(block_id, ip_address, action="DROP",
                                          description=f"{reason} | risk={risk_score:.3f}")
                logger.warning(f" BLOCKED: {ip_address} | risk={risk_score:.3f} | "
                               f"block_id={block_id} | release={release_at}")
                return block_id

        logger.error(f" Failed to block {ip_address}")
        return None

    def unblock_ip(self, ip_address: str, reason: str = "Manual unblock") -> bool:
        """
        Mở khóa IP thủ công (Admin can thiệp khi False Positive).
        
        Returns:
            True nếu unblock thành công
        """
        if not self.db.is_ip_blocked(ip_address):
            logger.info(f"  IP {ip_address} is not currently blocked")
            return False

        success = self._execute_firewall_command(ip_address, action="unblock")
        if success:
            self.db.unblock_ip(ip_address)
            # Lấy block_id để ghi audit
            result = self.db.execute_query(
                "SELECT block_id FROM blocked_ips WHERE ip_address = %s ORDER BY block_id DESC LIMIT 1",
                (ip_address,)
            )
            block_id = result[0]['block_id'] if result else None
            self.generate_audit_trail(block_id, ip_address, action="UNBLOCK",
                                      description=reason)
            logger.info(f" UNBLOCKED: {ip_address} | reason={reason}")
            return True

        return False

    def _execute_firewall_command(self, ip_address: str, action: str) -> bool:
        """
        Thực thi lệnh iptables thực tế hoặc simulation.
        
        Args:
            ip_address: IP mục tiêu
            action: "block" hoặc "unblock"
        """
        if action == "block":
            if self.os_type == "centos":
                cmd = self.FIREWALLD_BLOCK_TEMPLATE.format(ip=ip_address)
            else:
                cmd = self.IPTABLES_DROP_TEMPLATE.format(ip=ip_address)
        else:
            if self.os_type == "centos":
                cmd = self.FIREWALLD_UNBLOCK_TEMPLATE.format(ip=ip_address)
            else:
                cmd = self.IPTABLES_UNBLOCK_TEMPLATE.format(ip=ip_address)

        if self.mode == "simulation":
            return self._simulate_command(cmd, ip_address, action)
        elif self.mode == "real":
            return self._run_remote_command(cmd)
        else:
            return False

    def _simulate_command(self, cmd: str, ip: str, action: str) -> bool:
        """Giả lập lệnh firewall (dùng khi chạy trên Mac)."""
        action_symbol = "" if action == "block" else ""
        logger.info(f"{action_symbol} [SIMULATION] {cmd}")
        print(f"\n{'='*60}")
        print(f"  FIREWALL {action.upper()}: {ip}")
        print(f"  Command: {cmd}")
        print(f"  Mode: SIMULATION (lệnh không thực thi thật)")
        print(f"{'='*60}\n")
        return True

    def _run_remote_command(self, cmd: str) -> bool:
        """Thực thi lệnh trên Linux server qua SSH."""
        client = self._ssh_client
        temp_client = False
        
        if not client:
            if not self.host:
                logger.error(" SSH client not available and no host config found")
                return False
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(self.host, port=self.port, username=self.username, password=self.password, timeout=10)
                temp_client = True
            except Exception as e:
                logger.error(f" Temporary SSH connection failed: {e}")
                return False

        try:
            # Cần quyền sudo/root
            full_cmd = f"echo '{self.password}' | sudo -S {cmd} 2>&1"
            stdin, stdout, stderr = client.exec_command(full_cmd, timeout=10)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
            
            combined_out = err + " " + output
            if exit_code == 0 or "NOT_ENABLED" in combined_out or "Bad rule" in combined_out or "ALREADY_ENABLED" in combined_out:
                logger.info(f" Remote firewall command executed (or already applied): {cmd}")
                return True
            else:
                logger.error(f" Firewall command failed (exit={exit_code}): err='{err}' | out='{output}'")
                return False
        except Exception as e:
            logger.error(f" SSH command error: {e}")
            return False
        finally:
            if temp_client and client:
                client.close()

    def generate_audit_trail(self, block_id: Optional[int], target_ip: str,
                              action: str = "DROP", description: str = "") -> Optional[int]:
        """
        Lưu vết hành động chặn vào bảng audit_trails.
        
        Returns:
            audit_id nếu thành công
        """
        audit_id = self.db.insert_audit_trail(
            action_type=action,
            block_id=block_id,
            target_ip=target_ip,
            description=description
        )
        logger.debug(f" Audit trail recorded: {action} {target_ip} | audit_id={audit_id}")
        return audit_id

    def process_expired_blocks(self) -> int:
        """Tự động mở khóa các IP hết hạn block."""
        expired = self.db.execute_query(
            """SELECT ip_address, block_id FROM blocked_ips 
               WHERE is_active = TRUE 
               AND release_at IS NOT NULL 
               AND release_at <= NOW()"""
        )

        if not expired:
            return 0

        count = 0
        for record in expired:
            ip = record['ip_address']
            block_id = record['block_id']
            self._execute_firewall_command(ip, action="unblock")
            self.db.unblock_ip(ip)
            self.generate_audit_trail(block_id, ip, action="UNBLOCK",
                                      description="Auto-unblock: time expired")
            logger.info(f" Auto-unblocked {ip} (duration expired)")
            count += 1

        return count

    def get_blocked_ips(self) -> List[Dict]:
        """Lấy danh sách tất cả IP đang bị block."""
        return self.db.execute_query(
            """SELECT b.*, s.rule_name 
               FROM blocked_ips b 
               LEFT JOIN security_rules s ON b.rule_id = s.rule_id
               WHERE b.is_active = TRUE 
               ORDER BY b.blocked_at DESC"""
        ) or []

    def get_stats(self) -> Dict:
        """Thống kê firewall trong session hiện tại."""
        return {
            "mode": self.mode,
            "blocks_this_session": self._block_count,
            "active_blocks": len(self.get_blocked_ips()),
        }
