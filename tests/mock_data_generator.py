"""
MockDataGenerator - Tạo dữ liệu giả lập cho demo
Đồ án IT3930 - AI-Powered IDS - Đào Huy Phúc - 20236051
"""

import random
import logging
from datetime import datetime, timedelta
from typing import List

from src.database_connector import DatabaseConnector


logger = logging.getLogger(__name__)

# Danh sách IP giả lập
NORMAL_IPS = [
    "192.168.56.1",   # Host Mac (bình thường)
    "10.0.0.5",
    "10.0.0.10",
    "172.16.0.100",
]

ATTACK_IPS = [
    "185.220.101.45",  # Tor exit node
    "45.33.32.156",    # Scanner
    "194.165.16.11",   # Known attacker
    "198.199.82.58",
    "23.129.64.190",
    "103.99.0.122",
]

USERNAMES_NORMAL = ["admin", "root", "ubuntu", "user1"]
USERNAMES_DICT_ATTACK = [
    "root", "admin", "administrator", "test", "guest", "oracle",
    "postgres", "mysql", "ftp", "user", "pi", "ubuntu", "debian",
    "nagios", "jenkins", "git", "backup", "www", "data"
]


class MockDataGenerator:
    """Tạo dữ liệu log giả lập cho môi trường demo."""

    def __init__(self, db: DatabaseConnector):
        self.db = db

    def generate_logs(self, n_normal: int = 400, n_attack: int = 50,
                      inject_realtime: bool = False) -> int:
        """
        Sinh log giả lập vào database.

        Args:
            n_normal: Số log hành vi bình thường
            n_attack: Số log tấn công Brute-force
            inject_realtime: Nếu True, inject thêm log tấn công với timestamp hiện tại

        Returns:
            Tổng số log đã insert
        """
        total = 0
        now = datetime.now()

        # ---- Log bình thường (7 ngày qua) ----
        logger.info(f" Generating {n_normal} normal log entries...")
        for i in range(n_normal):
            ip = random.choice(NORMAL_IPS)
            user = random.choice(USERNAMES_NORMAL)
            # 90% thành công, 10% thất bại
            status = "Success" if random.random() < 0.9 else "Failed"
            # Timestamp ngẫu nhiên trong 7 ngày qua
            ts = now - timedelta(
                days=random.randint(0, 6),
                hours=random.randint(8, 20),  # Giờ làm việc
                minutes=random.randint(0, 59)
            )
            raw = (f"Jun 19 {ts.strftime('%H:%M:%S')} server sshd[1234]: "
                   f"{'Accepted' if status == 'Success' else 'Failed'} "
                   f"password for {user} from {ip} port {random.randint(10000, 65535)} ssh2")

            self.db.execute_write(
                "INSERT INTO system_logs (ip_address, username, event_status, raw_log, logged_at) VALUES (%s,%s,%s,%s,%s)",
                (ip, user, status, raw, ts.strftime("%Y-%m-%d %H:%M:%S"))
            )
            total += 1

        # ---- Log tấn công Brute-force (hôm nay) ----
        logger.info(f" Generating {n_attack} attack log entries...")
        for attack_ip in ATTACK_IPS[:4]:
            n_per_ip = n_attack // 4
            for j in range(n_per_ip):
                user = random.choice(USERNAMES_DICT_ATTACK)
                # Timestamp dày đặc trong vòng 10 phút
                ts = now - timedelta(
                    minutes=random.randint(0, 15),
                    seconds=random.randint(0, 59)
                )
                raw = (f"Jun 19 {ts.strftime('%H:%M:%S')} server sshd[9999]: "
                       f"Failed password for invalid user {user} "
                       f"from {attack_ip} port {random.randint(10000, 65535)} ssh2")

                self.db.execute_write(
                    "INSERT INTO system_logs (ip_address, username, event_status, raw_log, logged_at) VALUES (%s,%s,%s,%s,%s)",
                    (attack_ip, user, "Failed", raw, ts.strftime("%Y-%m-%d %H:%M:%S"))
                )
                total += 1

        if inject_realtime:
            # Inject thêm tấn công cực kỳ rõ ràng để AI dễ phát hiện
            logger.info(" Injecting realtime attack pattern...")
            for burst in range(30):
                ts = now - timedelta(seconds=burst * 2)
                attack_ip = "185.220.101.45"
                user = random.choice(USERNAMES_DICT_ATTACK)
                raw = (f"Jun 19 {ts.strftime('%H:%M:%S')} server sshd[8888]: "
                       f"Failed password for {user} from {attack_ip} port 22 ssh2")
                self.db.execute_write(
                    "INSERT INTO system_logs (ip_address, username, event_status, raw_log, logged_at) VALUES (%s,%s,%s,%s,%s)",
                    (attack_ip, user, "Failed", raw, ts.strftime("%Y-%m-%d %H:%M:%S"))
                )
                total += 1

        logger.info(f" Mock data generated: {total} total log entries")
        return total

    def generate_sample_auth_log(self, output_path: str = "logs/sample_auth.log"):
        """Tạo file auth.log mẫu để copy vào Linux server."""
        lines = []
        now = datetime.now()

        # Normal traffic
        for _ in range(50):
            ip = random.choice(NORMAL_IPS)
            user = random.choice(USERNAMES_NORMAL)
            ts = (now - timedelta(minutes=random.randint(60, 1440))).strftime("%b %d %H:%M:%S")
            lines.append(f"{ts} server sshd[1234]: Accepted password for {user} from {ip} port 22 ssh2\n")

        # Brute-force attack
        for j in range(100):
            user = random.choice(USERNAMES_DICT_ATTACK)
            ts = (now - timedelta(seconds=j * 3)).strftime("%b %d %H:%M:%S")
            lines.append(f"{ts} server sshd[9999]: Failed password for invalid user {user} from 185.220.101.45 port 22 ssh2\n")

        random.shuffle(lines)

        with open(output_path, "w") as f:
            f.writelines(lines)
        logger.info(f" Sample auth.log generated: {output_path}")
        return output_path
