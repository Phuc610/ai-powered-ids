"""
IDSController - Bộ điều phối trung tâm của hệ thống IDS
Đồ án IT3930 - AI-Powered IDS - Đào Huy Phúc - 20236051

Vòng lặp chính:
  LogMonitor → DatabaseConnector → AIThreatDetector 
      → FirewallManager + AlertManager + ReportGenerator
"""

import time
import logging
import schedule
import threading
from datetime import datetime, date
from typing import Dict, Optional

import yaml

from src.database_connector import DatabaseConnector
from src.log_monitor import LogMonitor
from src.ai_threat_detector import AIThreatDetector
from src.firewall_manager import FirewallManager
from src.alert_manager import AlertManager
from src.report_generator import ReportGenerator


logger = logging.getLogger(__name__)


class IDSController:
    """
    Bộ điều phối trung tâm - kết nối và điều phối toàn bộ pipeline.
    """

    def __init__(self, config: dict):
        self.config = config
        self._running = False

        # Khởi tạo 6 components
        logger.info(" Initializing AI-Powered IDS components...")

        self.db = DatabaseConnector(config)
        self.db.connect()

        self.log_monitor = LogMonitor(config, self.db)
        self.ai_detector = AIThreatDetector(config, self.db)
        self.firewall = FirewallManager(config, self.db)
        self.alert_manager = AlertManager(config, self.db)
        self.report_gen = ReportGenerator(config, self.db)

        # Thống kê session
        self._stats = {
            "start_time": datetime.now().isoformat(),
            "logs_processed": 0,
            "threats_detected": 0,
            "ips_blocked": 0,
            "alerts_sent": 0,
        }

        logger.info(" All components initialized successfully")

    def _process_log_entry(self, log_entry: Dict):
        """
        Xử lý một dòng log qua toàn bộ pipeline:
        1. Lưu vào DB
        2. Phân tích AI
        3. Block IP nếu là tấn công
        4. Gửi cảnh báo Telegram
        """
        self._stats['logs_processed'] += 1
        ip = log_entry.get("ip_address", "")

        if not ip:
            return

        # Bước 1: Đã được lưu bởi LogMonitor, chỉ cần phân tích
        # Bước 2: AI phân tích
        is_attack, risk_score = self.ai_detector.predict_anomaly(log_entry)

        if is_attack:
            self._stats['threats_detected'] += 1

            # Bước 3: Block IP qua Firewall
            rule_id = 1  # Mặc định dùng luật Brute-force SSH
            block_id = self.firewall.block_ip(
                ip_address=ip,
                rule_id=rule_id,
                risk_score=risk_score,
                reason=f"AI Detection (risk={risk_score:.3f})"
            )

            if block_id:
                self._stats['ips_blocked'] += 1

                # Bước 4: Gửi cảnh báo Telegram
                failed_count = self.db.get_failed_login_count(ip, 10)
                sent = self.alert_manager.send_block_alert(
                    ip_address=ip,
                    risk_score=risk_score,
                    block_id=block_id,
                    rule_name="Brute-force SSH",
                    failed_attempts=failed_count
                )
                if sent:
                    self._stats['alerts_sent'] += 1

    def run_once(self, log_lines: int = 200):
        """
        Chạy pipeline một lần: đọc log → phân tích → xử lý.
        Dùng cho chế độ batch hoặc test.
        """
        logger.info(" Running single IDS cycle...")

        # Kết nối SSH
        if not self.log_monitor.connect_ssh():
            logger.error("Cannot connect to Linux server. Check config.yaml")
            return self._stats

        # Thu thập và xử lý log
        raw_content = self.log_monitor.read_secure_log(lines=log_lines)
        if raw_content:
            for line in raw_content.split("\n"):
                parsed = self.log_monitor.parse_log_regex(line)
                if parsed:
                    # Lưu vào DB
                    self.db.insert_log_data(
                        ip_address=parsed["ip_address"],
                        username=parsed["username"],
                        event_status=parsed["event_status"],
                        raw_log=parsed["raw_log"]
                    )
                    # Chỉ phân tích log Failed
                    if parsed["event_status"] == "Failed":
                        self._process_log_entry(parsed)

        # Xử lý IP hết hạn block
        expired = self.firewall.process_expired_blocks()
        if expired > 0:
            logger.info(f" Auto-unblocked {expired} expired IPs")

        self.log_monitor.disconnect()
        logger.info(f" Cycle complete: {self._stats}")
        return self._stats

    def run_realtime(self):
        """
        Chạy giám sát realtime (tail -f log file).
        Kết nối SSH và stream log liên tục.
        """
        logger.info(" Starting REALTIME monitoring mode...")
        self._running = True

        # Kết nối SSH
        if not self.log_monitor.connect_ssh():
            logger.error("Cannot connect to Linux server")
            return

        # Chia sẻ SSH client cho FirewallManager (để block thật)
        self.firewall.set_ssh_client(self.log_monitor.ssh_client)

        # Train AI model lần đầu
        logger.info(" Initial AI model training...")
        self.ai_detector.train_model()

        # Lên lịch tác vụ định kỳ
        self._setup_scheduled_tasks()

        def on_new_log(log_entry: Dict):
            """Callback được gọi mỗi khi có log mới."""
            if log_entry.get("event_status") == "Failed":
                # Lưu vào DB
                self.db.insert_log_data(**log_entry)
                # Pipeline phân tích
                self._process_log_entry(log_entry)

        # Chạy scheduler trong thread riêng
        scheduler_thread = threading.Thread(
            target=self._run_scheduler, daemon=True
        )
        scheduler_thread.start()

        # Stream log realtime (blocking)
        try:
            self.log_monitor.read_log_stream(callback=on_new_log, poll_interval=3.0)
        except KeyboardInterrupt:
            logger.info(" Shutting down realtime monitoring...")
        finally:
            self.stop()

    def run_simulate(self, inject_attacks: bool = True):
        """
        Chạy với dữ liệu giả lập (không cần Linux server).
        Dùng để demo và test trên máy Mac.
        """
        from tests.mock_data_generator import MockDataGenerator

        logger.info(" Running SIMULATION mode...")
        mock_gen = MockDataGenerator(self.db)

        # Sinh 500 log mẫu (gồm cả bình thường và tấn công)
        mock_gen.generate_logs(
            n_normal=400,
            n_attack=50,
            inject_realtime=inject_attacks
        )

        # Train AI model
        self.ai_detector.train_model()

        # Xử lý tất cả log Failed trong DB
        failed_logs = self.db.execute_query(
            "SELECT * FROM system_logs WHERE event_status = 'Failed' ORDER BY logged_at DESC LIMIT 100"
        ) or []

        logger.info(f" Analyzing {len(failed_logs)} failed login events...")
        for log in failed_logs:
            self._process_log_entry(log)

        # Xuất báo cáo PDF ngày hôm nay
        logger.info(" Generating PDF report...")
        pdf_path = self.report_gen.export_to_pdf()
        if pdf_path:
            logger.info(f" Report saved: {pdf_path}")

        return self._stats

    def _setup_scheduled_tasks(self):
        """Lên lịch các tác vụ định kỳ."""
        # Train lại AI mỗi 24 giờ
        schedule.every(24).hours.do(self._retrain_ai)

        # Dọn rác DB mỗi ngày lúc 3 giờ sáng
        schedule.every().day.at("03:00").do(
            lambda: self.db.cleanup_old_logs(days=30)
        )

        # Xuất báo cáo hàng ngày lúc 23:59
        report_time = self.config.get("reports", {}).get("generate_at", "23:59")
        schedule.every().day.at(report_time).do(self._generate_daily_report)

        # Gửi status report mỗi 6 giờ
        schedule.every(6).hours.do(self._send_status_report)

        # Kiểm tra IP hết hạn block mỗi 30 phút
        schedule.every(30).minutes.do(self.firewall.process_expired_blocks)

        logger.info(" Scheduled tasks configured")

    def _run_scheduler(self):
        """Chạy scheduler trong background thread."""
        while self._running:
            schedule.run_pending()
            time.sleep(30)

    def _retrain_ai(self):
        """Tái huấn luyện AI model định kỳ."""
        logger.info(" Scheduled AI retrain...")
        self.ai_detector.train_model()

    def _generate_daily_report(self):
        """Xuất báo cáo ngày."""
        logger.info(" Generating scheduled daily report...")
        pdf_path = self.report_gen.export_to_pdf()
        if pdf_path:
            # Thông báo qua Telegram
            self.alert_manager.send_telegram_alert(
                f" *Báo cáo An ninh Ngày {date.today()}*\n"
                f" File: `{pdf_path}`\n"
                f" Blocked: {self._stats['ips_blocked']} IPs\n"
                f" Threats: {self._stats['threats_detected']}"
            )

    def _send_status_report(self):
        """Gửi báo cáo trạng thái định kỳ qua Telegram."""
        stats = self.db.get_dashboard_stats()
        self.alert_manager.send_system_status(stats)

    def stop(self):
        """Dừng hệ thống."""
        self._running = False
        self.log_monitor.stop()
        self.log_monitor.disconnect()
        self.db.close()
        logger.info(" IDS Controller stopped")

    def get_stats(self) -> Dict:
        """Lấy thống kê session hiện tại."""
        return {**self._stats, "uptime": str(datetime.now())}
