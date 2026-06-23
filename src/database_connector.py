"""
DatabaseConnector - Kết nối và quản lý cơ sở dữ liệu PostgreSQL
Đồ án IT3930 - AI-Powered IDS - Đào Huy Phúc - 20236051
"""

import os
import psycopg2
import psycopg2.extras
import logging
from datetime import datetime, date
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

class DatabaseConnector:
    """
    Chịu trách nhiệm tương tác với cơ sở dữ liệu PostgreSQL.
    Hỗ trợ override config qua environment variables (dùng khi chạy Docker).
    """

    def __init__(self, config: dict):
        db_cfg = config.get('database', {})
        # Ưu tiên env var (Docker) > config.yaml (local)
        self.host     = os.environ.get('DB_HOST',     db_cfg.get('host',     'localhost'))
        self.port     = int(os.environ.get('DB_PORT', db_cfg.get('port',     5432)))
        self.user     = os.environ.get('DB_USER',     db_cfg.get('user',     'postgres'))
        self.password = os.environ.get('DB_PASSWORD', str(db_cfg.get('password', '')))
        self.dbname   = os.environ.get('DB_NAME',     db_cfg.get('dbname',   'postgres'))
        self.connection = None

    def connect(self) -> bool:
        """Kết nối DB và tạo schema nếu chưa có."""
        try:
            self.connection = psycopg2.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                dbname=self.dbname
            )
            self.connection.autocommit = False
            self._create_schema()
            self._seed_security_rules()
            logger.info(f" Database connected: PostgreSQL at {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f" Database connection failed: {e}")
            return False

    def _create_schema(self):
        """Tạo 6 bảng theo thiết kế ERD trong báo cáo cho PostgreSQL."""
        schema_sql = """
        -- Bảng 1: system_logs
        CREATE TABLE IF NOT EXISTS system_logs (
            log_id      SERIAL PRIMARY KEY,
            ip_address  VARCHAR(255) NOT NULL,
            username    VARCHAR(255),
            event_status VARCHAR(50) NOT NULL CHECK(event_status IN ('Failed', 'Success', 'Invalid')),
            raw_log     TEXT,
            logged_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_logs_ip ON system_logs(ip_address);
        CREATE INDEX IF NOT EXISTS idx_logs_time ON system_logs(logged_at);
        CREATE INDEX IF NOT EXISTS idx_logs_status ON system_logs(event_status);

        -- Bảng 2: security_rules
        CREATE TABLE IF NOT EXISTS security_rules (
            rule_id              SERIAL PRIMARY KEY,
            rule_name            VARCHAR(255) NOT NULL UNIQUE,
            max_failed_attempts  INTEGER DEFAULT 5,
            time_window_minutes  INTEGER DEFAULT 10,
            is_active            BOOLEAN DEFAULT TRUE,
            created_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Bảng 3: blocked_ips
        CREATE TABLE IF NOT EXISTS blocked_ips (
            block_id    SERIAL PRIMARY KEY,
            ip_address  VARCHAR(255) NOT NULL,
            rule_id     INTEGER,
            risk_score  REAL DEFAULT 0.0 CHECK(risk_score BETWEEN 0.0 AND 1.0),
            blocked_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            release_at  TIMESTAMP,
            is_active   BOOLEAN DEFAULT TRUE,
            FOREIGN KEY (rule_id) REFERENCES security_rules(rule_id)
        );
        CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips(ip_address);
        CREATE INDEX IF NOT EXISTS idx_blocked_active ON blocked_ips(is_active);

        -- Bảng 4: audit_trails
        CREATE TABLE IF NOT EXISTS audit_trails (
            audit_id    SERIAL PRIMARY KEY,
            action_type VARCHAR(50) NOT NULL CHECK(action_type IN ('DROP', 'UNBLOCK', 'WHITELIST')),
            block_id    INTEGER,
            target_ip   VARCHAR(255) NOT NULL,
            description TEXT,
            executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (block_id) REFERENCES blocked_ips(block_id)
        );

        -- Bảng 5: alert_history
        CREATE TABLE IF NOT EXISTS alert_history (
            alert_id        SERIAL PRIMARY KEY,
            block_id        INTEGER,
            platform        VARCHAR(50) DEFAULT 'Telegram',
            message_content TEXT,
            sent_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status          VARCHAR(50) DEFAULT 'SUCCESS' CHECK(status IN ('SUCCESS', 'FAILED')),
            FOREIGN KEY (block_id) REFERENCES blocked_ips(block_id)
        );

        -- Bảng 6: daily_reports
        CREATE TABLE IF NOT EXISTS daily_reports (
            report_id             SERIAL PRIMARY KEY,
            report_date           DATE NOT NULL UNIQUE,
            total_attacks_blocked INTEGER DEFAULT 0,
            high_risk_ips_count   INTEGER DEFAULT 0,
            pdf_file_path         TEXT,
            generated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        with self.connection.cursor() as cursor:
            cursor.execute(schema_sql)
        self.connection.commit()
        logger.info(" Database schema created/verified in PostgreSQL")

    def _seed_security_rules(self):
        """Thêm luật bảo mật mặc định nếu chưa có."""
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM security_rules")
            count = cursor.fetchone()[0]
            if count == 0:
                rules = [
                    ("Chặn Brute-force SSH", 5, 10),
                    ("Chặn DDoS/Flood", 100, 1),
                    ("Chặn Port Scan", 20, 5),
                ]
                cursor.executemany(
                    "INSERT INTO security_rules (rule_name, max_failed_attempts, time_window_minutes) VALUES (%s,%s,%s)",
                    rules
                )
        self.connection.commit()
        logger.info(" Default security rules seeded")

    def execute_query(self, sql_query: str, params: tuple = ()) -> Optional[List[Dict]]:
        """Chạy lệnh SQL SELECT và trả về kết quả."""
        try:
            with self.connection.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute(sql_query, params)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f" Query error: {e} | SQL: {sql_query}")
            self.connection.rollback()
            return None

    def execute_write(self, sql_query: str, params: tuple = ()) -> Optional[int]:
        """Chạy lệnh SQL INSERT/UPDATE/DELETE và trả về ID."""
        try:
            with self.connection.cursor() as cursor:
                cursor.execute(sql_query, params)
                self.connection.commit()
                try:
                    return cursor.fetchone()[0]
                except psycopg2.ProgrammingError:
                    return cursor.rowcount
        except Exception as e:
            logger.error(f" Write error: {e} | SQL: {sql_query}")
            self.connection.rollback()
            return None

    def insert_log_data(self, ip_address: str, username: str,
                        event_status: str, raw_log: str = "") -> Optional[int]:
        """Đẩy dữ liệu log vào bảng system_logs."""
        return self.execute_write(
            "INSERT INTO system_logs (ip_address, username, event_status, raw_log) VALUES (%s,%s,%s,%s) RETURNING log_id",
            (ip_address, username, event_status, raw_log)
        )

    def insert_blocked_ip(self, ip_address: str, rule_id: int,
                          risk_score: float, release_at: Optional[datetime] = None) -> Optional[int]:
        """Thêm IP vào danh sách bị chặn."""
        return self.execute_write(
            "INSERT INTO blocked_ips (ip_address, rule_id, risk_score, release_at) VALUES (%s,%s,%s,%s) RETURNING block_id",
            (ip_address, rule_id, round(risk_score, 4), release_at)
        )

    def insert_audit_trail(self, action_type: str, block_id: int,
                           target_ip: str, description: str = "") -> Optional[int]:
        """Lưu vết hành động firewall."""
        return self.execute_write(
            "INSERT INTO audit_trails (action_type, block_id, target_ip, description) VALUES (%s,%s,%s,%s) RETURNING audit_id",
            (action_type, block_id, target_ip, description)
        )

    def insert_alert_history(self, block_id: int, message_content: str,
                             status: str = "SUCCESS", platform: str = "Telegram") -> Optional[int]:
        """Lưu lịch sử cảnh báo đã gửi."""
        return self.execute_write(
            "INSERT INTO alert_history (block_id, platform, message_content, status) VALUES (%s,%s,%s,%s) RETURNING alert_id",
            (block_id, platform, message_content, status)
        )

    def insert_daily_report(self, report_date: str, total_blocked: int,
                            high_risk_count: int, pdf_path: str) -> Optional[int]:
        """Lưu thông tin báo cáo ngày."""
        return self.execute_write(
            """INSERT INTO daily_reports 
               (report_date, total_attacks_blocked, high_risk_ips_count, pdf_file_path)
               VALUES (%s,%s,%s,%s)
               ON CONFLICT (report_date) DO UPDATE SET
               total_attacks_blocked = EXCLUDED.total_attacks_blocked,
               high_risk_ips_count = EXCLUDED.high_risk_ips_count,
               pdf_file_path = EXCLUDED.pdf_file_path
               RETURNING report_id""",
            (report_date, total_blocked, high_risk_count, pdf_path)
        )

    def get_recent_logs(self, ip_address: str, minutes: int) -> List[Dict]:
        """Lấy log của một IP trong khoảng thời gian gần đây."""
        result = self.execute_query(
            """SELECT * FROM system_logs 
               WHERE ip_address = %s 
               AND event_status = 'Failed'
               AND logged_at >= NOW() - INTERVAL '1 minute' * %s
               ORDER BY logged_at DESC""",
            (ip_address, minutes)
        )
        return result or []

    def get_failed_login_count(self, ip_address: str, minutes: int) -> int:
        """Đếm số lần đăng nhập thất bại của một IP."""
        result = self.execute_query(
            """SELECT COUNT(*) as cnt FROM system_logs 
               WHERE ip_address = %s 
               AND event_status = 'Failed'
               AND logged_at >= NOW() - INTERVAL '1 minute' * %s""",
            (ip_address, minutes)
        )
        return result[0]['cnt'] if result else 0

    def get_training_data(self, limit: int = 5000) -> List[Dict]:
        """Tải dữ liệu lịch sử để huấn luyện AI model."""
        result = self.execute_query(
            """SELECT ip_address, event_status, logged_at,
               EXTRACT(HOUR FROM logged_at) as hour_of_day,
               EXTRACT(DOW FROM logged_at) as day_of_week
               FROM system_logs 
               ORDER BY logged_at DESC LIMIT %s""",
            (limit,)
        )
        return result or []

    def is_ip_blocked(self, ip_address: str) -> bool:
        """Kiểm tra xem IP có đang bị block không."""
        result = self.execute_query(
            "SELECT COUNT(*) as cnt FROM blocked_ips WHERE ip_address = %s AND is_active = TRUE",
            (ip_address,)
        )
        return result[0]['cnt'] > 0 if result else False

    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Lấy thống kê tổng hợp cho Web Dashboard."""
        stats = {}

        r = self.execute_query("SELECT COUNT(*) as cnt FROM system_logs WHERE DATE(logged_at) = CURRENT_DATE")
        stats['logs_today'] = r[0]['cnt'] if r else 0

        r = self.execute_query("SELECT COUNT(*) as cnt FROM blocked_ips WHERE is_active = TRUE")
        stats['active_blocks'] = r[0]['cnt'] if r else 0

        r = self.execute_query("SELECT COUNT(*) as cnt FROM alert_history WHERE DATE(sent_at) = CURRENT_DATE")
        stats['alerts_today'] = r[0]['cnt'] if r else 0

        r = self.execute_query(
            """SELECT ip_address, COUNT(*) as attempts 
               FROM system_logs WHERE event_status = 'Failed'
               GROUP BY ip_address ORDER BY attempts DESC LIMIT 5"""
        )
        stats['top_attackers'] = r or []

        r = self.execute_query(
            """SELECT DATE(blocked_at) as day, COUNT(*) as count 
               FROM blocked_ips 
               WHERE blocked_at >= CURRENT_DATE - INTERVAL '7 days'
               GROUP BY DATE(blocked_at) ORDER BY day"""
        )
        if r:
            for row in r:
                if isinstance(row['day'], (date, datetime)):
                    row['day'] = row['day'].isoformat()
        stats['blocks_7days'] = r or []

        r = self.execute_query(
            """SELECT b.ip_address, b.risk_score, b.blocked_at, s.rule_name
               FROM blocked_ips b LEFT JOIN security_rules s ON b.rule_id = s.rule_id
               WHERE b.is_active = TRUE ORDER BY b.blocked_at DESC LIMIT 10"""
        )
        stats['recent_blocks'] = r or []

        return stats

    def unblock_ip(self, ip_address: str) -> bool:
        """Mở khóa IP thủ công."""
        result = self.execute_write(
            "UPDATE blocked_ips SET is_active = FALSE WHERE ip_address = %s AND is_active = TRUE RETURNING block_id",
            (ip_address,)
        )
        return result is not None

    def cleanup_old_logs(self, days: int = 30):
        """Dọn rác: Xóa log cũ hơn N ngày."""
        deleted = self.execute_write(
            "DELETE FROM system_logs WHERE logged_at < NOW() - INTERVAL '1 day' * %s RETURNING log_id",
            (days,)
        )
        logger.info(f"  Cleanup: removed logs older than {days} days")

    def close(self):
        """Đóng kết nối database."""
        if self.connection:
            self.connection.close()
            logger.info(" Database connection closed")
