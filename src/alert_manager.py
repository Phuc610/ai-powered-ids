"""
AlertManager - Quản lý cảnh báo qua Telegram
Đồ án IT3930 - AI-Powered IDS - Đào Huy Phúc - 20236051

Chức năng:
  - format_alert_message(): Định dạng nội dung tin nhắn
  - send_telegram_alert(): Gửi tin nhắn qua Telegram Bot API
"""

import logging
import requests
from datetime import datetime
from typing import Optional, Dict

from src.database_connector import DatabaseConnector


logger = logging.getLogger(__name__)


class AlertManager:
    """
    Phụ trách gửi tin nhắn cảnh báo qua Telegram.

    Attributes:
        telegram_bot_token (str): Mã token của bot
        chat_id (str): ID của người/nhóm nhận
    """

    TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/sendMessage"

    def __init__(self, config: dict, db: DatabaseConnector):
        tg_cfg = config.get("telegram", {})
        self.telegram_bot_token: str = tg_cfg.get("bot_token", "")
        self.chat_id: str = str(tg_cfg.get("chat_id", ""))
        self.enabled: bool = tg_cfg.get("enabled", True)

        self.db = db
        self._sent_count = 0
        self._failed_count = 0

        if not self.telegram_bot_token or self.telegram_bot_token == "YOUR_BOT_TOKEN":
            logger.warning("  Telegram bot_token not configured! Alerts will be logged only.")
            self.enabled = False

        if self.enabled:
            logger.info(f" AlertManager ready | chat_id={self.chat_id}")
        else:
            logger.info(" AlertManager in LOG-ONLY mode (Telegram disabled)")

    def format_alert_message(self, ip_address: str, risk_score: float,
                              block_id: int, rule_name: str = "",
                              failed_attempts: int = 0) -> str:
        """
        Định dạng text cảnh báo.

        Returns:
            Chuỗi tin nhắn đã format đẹp với emoji
        """
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        risk_emoji = "" if risk_score >= 0.8 else "" if risk_score >= 0.6 else ""
        risk_label = "CỰC KỲ NGUY HIỂM" if risk_score >= 0.8 else "NGUY HIỂM" if risk_score >= 0.6 else "CẢNH BÁO"

        message = (
            f" *AI-POWERED IDS ALERT*\n"
            f"{'─'*30}\n"
            f"{risk_emoji} *Mức độ:* {risk_label}\n"
            f" *IP tấn công:* `{ip_address}`\n"
            f" *Risk Score:* `{risk_score:.3f}`\n"
            f" *Luật vi phạm:* {rule_name or 'Brute-force SSH'}\n"
            f" *Số lần thử:* {failed_attempts} lần\n"
            f" *Block ID:* #{block_id}\n"
            f" *Thời gian:* {now}\n"
            f"{'─'*30}\n"
            f" IP đã bị chặn tự động qua Firewall\n"
            f" *Hệ thống:* AI-Powered IDS | IT3930"
        )
        return message

    def send_telegram_alert(self, message: str, block_id: Optional[int] = None,
                             parse_mode: str = "Markdown") -> bool:
        """
        Bắn tin nhắn cảnh báo qua Telegram.

        Args:
            message: Nội dung tin nhắn đã được format
            block_id: ID trong DB để lưu vào alert_history
            parse_mode: "Markdown" hoặc "HTML"

        Returns:
            True nếu gửi thành công
        """
        # Luôn log ra console
        logger.warning(f"\n{'='*60}\n TELEGRAM ALERT:\n{message}\n{'='*60}")

        if not self.enabled:
            # Log-only mode: lưu DB với status SUCCESS (giả lập)
            if block_id is not None:
                self.db.insert_alert_history(
                    block_id=block_id,
                    message_content=message,
                    status="SUCCESS",
                    platform="Console (Telegram disabled)"
                )
            return True

        # Gửi thật qua Telegram API
        url = self.TELEGRAM_API_URL.format(token=self.telegram_bot_token)
        payload = {
            "chat_id": self.chat_id,
            "text": message,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        }

        status = "FAILED"
        try:
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            result = response.json()

            if result.get("ok"):
                self._sent_count += 1
                status = "SUCCESS"
                logger.info(f" Telegram alert sent | message_id={result['result']['message_id']}")
            else:
                self._failed_count += 1
                logger.error(f" Telegram API error: {result}")

        except requests.exceptions.Timeout:
            self._failed_count += 1
            logger.error(" Telegram API timeout")
        except requests.exceptions.ConnectionError:
            self._failed_count += 1
            logger.error(" Cannot reach Telegram API (check internet)")
        except Exception as e:
            self._failed_count += 1
            logger.error(f" Telegram send error: {e}")

        # Lưu lịch sử vào DB dù thành công hay thất bại
        if block_id is not None:
            self.db.insert_alert_history(
                block_id=block_id,
                message_content=message,
                status=status
            )

        return status == "SUCCESS"

    def send_block_alert(self, ip_address: str, risk_score: float,
                          block_id: int, rule_name: str = "",
                          failed_attempts: int = 0) -> bool:
        """
        Hàm tiện ích: format và gửi alert trong một lần gọi.
        
        Được gọi bởi AIThreatDetector mỗi khi phát hiện tấn công.
        """
        message = self.format_alert_message(
            ip_address=ip_address,
            risk_score=risk_score,
            block_id=block_id,
            rule_name=rule_name,
            failed_attempts=failed_attempts
        )
        return self.send_telegram_alert(message, block_id=block_id)

    def send_system_status(self, stats: Dict) -> bool:
        """Gửi báo cáo trạng thái hệ thống định kỳ."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        message = (
            f" *IDS SYSTEM STATUS REPORT*\n"
            f"{'─'*30}\n"
            f" {now}\n\n"
            f" *Log hôm nay:* {stats.get('logs_today', 0)}\n"
            f" *IP đang bị block:* {stats.get('active_blocks', 0)}\n"
            f" *Cảnh báo hôm nay:* {stats.get('alerts_today', 0)}\n"
            f" *Đã gửi:* {self._sent_count} |  *Thất bại:* {self._failed_count}\n"
            f"{'─'*30}\n"
            f" AI-Powered IDS | IT3930 | Đào Huy Phúc"
        )
        return self.send_telegram_alert(message)

    def test_connection(self) -> bool:
        """Kiểm tra kết nối với Telegram API."""
        if not self.enabled:
            logger.info("Telegram disabled, skipping test")
            return False

        url = f"https://api.telegram.org/bot{self.telegram_bot_token}/getMe"
        try:
            response = requests.get(url, timeout=10)
            result = response.json()
            if result.get("ok"):
                bot_name = result['result'].get('first_name', 'Unknown')
                logger.info(f" Telegram bot connected: {bot_name}")
                return True
            else:
                logger.error(f" Invalid bot token: {result}")
                return False
        except Exception as e:
            logger.error(f" Telegram test failed: {e}")
            return False
