#!/usr/bin/env python3
"""
main.py - Entry point for AI-Powered IDS
AI-Powered IDS | Threat Intelligence Engine

Cách chạy:
  python main.py --mode simulate    # Demo với dữ liệu giả lập (không cần Linux server)
  python main.py --mode dashboard   # Chạy Web Dashboard (API server)
  python main.py --mode once        # Kết nối SSH thật, chạy 1 lần
  python main.py --mode realtime    # Kết nối SSH thật, giám sát liên tục
  python main.py --mode test-ssh    # Kiểm tra kết nối SSH
  python main.py --mode test-tg     # Kiểm tra kết nối Telegram
  python main.py --mode report      # Xuất báo cáo PDF ngay
"""

import argparse
import logging
import sys
import os
import yaml
from datetime import date
from colorama import init, Fore, Style

# Initialize colorama for colored output on Mac/Windows
init(autoreset=True)


def setup_logging(config: dict):
    """Cấu hình logging có màu sắc ra console."""
    log_cfg = config.get("logging", {})
    level = getattr(logging, log_cfg.get("level", "INFO"), logging.INFO)
    log_file = log_cfg.get("file", "logs/ids.log")

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    # Formatter
    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"

    # File handler
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(fmt, datefmt))

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(fmt, datefmt))

    logging.basicConfig(level=level, handlers=[file_handler, console_handler])


def print_banner():
    """In banner khởi động."""
    print(f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║                  AI-POWERED IDS ENGINE                   ║
║           Intelligent Intrusion Detection System         ║
╠══════════════════════════════════════════════════════════╣
║  Version  : v1.2.0-stable                                ║
║  Status   : Online                                       ║
║  Module   : AI Threat Intelligence Core                  ║
╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")


def load_config(config_path: str = "config/config.yaml") -> dict:
    """Load file cấu hình YAML."""
    if not os.path.exists(config_path):
        print(f"{Fore.RED} Config file not found: {config_path}{Style.RESET_ALL}")
        sys.exit(1)
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


# ============================================================
# MODE: SIMULATE (Demo không cần Linux server)
# ============================================================
def mode_simulate(config: dict):
    """Chạy demo đầy đủ với dữ liệu giả lập."""
    print(f"\n{Fore.YELLOW} SIMULATION MODE{Style.RESET_ALL}")
    print("Chạy pipeline đầy đủ với dữ liệu giả lập...")

    from src.ids_controller import IDSController

    controller = IDSController(config)
    stats = controller.run_simulate(inject_attacks=True)

    print(f"\n{Fore.GREEN} Simulation hoàn tất!{Style.RESET_ALL}")
    print(f"   Log đã xử lý : {stats.get('logs_processed', 0)}")
    print(f"   Mối đe dọa   : {stats.get('threats_detected', 0)}")
    print(f"   IP bị chặn   : {stats.get('ips_blocked', 0)}")
    print(f"   Cảnh báo gửi : {stats.get('alerts_sent', 0)}")
    print(f"\n{Fore.CYAN} Web Dashboard: http://localhost:5000{Style.RESET_ALL}")
    print(f"   Chạy: python main.py --mode dashboard")


# ============================================================
# MODE: DASHBOARD (Web UI)
# ============================================================
def mode_dashboard(config: dict):
    """Khởi động Web Dashboard API server."""
    print(f"\n{Fore.CYAN} WEB DASHBOARD MODE{Style.RESET_ALL}")

    # Khởi tạo DB trước
    from src.database_connector import DatabaseConnector
    db = DatabaseConnector(config)
    db.connect()

    # Import và chạy Flask app
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    os.environ['IDS_CONFIG_PATH'] = 'config/config.yaml'

    from dashboard.api_server import app, init_components
    init_components(config)

    dash_cfg = config.get('dashboard', {})
    host = dash_cfg.get('host', '0.0.0.0')
    port = dash_cfg.get('port', 5000)

    print(f"\n{Fore.GREEN} Dashboard: http://localhost:{port}{Style.RESET_ALL}")
    print(f"   Nhấn Ctrl+C để dừng\n")
    app.run(host=host, port=port, debug=False, use_reloader=False)


# ============================================================
# MODE: ONCE (SSH thật, chạy 1 lần)
# ============================================================
def mode_once(config: dict):
    """Kết nối SSH thật và chạy pipeline một lần."""
    print(f"\n{Fore.YELLOW} SINGLE RUN MODE{Style.RESET_ALL}")
    from src.ids_controller import IDSController

    controller = IDSController(config)
    stats = controller.run_once(log_lines=500)

    print(f"\n{Fore.GREEN} Hoàn tất!{Style.RESET_ALL}")
    for k, v in stats.items():
        print(f"  {k}: {v}")


# ============================================================
# MODE: REALTIME (SSH thật, giám sát liên tục)
# ============================================================
def mode_realtime(config: dict):
    """Giám sát log Linux realtime qua SSH."""
    print(f"\n{Fore.RED} REALTIME MONITORING MODE{Style.RESET_ALL}")
    print(f"  Server: {config['linux_server']['host']}")
    print(f"  Log: {config['linux_server']['log_file']}")
    print(f"  Nhấn Ctrl+C để dừng\n")

    from src.ids_controller import IDSController
    controller = IDSController(config)
    controller.run_realtime()


# ============================================================
# MODE: TEST SSH
# ============================================================
def mode_test_ssh(config: dict):
    """Kiểm tra kết nối SSH tới Linux VirtualBox."""
    print(f"\n{Fore.CYAN} TESTING SSH CONNECTION{Style.RESET_ALL}")

    from src.database_connector import DatabaseConnector
    from src.log_monitor import LogMonitor

    db = DatabaseConnector(config)
    db.connect()

    monitor = LogMonitor(config, db)
    result = monitor.test_connection()

    if result.get('success'):
        print(f"{Fore.GREEN} SSH Connected!{Style.RESET_ALL}")
        print(f"  IP: {result['ip']}")
        print(f"  Server info:\n{result['server_info']}")

        # Thử đọc vài dòng log
        print(f"\n{Fore.CYAN} Sample logs:{Style.RESET_ALL}")
        sample = monitor.read_secure_log(lines=20)
        lines_parsed = 0
        for line in sample.split('\n')[:20]:
            parsed = monitor.parse_log_regex(line)
            if parsed:
                status_color = Fore.RED if parsed['event_status'] == 'Failed' else Fore.GREEN
                print(f"  {status_color}[{parsed['event_status']}]{Style.RESET_ALL} "
                      f"{parsed['ip_address']} | {parsed['username']}")
                lines_parsed += 1
        print(f"\n  Parsed {lines_parsed} relevant log entries")
    else:
        print(f"{Fore.RED} SSH Failed: {result.get('error', 'Unknown')}{Style.RESET_ALL}")
        print("\n Kiểm tra lại:")
        print("  1. VirtualBox đang chạy chưa?")
        print("  2. IP trong config/config.yaml đúng chưa?")
        print(f"     host: {config['linux_server']['host']}")
        print("  3. SSH service trên Linux đang chạy chưa? (systemctl status ssh)")

    monitor.disconnect()
    db.close()


# ============================================================
# MODE: TEST TELEGRAM
# ============================================================
def mode_test_telegram(config: dict):
    """Kiểm tra kết nối Telegram Bot."""
    print(f"\n{Fore.CYAN} TESTING TELEGRAM CONNECTION{Style.RESET_ALL}")

    from src.database_connector import DatabaseConnector
    from src.alert_manager import AlertManager

    db = DatabaseConnector(config)
    db.connect()

    alert = AlertManager(config, db)

    if not alert.enabled:
        print(f"{Fore.YELLOW}  Telegram chưa được cấu hình trong config.yaml{Style.RESET_ALL}")
        print("   Hãy điền bot_token và chat_id")
        return

    success = alert.test_connection()
    if success:
        # Gửi tin nhắn test
        sent = alert.send_telegram_alert(
            " *Test từ AI-Powered IDS*\n"
            " Kết nối Telegram thành công!\n"
            "Hệ thống sẵn sàng gửi cảnh báo.\n"
            " IT3930 | Đào Huy Phúc"
        )
        if sent:
            print(f"{Fore.GREEN} Test message sent to Telegram!{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED} Telegram connection failed{Style.RESET_ALL}")

    db.close()


# ============================================================
# MODE: REPORT
# ============================================================
def mode_report(config: dict, report_date: str = None):
    """Xuất báo cáo PDF."""
    print(f"\n{Fore.CYAN} GENERATING PDF REPORT{Style.RESET_ALL}")

    from src.database_connector import DatabaseConnector
    from src.report_generator import ReportGenerator

    db = DatabaseConnector(config)
    db.connect()

    report_gen = ReportGenerator(config, db)
    target_date = date.fromisoformat(report_date) if report_date else date.today()

    pdf_path = report_gen.export_to_pdf(target_date)
    if pdf_path:
        print(f"{Fore.GREEN} Report generated: {pdf_path}{Style.RESET_ALL}")
        # Mở file PDF tự động trên Mac
        os.system(f"open '{pdf_path}'")
    else:
        print(f"{Fore.RED} Report generation failed{Style.RESET_ALL}")

    db.close()


# ============================================================
# MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description='AI-Powered IDS - IT3930',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  python main.py --mode simulate    # Demo với dữ liệu giả lập
  python main.py --mode dashboard   # Khởi động Web Dashboard
  python main.py --mode test-ssh    # Kiểm tra kết nối SSH
  python main.py --mode test-tg     # Kiểm tra Telegram Bot
  python main.py --mode once        # Chạy một lần với SSH thật
  python main.py --mode realtime    # Giám sát liên tục
  python main.py --mode report      # Xuất báo cáo PDF hôm nay
        """
    )
    parser.add_argument(
        '--mode', '-m',
        choices=['simulate', 'dashboard', 'once', 'realtime', 'test-ssh', 'test-tg', 'report'],
        default='simulate',
        help='Chế độ chạy (mặc định: simulate)'
    )
    parser.add_argument(
        '--config', '-c',
        default='config/config.yaml',
        help='Đường dẫn file config (mặc định: config/config.yaml)'
    )
    parser.add_argument(
        '--date', '-d',
        help='Ngày xuất báo cáo (YYYY-MM-DD, mặc định: hôm nay)'
    )

    args = parser.parse_args()
    print_banner()

    # Load config
    config = load_config(args.config)
    setup_logging(config)

    # Dispatch mode
    mode_map = {
        'simulate': lambda: mode_simulate(config),
        'dashboard': lambda: mode_dashboard(config),
        'once': lambda: mode_once(config),
        'realtime': lambda: mode_realtime(config),
        'test-ssh': lambda: mode_test_ssh(config),
        'test-tg': lambda: mode_test_telegram(config),
        'report': lambda: mode_report(config, args.date),
    }

    try:
        mode_map[args.mode]()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW} Hệ thống đã dừng.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED} Lỗi: {e}{Style.RESET_ALL}")
        logging.exception("Fatal error")
        sys.exit(1)


if __name__ == '__main__':
    main()
