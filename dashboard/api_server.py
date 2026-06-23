"""
Flask API Server - Backend cho Web Dashboard
Đồ án IT3930 - AI-Powered IDS - Đào Huy Phúc - 20236051
"""

import os
import yaml
import logging
from datetime import date, datetime
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from src.database_connector import DatabaseConnector
from src.ai_threat_detector import AIThreatDetector
from src.report_generator import ReportGenerator
from src.firewall_manager import FirewallManager
from src.alert_manager import AlertManager


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Absolute path tới thư mục dashboard
DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'dashboard')
DASHBOARD_DIR = os.path.normpath(DASHBOARD_DIR)

app = Flask(__name__, static_folder=DASHBOARD_DIR, static_url_path='')
CORS(app)

# Global components
db: DatabaseConnector = None
ai: AIThreatDetector = None
firewall: FirewallManager = None
alert_mgr: AlertManager = None
report_gen: ReportGenerator = None
config: dict = {}


def init_components(cfg: dict):
    global db, ai, firewall, alert_mgr, report_gen, config
    config = cfg
    db = DatabaseConnector(cfg)
    db.connect()
    ai = AIThreatDetector(cfg, db)
    firewall = FirewallManager(cfg, db)
    alert_mgr = AlertManager(cfg, db)
    report_gen = ReportGenerator(cfg, db)
    logger.info(" API Server components initialized")


# ---- Routes ----

@app.route('/')
def index():
    return send_from_directory(DASHBOARD_DIR, 'index.html')

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Thống kê tổng quan cho Dashboard."""
    stats = db.get_dashboard_stats()
    model_info = ai.get_model_info()
    fw_stats = firewall.get_stats()
    return jsonify({
        **stats,
        "ai_model": model_info,
        "firewall": fw_stats,
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Lấy log gần đây."""
    limit = request.args.get('limit', 50, type=int)
    status_filter = request.args.get('status', '')

    if status_filter:
        logs = db.execute_query(
            f"SELECT * FROM system_logs WHERE event_status = %s ORDER BY logged_at DESC LIMIT %s",
            (status_filter, limit)
        )
    else:
        logs = db.execute_query(
            "SELECT * FROM system_logs ORDER BY logged_at DESC LIMIT %s",
            (limit,)
        )
    return jsonify(logs or [])

@app.route('/api/blocked-ips', methods=['GET'])
def get_blocked_ips():
    """Danh sách IP đang bị block."""
    ips = db.execute_query(
        """SELECT b.*, s.rule_name 
           FROM blocked_ips b LEFT JOIN security_rules s ON b.rule_id = s.rule_id
           WHERE b.is_active = TRUE ORDER BY b.blocked_at DESC"""
    )
    return jsonify(ips or [])

@app.route('/api/unblock', methods=['POST'])
def unblock_ip():
    """Mở khóa IP thủ công (Admin)."""
    data = request.json
    ip = data.get('ip_address', '')
    reason = data.get('reason', 'Manual unblock by Admin')

    if not ip:
        return jsonify({"error": "ip_address required"}), 400

    success = firewall.unblock_ip(ip, reason=reason)
    return jsonify({"success": success, "ip": ip})

@app.route('/api/audit-trails', methods=['GET'])
def get_audit_trails():
    """Lịch sử hành động firewall."""
    limit = request.args.get('limit', 30, type=int)
    trails = db.execute_query(
        "SELECT * FROM audit_trails ORDER BY executed_at DESC LIMIT %s", (limit,)
    )
    return jsonify(trails or [])

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Lịch sử cảnh báo Telegram."""
    limit = request.args.get('limit', 30, type=int)
    alerts = db.execute_query(
        "SELECT * FROM alert_history ORDER BY sent_at DESC LIMIT %s", (limit,)
    )
    return jsonify(alerts or [])

@app.route('/api/reports', methods=['GET'])
def get_reports():
    """Danh sách báo cáo PDF."""
    reports = db.execute_query(
        "SELECT * FROM daily_reports ORDER BY report_date DESC LIMIT 30"
    )
    return jsonify(reports or [])

@app.route('/api/reports/generate', methods=['POST'])
def generate_report():
    """Xuất báo cáo PDF theo yêu cầu."""
    data = request.json or {}
    report_date_str = data.get('date', date.today().isoformat())
    try:
        report_date = date.fromisoformat(report_date_str)
    except ValueError:
        return jsonify({"error": "Invalid date format"}), 400

    pdf_path = report_gen.export_to_pdf(report_date)
    if pdf_path:
        return jsonify({"success": True, "path": pdf_path})
    return jsonify({"success": False, "error": "PDF generation failed"}), 500

@app.route('/api/security-rules', methods=['GET'])
def get_security_rules():
    """Lấy danh sách luật bảo mật."""
    rules = db.execute_query("SELECT * FROM security_rules ORDER BY rule_id")
    return jsonify(rules or [])

@app.route('/api/simulate-attack', methods=['POST'])
def simulate_attack():
    """Giả lập tấn công Brute-force để demo."""
    from tests.mock_data_generator import MockDataGenerator
    mock_gen = MockDataGenerator(db)
    count = mock_gen.generate_logs(n_normal=10, n_attack=20, inject_realtime=True)

    # Phân tích ngay
    failed_logs = db.execute_query(
        """SELECT * FROM system_logs WHERE event_status = 'Failed' 
           AND logged_at >= NOW() - INTERVAL '10 minutes'
           ORDER BY logged_at DESC LIMIT 100"""
    ) or []

    detected = 0
    blocked_ips = []
    for log in failed_logs:
        is_attack, risk_score = ai.predict_anomaly(log)
        if is_attack:
            detected += 1
            block_id = firewall.block_ip(
                ip_address=log['ip_address'],
                rule_id=1,
                risk_score=risk_score
            )
            if block_id:
                blocked_ips.append({
                    "ip": log['ip_address'],
                    "risk_score": risk_score,
                    "block_id": block_id
                })
                alert_mgr.send_block_alert(
                    ip_address=log['ip_address'],
                    risk_score=risk_score,
                    block_id=block_id
                )

    return jsonify({
        "logs_generated": count,
        "threats_detected": detected,
        "blocked": blocked_ips
    })

@app.route('/api/ai/train', methods=['POST'])
def retrain_ai():
    """Tái huấn luyện AI model."""
    success = ai.train_model()
    return jsonify({"success": success, "model_info": ai.get_model_info()})

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "running",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "database": db is not None,
            "ai_model": ai._is_trained if ai else False,
        }
    })


if __name__ == '__main__':
    # Load config
    with open('config/config.yaml', 'r', encoding='utf-8') as f:
        cfg = yaml.safe_load(f)

    init_components(cfg)

    dash_cfg = cfg.get('dashboard', {})
    app.run(
        host=dash_cfg.get('host', '0.0.0.0'),
        port=dash_cfg.get('port', 5000),
        debug=dash_cfg.get('debug', False)
    )
