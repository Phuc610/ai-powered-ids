#  AI-Powered IDS | AI Threat Intelligence Engine

![AI-Powered IDS Architecture](https://img.shields.io/badge/Status-Active-success) ![Docker](https://img.shields.io/badge/Docker-Enabled-blue) ![Python](https://img.shields.io/badge/Python-3.11-yellow) ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue)

**AI-Powered IDS** is an enterprise-grade, AI-powered Intrusion Detection System (IDS) designed to protect Linux servers from brute-force attacks and unauthorized access. It monitors SSH logs in real-time, uses Machine Learning to detect anomalous behavior, and automatically mitigates threats.

---

##  Architecture Pipeline

The system operates in a closed-loop security pipeline:

```text
Linux Server (rsyslog) 
    → SSH Log Monitor
    → PostgreSQL Database
    → Isolation Forest AI (Anomaly Detection)
    → Firewall Manager (iptables/fail2ban simulation)
    → Telegram Alert Manager
    → Security Report Generator (PDF)
```

##  Key Features

-  **AI-Powered Detection**: Uses `Isolation Forest` (scikit-learn) with a 6-dimensional feature vector to identify sophisticated attacks that bypass traditional rule-based IDS.
-  **Dockerized Infrastructure**: Fully containerized application and PostgreSQL database with proper health checks and volume persistence.
-  **Real-time Web Dashboard**: Clean, professional dashboard to monitor system health, view logs, and manage blocked IPs.
-  **Instant Notifications**: Automated Telegram alerts for high-risk IPs and system events.
-  **Automated Reporting**: Generates periodic PDF security reports based on DB metrics.

---

##  Quick Start (Docker)

The easiest way to run AI-Powered IDS is via Docker.

### 1. Prerequisites
- Docker & Docker Compose installed
- Telegram Bot Token & Chat ID (for alerts)

### 2. Configuration
Create/edit `config/config.yaml` and add your Telegram credentials:
```yaml
telegram:
  bot_token: "YOUR_BOT_TOKEN"
  chat_id: "YOUR_CHAT_ID"
```

### 3. Deploy
```bash
# Build and start the containers
docker-compose up -d --build

# Check logs
docker-compose logs -f ids_app
```

### 4. Access Dashboard
Open your browser and navigate to: **http://localhost:5001**

---

##  Manual Setup (Development)

If you wish to run the project without Docker:

```bash
# 1. Install dependencies
pip3 install -r requirements.txt

# 2. Run the dashboard
python main.py --mode dashboard
```

##  Database Schema

The system uses **PostgreSQL** with the following tables:
- `system_logs`: Raw logs parsed from auth.log/secure
- `security_rules`: Security threshold configurations
- `blocked_ips`: Actively blocked IP addresses and their AI risk scores
- `audit_trails`: Firewall action history
- `alert_history`: Telegram notification history
- `daily_reports`: Metadata for generated PDF reports

##  AI Model Configuration

- **Algorithm**: Isolation Forest (Unsupervised Learning)
- **Features**: `[failed_10min, failed_60min, success_ratio, hour_of_day, is_weekend, unique_usernames]`
- **Contamination**: 5%
- **Risk threshold**: 0.6
- The model is pre-trained and packaged within the Docker image (`data/models/isolation_forest_model.pkl`).

