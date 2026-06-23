# ============================================================
# Dockerfile - AI-Powered IDS
# Đồ án IT3930 - Đào Huy Phúc - 20236051
# ============================================================

# Base image: Python 3.11 slim (nhẹ hơn full image ~3x)
FROM python:3.11-slim

# Metadata
LABEL maintainer="Đào Huy Phúc <20236051>"
LABEL description="AI-Powered Intrusion Detection System - IT3930"
LABEL version="1.0"

# Tránh prompt tương tác khi cài package
ENV DEBIAN_FRONTEND=noninteractive

# Cài các thư viện hệ thống cần thiết
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Tạo thư mục làm việc trong container
WORKDIR /app

# Copy requirements trước (tận dụng Docker layer cache)
COPY requirements.txt .

# Cài Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir psycopg2-binary && \
    pip install --no-cache-dir -r requirements.txt

# Copy toàn bộ source code
COPY . .

# Tạo các thư mục cần thiết (sẽ được mount volume đè lên)
RUN mkdir -p logs data/reports data/models

# Expose port dashboard
EXPOSE 5001

# Health check: kiểm tra Flask app có đang chạy không
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:5001/api/stats || exit 1

# Lệnh chạy mặc định: Dashboard mode
CMD ["python3", "main.py", "--mode", "dashboard"]
