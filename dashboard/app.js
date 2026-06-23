// ============================================================
// AI-Powered IDS Dashboard - Frontend JS
// Đồ án IT3930 - Đào Huy Phúc - 20236051
// ============================================================

const API = 'http://localhost:5001/api';
let currentPage = 'dashboard';
let weeklyChart = null;
let attackersChart = null;
let currentUnblockIp = null;
let autoRefreshInterval = null;

// ============================================================
// NAVIGATION
// ============================================================
function navigateTo(page) {
    // Hide all pages
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    // Show target page
    const pageEl = document.getElementById(`page-${page}`);
    const navEl = document.getElementById(`nav-${page}`);
    if (pageEl) pageEl.classList.add('active');
    if (navEl) navEl.classList.add('active');

    currentPage = page;

    const titles = {
        dashboard: ' Security Dashboard',
        logs: ' System Logs',
        blocked: ' Blocked IPs',
        alerts: ' Telegram Alerts',
        reports: ' PDF Reports',
        audit: ' Audit Trail'
    };
    document.getElementById('page-title').textContent = titles[page] || page;

    // Load page data
    loadPageData(page);
}

// Nav items click
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        navigateTo(item.dataset.page);
    });
});

function loadPageData(page) {
    switch (page) {
        case 'dashboard': loadDashboard(); break;
        case 'logs': loadLogs(); break;
        case 'blocked': loadBlockedIPs(); break;
        case 'alerts': loadAlerts(); break;
        case 'reports': loadReports(); break;
        case 'audit': loadAuditTrails(); break;
    }
}

// ============================================================
// API CALLS
// ============================================================
async function apiGet(endpoint) {
    try {
        const res = await fetch(`${API}${endpoint}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
    } catch (e) {
        console.error(`API GET ${endpoint}:`, e);
        return null;
    }
}

async function apiPost(endpoint, data = {}) {
    try {
        const res = await fetch(`${API}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
    } catch (e) {
        console.error(`API POST ${endpoint}:`, e);
        return null;
    }
}

// ============================================================
// HEALTH CHECK & SYSTEM STATUS
// ============================================================
async function checkHealth() {
    const data = await apiGet('/health');
    const dot = document.getElementById('system-status-dot');
    const text = document.getElementById('system-status-text');

    if (data && data.status === 'running') {
        dot.className = 'status-dot online';
        text.textContent = 'Hệ thống hoạt động';
    } else {
        dot.className = 'status-dot offline';
        text.textContent = 'Mất kết nối';
    }
}

// ============================================================
// DASHBOARD
// ============================================================
async function loadDashboard() {
    const data = await apiGet('/stats');
    if (!data) {
        showToast('Không thể kết nối API server', 'error');
        return;
    }

    // Update stat cards
    updateStatCard('stat-logs-today', data.logs_today || 0);
    updateStatCard('stat-active-blocks', data.active_blocks || 0);
    updateStatCard('stat-alerts-today', data.alerts_today || 0);
    updateStatCard('stat-ai-status', data.ai_model?.is_trained ? 'Online' : 'Training');

    // Update AI Panel
    if (data.ai_model) {
        document.getElementById('ai-info-trained').textContent = data.ai_model.is_trained ? ' Đã huấn luyện (Online)' : ' Chưa huấn luyện';
        document.getElementById('ai-info-estimators').textContent = data.ai_model.n_estimators || 100;
        document.getElementById('ai-info-contamination').textContent = data.ai_model.contamination || '0.05';
        document.getElementById('ai-info-threshold').textContent = data.ai_model.risk_threshold || '0.6';
        document.getElementById('ai-info-path').textContent = data.ai_model.model_path || 'data/isolation_forest_model.pkl';
    }

    // Blocked badge in sidebar
    const badge = document.getElementById('blocked-badge');
    if (badge) badge.textContent = data.active_blocks || 0;

    // Update timestamp
    const now = new Date().toLocaleString('vi-VN');
    document.getElementById('last-update').textContent = `Cập nhật: ${now}`;

    // Charts
    renderWeeklyChart(data.blocks_7days || []);
    renderAttackersChart(data.top_attackers || []);

    // Recent blocks table
    renderRecentBlocks(data.recent_blocks || []);
}

function updateStatCard(id, value) {
    const el = document.getElementById(id);
    if (el && el.textContent !== String(value)) {
        el.classList.add('updating');
        el.textContent = value;
        setTimeout(() => el.classList.remove('updating'), 400);
    }
}

function renderWeeklyChart(data) {
    const ctx = document.getElementById('chart-weekly');
    if (!ctx) return;

    // Tạo 7 ngày gần nhất
    const days = [];
    const counts = [];
    for (let i = 6; i >= 0; i--) {
        const d = new Date();
        d.setDate(d.getDate() - i);
        const dateStr = d.toISOString().split('T')[0];
        days.push(d.toLocaleDateString('vi-VN', { month: 'short', day: 'numeric' }));
        const found = data.find(r => r.day === dateStr);
        counts.push(found ? found.count : 0);
    }

    if (weeklyChart) weeklyChart.destroy();
    weeklyChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: days,
            datasets: [{
                label: 'IP bị chặn',
                data: counts,
                backgroundColor: counts.map((v, i) =>
                    i === counts.length - 1
                        ? 'rgba(239,68,68,0.8)'
                        : 'rgba(124,58,237,0.6)'
                ),
                borderColor: counts.map((v, i) =>
                    i === counts.length - 1 ? '#ef4444' : '#7c3aed'
                ),
                borderWidth: 1,
                borderRadius: 6,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(15,15,46,0.9)',
                    borderColor: 'rgba(255,255,255,0.1)',
                    borderWidth: 1,
                    titleColor: '#f1f5f9',
                    bodyColor: '#94a3b8',
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#64748b', font: { size: 11 } }
                },
                y: {
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#64748b', font: { size: 11 }, stepSize: 1 },
                    beginAtZero: true
                }
            }
        }
    });
}

function renderAttackersChart(data) {
    const ctx = document.getElementById('chart-attackers');
    if (!ctx) return;

    if (attackersChart) attackersChart.destroy();

    if (!data.length) {
        return;
    }

    const labels = data.map(d => d.ip_address);
    const values = data.map(d => d.attempts);
    const colors = ['#ef4444', '#f97316', '#f59e0b', '#6366f1', '#8b5cf6'];

    attackersChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: colors.slice(0, labels.length).map(c => c + 'cc'),
                borderColor: colors.slice(0, labels.length),
                borderWidth: 2,
                hoverOffset: 8,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        font: { size: 10 },
                        boxWidth: 10,
                        padding: 8,
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(15,15,46,0.9)',
                    borderColor: 'rgba(255,255,255,0.1)',
                    borderWidth: 1,
                    titleColor: '#f1f5f9',
                    bodyColor: '#94a3b8',
                    callbacks: {
                        label: (ctx) => ` ${ctx.label}: ${ctx.raw} lần thử`
                    }
                }
            }
        }
    });
}

function renderRecentBlocks(blocks) {
    const tbody = document.getElementById('tbody-recent-blocks');
    if (!tbody) return;

    if (!blocks.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="loading-row"> Chưa có IP nào bị chặn</td></tr>';
        return;
    }

    tbody.innerHTML = blocks.map(row => `
        <tr>
            <td><span class="ip-text">${row.ip_address}</span></td>
            <td>${renderRiskBadge(row.risk_score)}</td>
            <td><span style="font-size:12px">${row.rule_name || 'Brute-force SSH'}</span></td>
            <td><span class="time-text">${formatTime(row.blocked_at)}</span></td>
            <td>
                <button class="btn btn-sm btn-success" onclick="showUnblockModal('${row.ip_address}')">
                     Mở khóa
                </button>
            </td>
        </tr>
    `).join('');
}

// ============================================================
// LOGS PAGE
// ============================================================
async function loadLogs() {
    const status = document.getElementById('log-status-filter')?.value || '';
    const limit = document.getElementById('log-limit')?.value || 100;

    let url = `/logs?limit=${limit}`;
    if (status) url += `&status=${status}`;

    const logs = await apiGet(url);
    const tbody = document.getElementById('tbody-logs');
    const countEl = document.getElementById('logs-count');

    if (!logs) {
        tbody.innerHTML = '<tr><td colspan="6" class="loading-row">Lỗi tải dữ liệu</td></tr>';
        return;
    }

    if (countEl) countEl.textContent = `${logs.length} bản ghi`;

    tbody.innerHTML = logs.map((log, i) => `
        <tr>
            <td style="color:var(--text-muted)">${log.log_id || i+1}</td>
            <td><span class="ip-text">${log.ip_address}</span></td>
            <td style="font-family:var(--font-mono);font-size:12px">${log.username || '-'}</td>
            <td>${renderStatusBadge(log.event_status)}</td>
            <td><span class="time-text">${formatTime(log.logged_at)}</span></td>
            <td style="font-family:var(--font-mono);font-size:10px;color:var(--text-muted);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(log.raw_log || '')}">
                ${escHtml((log.raw_log || '').slice(0, 80))}${log.raw_log?.length > 80 ? '...' : ''}
            </td>
        </tr>
    `).join('');
}

// ============================================================
// BLOCKED IPs PAGE
// ============================================================
async function loadBlockedIPs() {
    const ips = await apiGet('/blocked-ips');
    const tbody = document.getElementById('tbody-blocked');
    const countEl = document.getElementById('blocked-count');

    if (!ips) {
        tbody.innerHTML = '<tr><td colspan="6" class="loading-row">Lỗi tải dữ liệu</td></tr>';
        return;
    }

    if (countEl) countEl.textContent = `${ips.length} IP`;

    // Update sidebar badge
    const badge = document.getElementById('blocked-badge');
    if (badge) badge.textContent = ips.length;

    if (!ips.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="loading-row"> Không có IP nào đang bị chặn</td></tr>';
        return;
    }

    tbody.innerHTML = ips.map(row => `
        <tr>
            <td><span class="ip-text">${row.ip_address}</span></td>
            <td>${renderRiskBadge(row.risk_score)}</td>
            <td><span style="font-size:12px">${row.rule_name || 'N/A'}</span></td>
            <td><span class="time-text">${formatTime(row.blocked_at)}</span></td>
            <td><span class="time-text">${row.release_at ? formatTime(row.release_at) : ' Vĩnh viễn'}</span></td>
            <td>
                <button class="btn btn-sm btn-success" onclick="showUnblockModal('${row.ip_address}')">
                     Mở khóa
                </button>
            </td>
        </tr>
    `).join('');
}

// ============================================================
// ALERTS PAGE
// ============================================================
async function loadAlerts() {
    const alerts = await apiGet('/alerts?limit=30');
    const container = document.getElementById('alerts-container');

    if (!alerts || !alerts.length) {
        container.innerHTML = '<div class="no-data"> Chưa có cảnh báo nào được gửi</div>';
        return;
    }

    container.innerHTML = alerts.map(a => `
        <div class="alert-card ${a.status === 'SUCCESS' ? 'success' : 'failed'}">
            <div class="alert-header">
                <span class="alert-platform">
                    ${a.status === 'SUCCESS' ? '' : ''} ${a.platform || 'Telegram'}
                </span>
                <span class="alert-time">${formatTime(a.sent_at)}</span>
            </div>
            <div class="alert-content">${escHtml(a.message_content || '')}</div>
        </div>
    `).join('');
}

// ============================================================
// REPORTS PAGE
// ============================================================
async function loadReports() {
    // Set default date
    const dateInput = document.getElementById('report-date');
    if (dateInput && !dateInput.value) {
        dateInput.value = new Date().toISOString().split('T')[0];
    }

    const reports = await apiGet('/reports');
    const tbody = document.getElementById('tbody-reports');

    if (!reports) {
        tbody.innerHTML = '<tr><td colspan="5" class="loading-row">Lỗi tải dữ liệu</td></tr>';
        return;
    }

    if (!reports.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="loading-row"> Chưa có báo cáo nào</td></tr>';
        return;
    }

    tbody.innerHTML = reports.map(r => `
        <tr>
            <td style="font-family:var(--font-mono)">${r.report_date}</td>
            <td><strong style="color:var(--accent-red)">${r.total_attacks_blocked}</strong></td>
            <td><strong style="color:var(--accent-orange)">${r.high_risk_ips_count}</strong></td>
            <td style="font-family:var(--font-mono);font-size:11px;color:var(--text-muted)">${r.pdf_file_path || '-'}</td>
            <td><span class="time-text">${formatTime(r.generated_at)}</span></td>
        </tr>
    `).join('');
}

async function generateReport() {
    const dateInput = document.getElementById('report-date');
    const reportDate = dateInput?.value || new Date().toISOString().split('T')[0];

    showToast(' Đang xuất báo cáo PDF...', 'info');
    const result = await apiPost('/reports/generate', { date: reportDate });

    if (result?.success) {
        showToast(` PDF đã xuất: ${result.path}`, 'success');
        if (currentPage === 'reports') loadReports();
    } else {
        showToast(' Xuất PDF thất bại', 'error');
    }
}

// ============================================================
// AUDIT TRAIL PAGE
// ============================================================
async function loadAuditTrails() {
    const trails = await apiGet('/audit-trails?limit=50');
    const tbody = document.getElementById('tbody-audit');

    if (!trails) {
        tbody.innerHTML = '<tr><td colspan="4" class="loading-row">Lỗi tải dữ liệu</td></tr>';
        return;
    }

    if (!trails.length) {
        tbody.innerHTML = '<tr><td colspan="4" class="loading-row"> Chưa có hành động firewall nào</td></tr>';
        return;
    }

    tbody.innerHTML = trails.map(t => `
        <tr>
            <td><span class="action-${t.action_type.toLowerCase()}">${t.action_type}</span></td>
            <td><span class="ip-text">${t.target_ip}</span></td>
            <td style="font-size:12px;color:var(--text-secondary)">${t.description || '-'}</td>
            <td><span class="time-text">${formatTime(t.executed_at)}</span></td>
        </tr>
    `).join('');
}

// ============================================================
// ACTIONS
// ============================================================
async function simulateAttack() {
    const btn = document.getElementById('btn-simulate-attack');
    btn.disabled = true;
    btn.textContent = ' Đang chạy...';
    showToast(' Đang giả lập tấn công Brute-force...', 'warning');

    const result = await apiPost('/simulate-attack');

    btn.disabled = false;
    btn.textContent = ' Giả lập Tấn công';

    if (result) {
        showToast(
            ` Phát hiện ${result.threats_detected} mối đe dọa | Blocked: ${result.blocked?.length || 0} IP`,
            'error'
        );
        // Refresh dashboard
        setTimeout(() => {
            if (currentPage === 'dashboard') loadDashboard();
        }, 1000);
    } else {
        showToast(' Lỗi khi giả lập tấn công', 'error');
    }
}

async function retrainAI() {
    const btn1 = document.getElementById('btn-train-ai');
    const btn2 = document.getElementById('btn-train-ai-panel');
    if (btn1) btn1.disabled = true;
    if (btn2) btn2.disabled = true;
    
    showToast(' AI đang học lại dữ liệu từ Database. Vui lòng đợi...', 'info');
    
    const result = await apiPost('/ai/train');
    
    if (btn1) btn1.disabled = false;
    if (btn2) btn2.disabled = false;

    if (result && result.success) {
        showToast(' Đã huấn luyện xong mô hình AI mới!', 'success');
        refreshAll();
    } else {
        showToast(' Lỗi khi huấn luyện AI (có thể do chưa đủ dữ liệu mẫu)', 'error');
    }
}

function showUnblockModal(ip) {
    currentUnblockIp = ip;
    document.getElementById('modal-ip').textContent = ip;
    document.getElementById('modal-unblock').classList.add('show');
}

function closeModal() {
    document.getElementById('modal-unblock').classList.remove('show');
    currentUnblockIp = null;
}

async function confirmUnblock() {
    if (!currentUnblockIp) return;

    const ipToUnblock = currentUnblockIp;
    const reason = document.getElementById('unblock-reason').value;
    const result = await apiPost('/unblock', {
        ip_address: ipToUnblock,
        reason
    });

    closeModal();

    if (result?.success) {
        showToast(` Đã mở khóa IP: ${ipToUnblock}`, 'success');
        loadPageData(currentPage);
    } else {
        showToast(` Không thể mở khóa IP: ${ipToUnblock}`, 'error');
    }
}

async function refreshAll() {
    showToast(' Đang làm mới...', 'info');
    await checkHealth();
    loadPageData(currentPage);
}

// ============================================================
// HELPER FUNCTIONS
// ============================================================
function renderRiskBadge(score) {
    score = parseFloat(score) || 0;
    if (score >= 0.8) return `<span class="risk-badge risk-high"> ${score.toFixed(3)}</span>`;
    if (score >= 0.6) return `<span class="risk-badge risk-medium"> ${score.toFixed(3)}</span>`;
    return `<span class="risk-badge risk-low"> ${score.toFixed(3)}</span>`;
}

function renderStatusBadge(status) {
    const map = {
        'Failed': '<span class="status-badge status-failed"> Failed</span>',
        'Success': '<span class="status-badge status-success"> Success</span>',
        'Invalid': '<span class="status-badge status-invalid"> Invalid</span>',
    };
    return map[status] || `<span class="status-badge">${status}</span>`;
}

function formatTime(timeStr) {
    if (!timeStr) return '-';
    try {
        const d = new Date(timeStr);
        return d.toLocaleString('vi-VN', {
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
    } catch { return timeStr; }
}

function escHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ============================================================
// TOAST NOTIFICATIONS
// ============================================================
function showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const icons = { success: '', error: '', warning: '', info: '' };
    toast.innerHTML = `<span>${icons[type] || ''}</span><span>${message}</span>`;

    container.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'slide-out 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, duration);
}

// ============================================================
// AUTO REFRESH
// ============================================================
function startAutoRefresh(intervalMs = 30000) {
    if (autoRefreshInterval) clearInterval(autoRefreshInterval);
    autoRefreshInterval = setInterval(() => {
        loadPageData(currentPage);
        checkHealth();
    }, intervalMs);
}

// ============================================================
// INITIALIZATION
// ============================================================
document.addEventListener('DOMContentLoaded', async () => {
    console.log(' AI-Powered IDS Dashboard loaded');

    // Check API connection
    await checkHealth();

    // Load initial dashboard
    loadDashboard();

    // Auto refresh every 30 seconds
    startAutoRefresh(30000);

    // Set today's date for report picker
    const dateInput = document.getElementById('report-date');
    if (dateInput) dateInput.value = new Date().toISOString().split('T')[0];
});
