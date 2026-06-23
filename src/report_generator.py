"""
ReportGenerator - Xuất báo cáo PDF định kỳ
Đồ án IT3930 - AI-Powered IDS - Đào Huy Phúc - 20236051

Chức năng:
  - aggregate_daily_stats(): Gom số liệu thống kê theo ngày
  - export_to_pdf(): Xuất báo cáo PDF đẹp với biểu đồ
"""

import os
import logging
from datetime import datetime, date, timedelta
from typing import Dict, List, Optional

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                  TableStyle, Image, HRFlowable)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from src.database_connector import DatabaseConnector


logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Xử lý thống kê định kỳ và xuất file PDF báo cáo an ninh.

    Attributes:
        pdf_template (str): Mẫu giao diện PDF
        export_dir (str): Thư mục lưu file
    """

    def __init__(self, config: dict, db: DatabaseConnector):
        report_cfg = config.get("reports", {})
        self.export_dir: str = report_cfg.get("output_dir", "data/reports")
        self.pdf_template: str = "AI-Powered IDS Security Report"

        self.db = db
        os.makedirs(self.export_dir, exist_ok=True)
        logger.info(f" ReportGenerator ready | output_dir={self.export_dir}")

    def aggregate_daily_stats(self, report_date: date = None) -> Dict:
        """
        Gom số liệu thống kê theo ngày.

        Args:
            report_date: Ngày cần thống kê (mặc định: hôm nay)

        Returns:
            Dict chứa toàn bộ số liệu cho báo cáo ngày
        """
        if report_date is None:
            report_date = date.today()

        date_str = report_date.strftime("%Y-%m-%d")

        stats = {"report_date": date_str}

        # 1. Tổng số log thu thập
        r = self.db.execute_query(
            "SELECT COUNT(*) as cnt FROM system_logs WHERE date(logged_at) = ?",
            (date_str,)
        )
        stats['total_logs'] = r[0]['cnt'] if r else 0

        # 2. Tổng số lần failed
        r = self.db.execute_query(
            "SELECT COUNT(*) as cnt FROM system_logs WHERE date(logged_at) = ? AND event_status = 'Failed'",
            (date_str,)
        )
        stats['total_failed'] = r[0]['cnt'] if r else 0

        # 3. Tổng IP bị block trong ngày
        r = self.db.execute_query(
            "SELECT COUNT(*) as cnt FROM blocked_ips WHERE date(blocked_at) = ?",
            (date_str,)
        )
        stats['total_attacks_blocked'] = r[0]['cnt'] if r else 0

        # 4. IP có risk_score cao (>= 0.8)
        r = self.db.execute_query(
            "SELECT COUNT(*) as cnt FROM blocked_ips WHERE date(blocked_at) = ? AND risk_score >= 0.8",
            (date_str,)
        )
        stats['high_risk_ips_count'] = r[0]['cnt'] if r else 0

        # 5. Top 10 IP tấn công
        r = self.db.execute_query(
            """SELECT ip_address, COUNT(*) as attempts, MAX(event_status) as status
               FROM system_logs 
               WHERE date(logged_at) = ? AND event_status = 'Failed'
               GROUP BY ip_address ORDER BY attempts DESC LIMIT 10""",
            (date_str,)
        )
        stats['top_attackers'] = r or []

        # 6. Phân bố tấn công theo giờ (0-23)
        r = self.db.execute_query(
            """SELECT CAST(strftime('%H', logged_at) AS INTEGER) as hour, COUNT(*) as count
               FROM system_logs 
               WHERE date(logged_at) = ? AND event_status = 'Failed'
               GROUP BY hour ORDER BY hour""",
            (date_str,)
        )
        hour_dist = {row['hour']: row['count'] for row in (r or [])}
        stats['hourly_distribution'] = [hour_dist.get(h, 0) for h in range(24)]

        # 7. Cảnh báo đã gửi
        r = self.db.execute_query(
            """SELECT COUNT(*) as cnt, status FROM alert_history 
               WHERE date(sent_at) = ? GROUP BY status""",
            (date_str,)
        )
        stats['alerts_sent'] = sum(row['cnt'] for row in (r or []))

        # 8. Danh sách IP bị block với chi tiết
        r = self.db.execute_query(
            """SELECT b.ip_address, b.risk_score, b.blocked_at, s.rule_name
               FROM blocked_ips b LEFT JOIN security_rules s ON b.rule_id = s.rule_id
               WHERE date(b.blocked_at) = ?
               ORDER BY b.risk_score DESC LIMIT 20""",
            (date_str,)
        )
        stats['blocked_ip_details'] = r or []

        return stats

    def _create_hourly_chart(self, hourly_data: List[int], output_path: str):
        """Tạo biểu đồ cột phân bố tấn công theo giờ."""
        fig, ax = plt.subplots(figsize=(10, 3.5))
        hours = list(range(24))
        colors_bar = ['#ef4444' if v == max(hourly_data) else '#f97316'
                      if v >= np.percentile(hourly_data, 75) else '#6366f1'
                      for v in hourly_data]

        bars = ax.bar(hours, hourly_data, color=colors_bar, edgecolor='#1e1e2e', linewidth=0.5)
        ax.set_xlabel("Giờ trong ngày", fontsize=10)
        ax.set_ylabel("Số lần tấn công", fontsize=10)
        ax.set_title("Phân bố Tấn công theo Giờ", fontsize=12, fontweight='bold')
        ax.set_xticks(hours)
        ax.set_xticklabels([f"{h:02d}h" for h in hours], fontsize=7, rotation=45)
        ax.grid(axis='y', alpha=0.3)
        ax.set_facecolor('#f8fafc')
        fig.patch.set_facecolor('#ffffff')

        # Thêm số liệu trên cột nếu > 0
        for bar, val in zip(bars, hourly_data):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                        str(val), ha='center', va='bottom', fontsize=7)

        plt.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        plt.close()

    def _create_risk_pie_chart(self, stats: Dict, output_path: str):
        """Tạo biểu đồ tròn phân bố mức độ rủi ro."""
        blocked_details = stats.get('blocked_ip_details', [])
        if not blocked_details:
            # Tạo biểu đồ trống
            fig, ax = plt.subplots(figsize=(4, 4))
            ax.text(0.5, 0.5, 'Không có dữ liệu', ha='center', va='center',
                    transform=ax.transAxes, fontsize=12)
            ax.axis('off')
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()
            return

        high = sum(1 for d in blocked_details if d['risk_score'] >= 0.8)
        medium = sum(1 for d in blocked_details if 0.6 <= d['risk_score'] < 0.8)
        low = sum(1 for d in blocked_details if d['risk_score'] < 0.6)

        labels, sizes, chart_colors = [], [], []
        if high > 0:
            labels.append(f'Cao (≥0.8)\n{high} IP')
            sizes.append(high)
            chart_colors.append('#ef4444')
        if medium > 0:
            labels.append(f'Trung bình\n{medium} IP')
            sizes.append(medium)
            chart_colors.append('#f97316')
        if low > 0:
            labels.append(f'Thấp (<0.6)\n{low} IP')
            sizes.append(low)
            chart_colors.append('#6366f1')

        if not sizes:
            return

        fig, ax = plt.subplots(figsize=(4, 4))
        wedges, texts, autotexts = ax.pie(
            sizes, labels=labels, colors=chart_colors,
            autopct='%1.0f%%', startangle=90,
            pctdistance=0.75, labeldistance=1.15
        )
        for text in texts:
            text.set_fontsize(8)
        for autotext in autotexts:
            autotext.set_fontsize(8)
            autotext.set_fontweight('bold')
            autotext.set_color('white')

        ax.set_title("Phân bố Risk Score", fontsize=11, fontweight='bold')
        plt.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches='tight')
        plt.close()

    def export_to_pdf(self, report_date: date = None) -> Optional[str]:
        """
        Xuất file PDF báo cáo an ninh đầy đủ.

        Args:
            report_date: Ngày cần xuất báo cáo

        Returns:
            Đường dẫn file PDF nếu thành công, None nếu thất bại
        """
        if report_date is None:
            report_date = date.today()

        stats = self.aggregate_daily_stats(report_date)
        date_str = report_date.strftime("%Y-%m-%d")
        pdf_filename = f"IDS_Report_{date_str}.pdf"
        pdf_path = os.path.join(self.export_dir, pdf_filename)

        # Tạo biểu đồ
        chart_hourly_path = os.path.join(self.export_dir, f"hourly_{date_str}.png")
        chart_pie_path = os.path.join(self.export_dir, f"pie_{date_str}.png")
        self._create_hourly_chart(stats['hourly_distribution'], chart_hourly_path)
        self._create_risk_pie_chart(stats, chart_pie_path)

        try:
            doc = SimpleDocTemplate(
                pdf_path, pagesize=A4,
                rightMargin=2*cm, leftMargin=2*cm,
                topMargin=2*cm, bottomMargin=2*cm
            )
            styles = getSampleStyleSheet()
            story = []

            # ---- HEADER ----
            title_style = ParagraphStyle(
                'CustomTitle', parent=styles['Title'],
                fontSize=20, textColor=colors.HexColor('#1e293b'),
                spaceAfter=4, alignment=TA_CENTER
            )
            sub_style = ParagraphStyle(
                'SubTitle', parent=styles['Normal'],
                fontSize=11, textColor=colors.HexColor('#64748b'),
                alignment=TA_CENTER, spaceAfter=2
            )
            story.append(Paragraph(" BÁO CÁO AN NINH HỆ THỐNG", title_style))
            story.append(Paragraph("AI-Powered Intrusion Detection System", sub_style))
            story.append(Paragraph(f"Ngày: {date_str} | IT3930 | Đào Huy Phúc - 20236051", sub_style))
            story.append(HRFlowable(width="100%", thickness=2,
                                     color=colors.HexColor('#6366f1')))
            story.append(Spacer(1, 0.4*cm))

            # ---- SUMMARY STATS TABLE ----
            section_style = ParagraphStyle(
                'Section', parent=styles['Heading2'],
                fontSize=13, textColor=colors.HexColor('#1e293b'),
                spaceBefore=8, spaceAfter=4
            )
            story.append(Paragraph(" Tổng quan trong ngày", section_style))

            summary_data = [
                ["Chỉ số", "Số liệu"],
                ["Tổng log thu thập", str(stats['total_logs'])],
                ["Số lần đăng nhập thất bại", str(stats['total_failed'])],
                ["IP tấn công bị chặn", str(stats['total_attacks_blocked'])],
                ["IP nguy hiểm cao (risk ≥ 0.8)", str(stats['high_risk_ips_count'])],
                ["Cảnh báo Telegram đã gửi", str(stats['alerts_sent'])],
            ]
            summary_table = Table(summary_data, colWidths=[10*cm, 7*cm])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#6366f1')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,0), 11),
                ('ROWBACKGROUNDS', (0,1), (-1,-1),
                 [colors.HexColor('#f8fafc'), colors.white]),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
                ('ALIGN', (1,0), (1,-1), 'CENTER'),
                ('FONTNAME', (0,1), (-1,-1), 'Helvetica'),
                ('FONTSIZE', (0,1), (-1,-1), 10),
                ('PADDING', (0,0), (-1,-1), 8),
                ('ROWBACKGROUNDS', (0,1), (-1,-1),
                 [colors.HexColor('#f1f5f9'), colors.white]),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.5*cm))

            # ---- CHARTS ----
            story.append(Paragraph(" Biểu đồ phân tích", section_style))
            if os.path.exists(chart_hourly_path):
                story.append(Image(chart_hourly_path, width=15*cm, height=5.5*cm))
            story.append(Spacer(1, 0.3*cm))
            if os.path.exists(chart_pie_path):
                story.append(Image(chart_pie_path, width=8*cm, height=8*cm))
            story.append(Spacer(1, 0.5*cm))

            # ---- TOP ATTACKERS TABLE ----
            story.append(Paragraph(" Top 10 IP Tấn công", section_style))
            if stats['top_attackers']:
                attacker_data = [["#", "Địa chỉ IP", "Số lần thử"]]
                for i, row in enumerate(stats['top_attackers'][:10], 1):
                    attacker_data.append([
                        str(i), row['ip_address'], str(row['attempts'])
                    ])
                attacker_table = Table(attacker_data, colWidths=[1.5*cm, 10*cm, 5.5*cm])
                attacker_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#ef4444')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1),
                     [colors.HexColor('#fff1f2'), colors.white]),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#fca5a5')),
                    ('ALIGN', (0,0), (-1,-1), 'CENTER'),
                    ('FONTSIZE', (0,0), (-1,-1), 9),
                    ('PADDING', (0,0), (-1,-1), 6),
                ]))
                story.append(attacker_table)
            else:
                story.append(Paragraph(" Không phát hiện tấn công trong ngày", styles['Normal']))

            story.append(Spacer(1, 0.5*cm))

            # ---- BLOCKED IP DETAILS ----
            if stats['blocked_ip_details']:
                story.append(Paragraph(" Chi tiết IP bị chặn", section_style))
                blocked_data = [["IP", "Risk Score", "Luật vi phạm", "Thời gian"]]
                for row in stats['blocked_ip_details'][:15]:
                    blocked_data.append([
                        row['ip_address'],
                        f"{row['risk_score']:.3f}",
                        row.get('rule_name', 'N/A'),
                        str(row['blocked_at'])[:16]
                    ])
                blocked_table = Table(blocked_data,
                                      colWidths=[5*cm, 3*cm, 5*cm, 4*cm])
                blocked_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1e293b')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1),
                     [colors.HexColor('#f0fdf4'), colors.white]),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#d1d5db')),
                    ('ALIGN', (1,0), (1,-1), 'CENTER'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('PADDING', (0,0), (-1,-1), 5),
                ]))
                story.append(blocked_table)

            # ---- FOOTER ----
            story.append(Spacer(1, 1*cm))
            story.append(HRFlowable(width="100%", thickness=1,
                                     color=colors.HexColor('#e2e8f0')))
            footer_style = ParagraphStyle(
                'Footer', parent=styles['Normal'],
                fontSize=8, textColor=colors.HexColor('#94a3b8'),
                alignment=TA_CENTER
            )
            story.append(Paragraph(
                f"Báo cáo được tạo tự động bởi AI-Powered IDS | "
                f"Đồ án IT3930 | ĐHBKHN | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                footer_style
            ))

            doc.build(story)
            logger.info(f" PDF report generated: {pdf_path}")

            # Dọn file chart tạm
            for tmp in [chart_hourly_path, chart_pie_path]:
                if os.path.exists(tmp):
                    os.remove(tmp)

            # Lưu vào DB
            self.db.insert_daily_report(
                report_date=date_str,
                total_blocked=stats['total_attacks_blocked'],
                high_risk_count=stats['high_risk_ips_count'],
                pdf_path=pdf_path
            )

            return pdf_path

        except Exception as e:
            logger.error(f" PDF generation failed: {e}")
            return None
