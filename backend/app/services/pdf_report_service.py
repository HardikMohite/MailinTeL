import os
import io
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image as PlatypusImage, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Group, Polygon
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY


from reportlab.pdfgen import canvas

# Brand asset paths
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
LOGO_PATH = os.path.join(BACKEND_DIR, "app", "static", "assets", "mailintel_symbol.png")
WATERMARK_PATH = os.path.join(BACKEND_DIR, "app", "static", "assets", "mailintel_watermark.png")


class ForensicNumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that dynamically calculates and prints total page counts
    ('Page X of Y') along with tamper-evident forensic watermark and running footer.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_decorations(self, num_pages: int):
        self.saveState()
        page_w, page_h = self._pagesize

        # 1. Subtle Center Watermark
        if os.path.exists(WATERMARK_PATH):
            wm_size = 320
            wm_x = (page_w - wm_size) / 2
            wm_y = (page_h - wm_size) / 2 + 15
            try:
                self.drawImage(
                    WATERMARK_PATH,
                    wm_x,
                    wm_y,
                    width=wm_size,
                    height=wm_size,
                    mask='auto',
                    preserveAspectRatio=True
                )
            except Exception:
                pass

        # 2. Running Footer Line & Tamper-Evident Metadata
        footer_y = 26
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.6)
        self.line(36, footer_y, page_w - 36, footer_y)

        self.setFont("Helvetica-Bold", 6.5)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawString(36, footer_y - 10, "MAILINTEL EMAIL FORENSIC REPORT  |  CONFIDENTIAL  |  TLP:AMBER+STRICT")
        self.drawRightString(page_w - 36, footer_y - 10, f"Page {self._pageNumber} of {num_pages}")

        self.restoreState()


class PDFReportService:
    """
    Generates professional, simple-language, strictly 2-page A4 forensic email threat intelligence reports
    formatted to MailinTeL project specifications.
    """

    @classmethod
    def create_likelihood_chart(cls, likelihoods: Dict[str, Any], width: float = 258, height: float = 72) -> Drawing:
        """
        Renders a simple, clean horizontal bar chart showing attack risk assessment.
        """
        d = Drawing(width, height)
        
        # Background card
        d.add(Rect(0, 0, width, height, fillColor=colors.HexColor("#f8fafc"), strokeColor=colors.HexColor("#e2e8f0"), strokeWidth=0.75, rx=4, ry=4))
        
        # Title in simple words
        d.add(String(8, height - 12, "THREAT & ATTACK RISK ASSESSMENT", fontName="Helvetica-Bold", fontSize=6.5, fillColor=colors.HexColor("#0f172a")))
        
        items = [
            ("Account Compromise", likelihoods.get("compromised_account", "UNLIKELY")),
            ("Fake / Spoofed Sender", likelihoods.get("spoofed_domain", "UNLIKELY")),
            ("Hidden Origin (VPN/TOR)", likelihoods.get("anonymized_infrastructure", "UNLIKELY")),
            ("Malicious Environment", likelihoods.get("malicious_environment", "UNLIKELY")),
        ]
        
        y_start = height - 25
        row_gap = 12
        bar_x = 94
        bar_max_w = 108
        
        level_map = {
            "CRITICAL": (1.0, colors.HexColor("#dc2626"), "CRITICAL"),
            "HIGH": (0.85, colors.HexColor("#ef4444"), "HIGH"),
            "MEDIUM": (0.55, colors.HexColor("#f59e0b"), "MEDIUM"),
            "LOW": (0.28, colors.HexColor("#10b981"), "LOW"),
            "UNLIKELY": (0.12, colors.HexColor("#94a3b8"), "UNLIKELY"),
            "NONE": (0.05, colors.HexColor("#cbd5e1"), "NONE"),
        }
        
        for idx, (label, val) in enumerate(items):
            cur_y = y_start - (idx * row_gap)
            val_norm = str(val or "UNLIKELY").upper()
            ratio, bar_color, disp_text = level_map.get(val_norm, (0.12, colors.HexColor("#94a3b8"), "UNLIKELY"))
            
            # Label
            d.add(String(8, cur_y + 1, label, fontName="Helvetica", fontSize=6, fillColor=colors.HexColor("#334155")))
            
            # Track
            d.add(Rect(bar_x, cur_y, bar_max_w, 7, fillColor=colors.HexColor("#e2e8f0"), strokeColor=None, rx=2, ry=2))
            
            # Fill
            fill_w = max(6, bar_max_w * ratio)
            d.add(Rect(bar_x, cur_y, fill_w, 7, fillColor=bar_color, strokeColor=None, rx=2, ry=2))
            
            # Text value
            d.add(String(bar_x + bar_max_w + 5, cur_y + 1, disp_text, fontName="Helvetica-Bold", fontSize=6, fillColor=bar_color))
            
        return d

    @classmethod
    def create_risk_and_auth_card(cls, scores: Dict[str, Any], auth: Dict[str, Any], width: float = 258, height: float = 72) -> Drawing:
        """
        Renders a simple, clean card displaying the Risk Score meter and Core Security Checks.
        """
        d = Drawing(width, height)
        d.add(Rect(0, 0, width, height, fillColor=colors.HexColor("#f8fafc"), strokeColor=colors.HexColor("#e2e8f0"), strokeWidth=0.75, rx=4, ry=4))
        
        # Card Header in simple words
        d.add(String(8, height - 12, "RISK SCORE & SENDER SECURITY CHECKS", fontName="Helvetica-Bold", fontSize=6.5, fillColor=colors.HexColor("#0f172a")))
        
        # Left side: Score meter
        threat_score = float(scores.get("threat_risk_score", 0.0))
        verdict = str(scores.get("threat_classification", "UNKNOWN")).upper()
        conf = float(scores.get("evidence_confidence_score", 0.0))
        
        score_color = colors.HexColor("#dc2626") if verdict in ("MALICIOUS", "CRITICAL") else (colors.HexColor("#d97706") if verdict == "SUSPICIOUS" else colors.HexColor("#16a34a"))
        
        # Big score number
        d.add(String(8, height - 32, f"{threat_score:.1f}", fontName="Helvetica-Bold", fontSize=18, fillColor=score_color))
        d.add(String(48, height - 25, "/ 100", fontName="Helvetica", fontSize=7.5, fillColor=colors.HexColor("#64748b")))
        d.add(String(8, height - 43, f"Confidence: {conf:.0f}%", fontName="Helvetica", fontSize=6.5, fillColor=colors.HexColor("#475569")))
        
        # Segmented gauge bar
        meter_x = 8
        meter_y = height - 56
        seg_w = 26
        d.add(Rect(meter_x, meter_y, seg_w, 5, fillColor=colors.HexColor("#10b981"), strokeColor=None, rx=1, ry=1))
        d.add(Rect(meter_x + seg_w + 2, meter_y, seg_w, 5, fillColor=colors.HexColor("#f59e0b"), strokeColor=None, rx=1, ry=1))
        d.add(Rect(meter_x + (seg_w * 2) + 4, meter_y, seg_w, 5, fillColor=colors.HexColor("#ef4444"), strokeColor=None, rx=1, ry=1))
        
        # Marker tick
        clamped_score = max(0.0, min(100.0, threat_score))
        total_meter_w = (seg_w * 3) + 4
        marker_x = meter_x + (clamped_score / 100.0) * total_meter_w
        d.add(Polygon([marker_x - 3, meter_y - 2, marker_x + 3, meter_y - 2, marker_x, meter_y + 1], fillColor=colors.HexColor("#0f172a"), strokeColor=None))
        d.add(String(meter_x, meter_y - 8, "Safe (0)", fontName="Helvetica", fontSize=5, fillColor=colors.HexColor("#94a3b8")))
        d.add(String(meter_x + total_meter_w - 28, meter_y - 8, "Dangerous (100)", fontName="Helvetica", fontSize=5, fillColor=colors.HexColor("#94a3b8")))
        
        # Vertical divider
        d.add(Line(100, 6, 100, height - 8, strokeColor=colors.HexColor("#e2e8f0"), strokeWidth=0.75))
        
        # Right side: Simple Security Checks (SPF, DKIM, DMARC, Domain Match)
        auth_items = [
            ("SPF Check", auth.get("spf_result", "NONE")),
            ("DKIM Signature", auth.get("dkim_result", "NONE")),
            ("DMARC Policy", auth.get("dmarc_result", "NONE")),
            ("Domain Match", auth.get("from_domain_alignment", "NONE")),
        ]
        
        grid_x1, grid_x2 = 107, 182
        y_r1, y_r2 = height - 34, height - 57
        positions = [(grid_x1, y_r1), (grid_x2, y_r1), (grid_x1, y_r2), (grid_x2, y_r2)]
        
        for (label, val), (gx, gy) in zip(auth_items, positions):
            val_str = str(val or "NONE").upper()
            pill_color = colors.HexColor("#10b981") if val_str == "PASS" else (colors.HexColor("#ef4444") if val_str in ("FAIL", "REJECT") else colors.HexColor("#f59e0b"))
            pill_bg = colors.HexColor("#ecfdf5") if val_str == "PASS" else (colors.HexColor("#fef2f2") if val_str in ("FAIL", "REJECT") else colors.HexColor("#fffbeb"))
            
            d.add(Rect(gx, gy, 68, 19, fillColor=pill_bg, strokeColor=pill_color, strokeWidth=0.5, rx=2, ry=2))
            d.add(String(gx + 4, gy + 11, label, fontName="Helvetica", fontSize=5.5, fillColor=colors.HexColor("#475569")))
            d.add(String(gx + 4, gy + 3.5, val_str, fontName="Helvetica-Bold", fontSize=6.5, fillColor=pill_color))
            
        return d

    @classmethod
    def build_email_story(cls, data: Dict[str, Any]) -> List[Any]:
        """
        Builds the complete flowable story elements for a single email forensic dossier.
        """
        # Typography & Styles
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'BrandTitle',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=16,
            leading=18,
            textColor=colors.HexColor('#0f172a'),
        )
        subtitle_style = ParagraphStyle(
            'BrandSub',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=7,
            leading=9,
            textColor=colors.HexColor('#0284c7'),
        )
        meta_right = ParagraphStyle(
            'MetaRight',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=6.5,
            leading=8.5,
            alignment=TA_RIGHT,
            textColor=colors.HexColor('#475569'),
        )
        section_head = ParagraphStyle(
            'SecHead',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=8,
            leading=10,
            textColor=colors.HexColor('#0f172a'),
        )
        body_cell = ParagraphStyle(
            'BodyCell',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=6.5,
            leading=8,
            textColor=colors.HexColor('#1e293b'),
        )
        body_cell_bold = ParagraphStyle(
            'BodyCellBold',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=6.5,
            leading=8,
            textColor=colors.HexColor('#0f172a'),
        )
        body_mono = ParagraphStyle(
            'BodyMono',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=6,
            leading=7.5,
            textColor=colors.HexColor('#0f172a'),
        )
        disclaimer_style = ParagraphStyle(
            'DisclaimerText',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=5.5,
            leading=7.5,
            textColor=colors.HexColor('#334155'),
        )

        meta = data.get("email_metadata", {})
        scores = data.get("explainable_scores", {})
        auth = data.get("authentication_and_headers", {})
        custody = data.get("custody_and_integrity", {})
        integ = custody.get("integrity", {})
        dna = data.get("email_dna") or {}
        intel = data.get("threat_intelligence", {})
        geo = data.get("geo_intelligence", {})
        sim = data.get("similarity_and_clusters", {})
        limitations = data.get("limitations_and_disclaimer", {})
        
        dom_intel = data.get("domain_intelligence") or {}
        
        raw_classification = str(scores.get("threat_classification", "UNKNOWN")).upper()
        if raw_classification in ("BENIGN", "CLEAN", "SAFE"):
            classification = "CLEAN / SAFE"
            badge_bg = colors.HexColor("#f0fdf4")
            badge_border = colors.HexColor("#16a34a")
        elif raw_classification in ("MALICIOUS", "CRITICAL"):
            classification = "DANGEROUS"
            badge_bg = colors.HexColor("#fef2f2")
            badge_border = colors.HexColor("#dc2626")
        elif raw_classification == "SUSPICIOUS":
            classification = "SUSPICIOUS"
            badge_bg = colors.HexColor("#fffbeb")
            badge_border = colors.HexColor("#d97706")
        else:
            classification = "UNVERIFIED"
            badge_bg = colors.HexColor("#f8fafc")
            badge_border = colors.HexColor("#64748b")

        threat_score = float(scores.get("threat_risk_score", 0.0))
        confidence = float(scores.get("evidence_confidence_score", 0.0))

        story = []

        # =========================================================================
        # PAGE 1: EXECUTIVE DOSSIER, VERDICT, CHARTS & EVIDENCE INTEGRITY
        # =========================================================================
        
        # 1. Header Block (Logo & Name at Top Left, Simple Metadata at Top Right)
        logo_img = None
        if os.path.exists(LOGO_PATH):
            try:
                logo_img = PlatypusImage(LOGO_PATH, width=33, height=36)
            except Exception:
                logo_img = Paragraph("🛡️", title_style)
        else:
            logo_img = Paragraph("🛡️", title_style)

        brand_cell = [
            Paragraph("MailinTeL", title_style),
            Spacer(1, 1),
            Paragraph("EMAIL THREAT ANALYSIS & FORENSIC REPORT", subtitle_style),
        ]

        meta_cell = [
            Paragraph(f"<b>REPORT ID:</b> {data.get('report_id', str(uuid.uuid4()))[:18]}...", meta_right),
            Paragraph(f"<b>ANALYZED AT:</b> {data.get('generated_at', datetime.now(timezone.utc).isoformat())[:19]} UTC", meta_right),
            Paragraph("<b>CLASSIFICATION:</b> <font color='#dc2626'><b>TLP:AMBER+STRICT</b></font>", meta_right),
            Paragraph("<b>FILE INTEGRITY:</b> <font color='#16a34a'><b>VERIFIED & SECURED</b></font>", meta_right),
        ]

        # Total printable width on A4 is ~523 pt: 36 + 234 + 253 = 523
        header_table = Table(
            [[logo_img, brand_cell, meta_cell]],
            colWidths=[36, 234, 253],
        )
        header_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
        ]))
        story.append(header_table)
        
        # Crisp accent line under header
        divider_drawing = Drawing(523, 3)
        divider_drawing.add(Line(0, 1.5, 523, 1.5, strokeColor=colors.HexColor("#0284c7"), strokeWidth=1.5))
        story.append(divider_drawing)
        story.append(Spacer(1, 5))

        # 2. Overall Verdict Banner
        summary_text = scores.get("summary", "Automated email security checks completed.")
        if len(summary_text) > 170:
            summary_text = summary_text[:167] + "..."

        verdict_p1 = Paragraph(
            f"<b>OVERALL VERDICT:</b> <font color='{badge_border.hexval()}'><b>{classification}</b></font>",
            ParagraphStyle('V1', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=10, leading=12, textColor=colors.HexColor('#0f172a'))
        )
        verdict_p2 = Paragraph(f"<b>Key Finding:</b> {summary_text}", ParagraphStyle('V2', parent=styles['Normal'], fontName='Helvetica', fontSize=6.5, leading=8.5, textColor=colors.HexColor('#334155')))

        score_box = [
            Paragraph(f"<font size=14 color='{badge_border.hexval()}'><b>{threat_score:.1f}</b></font><font size=8 color='#64748b'>/100</font>", ParagraphStyle('SB1', alignment=TA_RIGHT)),
            Paragraph(f"<font size=6 color='#475569'>Confidence: <b>{confidence:.0f}%</b></font>", ParagraphStyle('SB2', alignment=TA_RIGHT)),
        ]

        verdict_table = Table(
            [[[verdict_p1, Spacer(1, 2), verdict_p2], score_box]],
            colWidths=[405, 118]
        )
        verdict_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), badge_bg),
            ('BOX', (0, 0), (-1, -1), 1, badge_border),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(verdict_table)
        story.append(Spacer(1, 7))

        # 3. Simple Visual Analysis Charts
        chart_left = cls.create_likelihood_chart(scores.get("likelihoods", {}), width=258, height=72)
        chart_right = cls.create_risk_and_auth_card(scores, auth, width=258, height=72)
        
        charts_table = Table([[chart_left, chart_right]], colWidths=[261, 262])
        charts_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
        ]))
        story.append(charts_table)
        story.append(Spacer(1, 7))

        # 4. Section 1: Email Details & File Integrity
        sec1_header = Table([[
            Paragraph("<b>1. EMAIL DETAILS & FILE INTEGRITY</b>", section_head)
        ]], colWidths=[523])
        sec1_header.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('LINELEFT', (0, 0), (0, -1), 2.5, colors.HexColor("#0284c7")),
        ]))
        story.append(sec1_header)
        story.append(Spacer(1, 3))

        to_str = ", ".join(meta.get("to_addresses", [])) or "N/A"
        if len(to_str) > 55: to_str = to_str[:52] + "..."
        from_str = f"{meta.get('from_address', 'N/A')} ({meta.get('from_name') or 'N/A'})"
        if len(from_str) > 55: from_str = from_str[:52] + "..."
        subj_str = meta.get("subject", "N/A")
        if len(subj_str) > 55: subj_str = subj_str[:52] + "..."

        ev_data = [
            [
                Paragraph("<b>Subject:</b>", body_cell_bold), Paragraph(subj_str, body_cell),
                Paragraph("<b>Sent Date:</b>", body_cell_bold), Paragraph(str(meta.get("date_header", "N/A")), body_cell)
            ],
            [
                Paragraph("<b>From:</b>", body_cell_bold), Paragraph(from_str, body_cell),
                Paragraph("<b>Email ID:</b>", body_cell_bold), Paragraph(str(data.get("email_id", "N/A"))[:20] + "...", body_mono)
            ],
            [
                Paragraph("<b>To:</b>", body_cell_bold), Paragraph(to_str, body_cell),
                Paragraph("<b>File Size:</b>", body_cell_bold), Paragraph(f"{meta.get('file_size_bytes', 0):,} bytes", body_cell)
            ],
            [
                Paragraph("<b>SHA-256 Hash:</b>", body_cell_bold), Paragraph(str(meta.get("sha256_hash", "N/A")), body_mono),
                Paragraph("<b>Attachments:</b>", body_cell_bold), Paragraph(f"{meta.get('attachment_count', 0)} file(s)", body_cell)
            ],
            [
                Paragraph("<b>Storage Path:</b>", body_cell_bold), Paragraph(f"{integ.get('bucket', 'mailintel-evidence')} / {str(integ.get('object_key', 'N/A'))[:28]}...", body_mono),
                Paragraph("<b>Tamper Check:</b>", body_cell_bold), Paragraph("<font color='#16a34a'><b>LOCKED & UNALTERED</b></font>", body_cell)
            ],
        ]
        ev_table = Table(ev_data, colWidths=[78, 205, 78, 162])
        ev_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(ev_table)
        story.append(Spacer(1, 7))

        # 5. Section 2: Sender Domain & Registration Intelligence
        sec2_header = Table([[
            Paragraph("<b>2. SENDER DOMAIN & REGISTRATION INTELLIGENCE</b>", section_head)
        ]], colWidths=[523])
        sec2_header.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('LINELEFT', (0, 0), (0, -1), 2.5, colors.HexColor("#0284c7")),
        ]))
        story.append(sec2_header)
        story.append(Spacer(1, 3))

        d_name = dom_intel.get("domain") or (meta.get("from_address", "").split("@")[-1] if "@" in meta.get("from_address", "") else "N/A")
        if len(d_name) > 42: d_name = d_name[:39] + "..."
        d_reg = dom_intel.get("registrar") or "Not Disclosed / Privacy Protected"
        if len(d_reg) > 32: d_reg = d_reg[:29] + "..."
        d_age = dom_intel.get("domain_age_str") or "Active"
        d_created = dom_intel.get("registered_at") or "Unknown"
        if d_created != "Unknown": d_created = str(d_created)[:10]
        d_expires = dom_intel.get("expires_at") or "Not Disclosed"
        if d_expires != "Not Disclosed": d_expires = str(d_expires)[:10]

        mx_list = dom_intel.get("mx_servers") or []
        mx_str = ", ".join(mx_list) if mx_list else "Standard ESP / MX Relay"
        if len(mx_str) > 42: mx_str = mx_str[:39] + "..."

        ns_list = dom_intel.get("nameservers") or []
        ns_str = ", ".join(ns_list) if ns_list else "Cloudflare / Authoritative DNS"
        if len(ns_str) > 35: ns_str = ns_str[:32] + "..."

        d_type = dom_intel.get("domain_type") or "Custom Infrastructure"
        is_puny = dom_intel.get("is_punycode", False)
        puny_display = "<font color='#dc2626'><b>ALERT (LOOKALIKE / PUNYCODE)</b></font>" if is_puny else "<font color='#16a34a'><b>CLEAN (Standard ASCII Domain)</b></font>"

        dom_table_data = [
            [
                Paragraph("<b>Sender Domain:</b>", body_cell_bold), Paragraph(d_name, body_mono),
                Paragraph("<b>Registrar:</b>", body_cell_bold), Paragraph(d_reg, body_cell)
            ],
            [
                Paragraph("<b>Domain Age:</b>", body_cell_bold), Paragraph(f"<b>{d_age}</b> (Created: {d_created})", body_cell),
                Paragraph("<b>Expiry Date:</b>", body_cell_bold), Paragraph(d_expires, body_cell)
            ],
            [
                Paragraph("<b>Mail Servers (MX):</b>", body_cell_bold), Paragraph(mx_str, body_mono),
                Paragraph("<b>Nameservers:</b>", body_cell_bold), Paragraph(ns_str, body_mono)
            ],
            [
                Paragraph("<b>Domain Category:</b>", body_cell_bold), Paragraph(d_type, body_cell),
                Paragraph("<b>Typosquatting:</b>", body_cell_bold), Paragraph(puny_display, body_cell)
            ],
        ]
        dom_table = Table(dom_table_data, colWidths=[88, 195, 78, 162])
        dom_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 2.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(dom_table)
        story.append(Spacer(1, 6))

        # 6. Section 3: Sender Security & Authentication Checks
        sec3_header = Table([[
            Paragraph("<b>3. SENDER SECURITY & AUTHENTICATION (SPF, DKIM, DMARC)</b>", section_head)
        ]], colWidths=[523])
        sec3_header.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('LINELEFT', (0, 0), (0, -1), 2.5, colors.HexColor("#0284c7")),
        ]))
        story.append(sec3_header)
        story.append(Spacer(1, 3))

        ret_path = str(meta.get("return_path") or auth.get("return_path") or "N/A")
        if len(ret_path) > 55: ret_path = ret_path[:52] + "..."
        rep_to = str(meta.get("reply_to") or "N/A")
        if len(rep_to) > 55: rep_to = rep_to[:52] + "..."
        msg_id = str(meta.get("message_id") or "N/A")
        if len(msg_id) > 55: msg_id = msg_id[:52] + "..."

        auth_data_table = [
            [
                Paragraph("<b>SPF Status:</b>", body_cell_bold), Paragraph(f"<b>{auth.get('spf_result', 'NONE')}</b> (Sender authorized IP check)", body_cell),
                Paragraph("<b>Return-Path:</b>", body_cell_bold), Paragraph(ret_path, body_cell)
            ],
            [
                Paragraph("<b>DKIM Status:</b>", body_cell_bold), Paragraph(f"<b>{auth.get('dkim_result', 'NONE')}</b> (Cryptographic domain signature)", body_cell),
                Paragraph("<b>Reply-To:</b>", body_cell_bold), Paragraph(rep_to, body_cell)
            ],
            [
                Paragraph("<b>DMARC Status:</b>", body_cell_bold), Paragraph(f"<b>{auth.get('dmarc_result', 'NONE')}</b> (Domain protection policy)", body_cell),
                Paragraph("<b>Message-ID:</b>", body_cell_bold), Paragraph(msg_id, body_mono)
            ],
            [
                Paragraph("<b>Domain Match:</b>", body_cell_bold), Paragraph(f"<b>{auth.get('from_domain_alignment', 'NONE')}</b> (From header matches sender domain)", body_cell),
                Paragraph("<b>Server Trust:</b>", body_cell_bold), Paragraph("First external mail relay tested against threat feeds", body_cell)
            ],
        ]
        auth_table = Table(auth_data_table, colWidths=[78, 205, 78, 162])
        auth_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(auth_table)
        
        # Explicit Page Break to strictly enforce 2-Page limit
        story.append(PageBreak())

        # =========================================================================
        # PAGE 2: TECHNICAL FINDINGS, EMAIL DNA, IOC VERDICTS & SENDER NOTICE
        # =========================================================================
        
        # 1. Compact Page 2 Running Header
        p2_logo = None
        if os.path.exists(LOGO_PATH):
            try:
                p2_logo = PlatypusImage(LOGO_PATH, width=17, height=19)
            except Exception:
                p2_logo = Paragraph("🛡️", body_cell_bold)
        else:
            p2_logo = Paragraph("🛡️", body_cell_bold)

        p2_head_left = [
            Paragraph("<b>MailinTeL Forensic Report</b> | <i>Technical Details, DNA & Indicators</i>", body_cell_bold)
        ]
        p2_head_right = [
            Paragraph(f"<b>Subject:</b> {subj_str[:38]}... | <b>Page 2 of 2</b>", meta_right)
        ]
        p2_head_table = Table([[p2_logo, p2_head_left, p2_head_right]], colWidths=[22, 290, 211])
        p2_head_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 0),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
        ]))
        story.append(p2_head_table)
        
        p2_div = Drawing(523, 2)
        p2_div.add(Line(0, 1, 523, 1, strokeColor=colors.HexColor("#cbd5e1"), strokeWidth=0.75))
        story.append(p2_div)
        story.append(Spacer(1, 5))

        # 2. Section 4: Detailed Analysis Findings & Security Checks
        sec4_header = Table([[
            Paragraph("<b>4. DETAILED ANALYSIS FINDINGS & SECURITY CHECKS</b>", section_head)
        ]], colWidths=[523])
        sec4_header.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('LINELEFT', (0, 0), (0, -1), 2.5, colors.HexColor("#0284c7")),
        ]))
        story.append(sec4_header)
        story.append(Spacer(1, 3))

        findings = scores.get("findings", [])
        findings_rows = [
            [
                Paragraph("<b>Severity / Result</b>", body_cell_bold),
                Paragraph("<b>Check Category</b>", body_cell_bold),
                Paragraph("<b>Description & Finding Details</b>", body_cell_bold),
            ]
        ]
        
        disp_findings = findings[:4] if findings else []
        if not disp_findings:
            findings_rows.append([
                Paragraph("<font color='#16a34a'><b>SAFE / PASSED</b></font>", body_cell),
                Paragraph("Security Verification", body_cell),
                Paragraph("No dangerous indicators or security anomalies detected during analysis.", body_cell),
            ])
        else:
            for f in disp_findings:
                sev_raw = str(f.get("severity", "MEDIUM")).upper()
                if sev_raw in ("INFO", "PASS", "CLEAN"):
                    sev_html = "<font color='#16a34a'><b>SAFE / PASSED</b></font>"
                elif sev_raw == "LOW":
                    sev_html = "<font color='#10b981'><b>LOW RISK</b></font>"
                elif sev_raw == "MEDIUM":
                    sev_html = "<font color='#d97706'><b>MEDIUM RISK</b></font>"
                elif sev_raw == "HIGH":
                    sev_html = "<font color='#ef4444'><b>HIGH RISK</b></font>"
                elif sev_raw == "CRITICAL":
                    sev_html = "<font color='#dc2626'><b>CRITICAL THREAT</b></font>"
                else:
                    sev_html = f"<font color='#64748b'><b>{sev_raw}</b></font>"

                # Format check type in clear, professional words
                raw_ft = str(f.get("finding_type", "GENERAL")).upper().strip()
                cat_map = {
                    "AUTH_AUTHENTICATION_PASSED": "Email Authentication",
                    "AUTH_ALIGNMENT_PASSED": "Domain Alignment",
                    "THREAT_INTEL_MALICIOUS_IP": "Malicious Relay IP",
                    "THREAT_INTEL_MALICIOUS_URL": "Malicious URL Link",
                    "THREAT_INTEL_MALICIOUS_DOMAIN": "Malicious Domain",
                    "SPF_FAIL": "SPF Verification",
                    "DKIM_FAIL": "DKIM Verification",
                    "DMARC_FAIL": "DMARC Policy",
                    "SUSPICIOUS_CONTENT": "Content Analysis",
                    "LOOKALIKE_DOMAIN": "Domain Lookalike",
                    "DISPOSABLE_EMAIL": "Disposable Email",
                    "PHISHING_HEURISTIC": "Phishing Heuristic",
                    "SECURITY_CLEAN": "Security Clearance",
                }
                ft_display = cat_map.get(raw_ft, raw_ft.replace("_", " ").title()[:24])

                desc = str(f.get("description", "")).strip()
                if len(desc) > 130: desc = desc[:127] + "..."
                title_str = str(f.get("title", "Check Details")).strip()

                findings_rows.append([
                    Paragraph(sev_html, body_cell),
                    Paragraph(ft_display, body_cell_bold),
                    Paragraph(f"<b>{title_str}</b> — {desc}", body_cell),
                ])
        
        findings_table = Table(findings_rows, colWidths=[72, 115, 336])
        findings_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 2.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(findings_table)
        story.append(Spacer(1, 6))

        # 3. Section 5: Email DNA & System Traces
        sec5_header = Table([[
            Paragraph("<b>5. EMAIL DNA & SENDER SYSTEM TRACES</b>", section_head)
        ]], colWidths=[523])
        sec5_header.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('LINELEFT', (0, 0), (0, -1), 2.5, colors.HexColor("#0284c7")),
        ]))
        story.append(sec5_header)
        story.append(Spacer(1, 3))

        tech = dna.get("technical_fingerprint", {}) if dna else {}
        infra = dna.get("infrastructure_fingerprint", {}) if dna else {}
        dna_hash = dna.get("overall_dna_hash") or "N/A"
        header_hash = tech.get("header_order_hash") or "N/A"
        origin_ip = infra.get("originating_ip") or "N/A"
        x_mailer = tech.get("x_mailer") or "None / Removed"
        anonymized = f"TOR={infra.get('has_tor', False)} | VPN={infra.get('has_vpn', False)} | Cloud={infra.get('has_cloud', False)}"

        dna_data = [
            [
                Paragraph("<b>Header Order Hash:</b>", body_cell_bold), Paragraph(header_hash, body_mono),
                Paragraph("<b>Originating IP:</b>", body_cell_bold), Paragraph(str(origin_ip), body_mono)
            ],
            [
                Paragraph("<b>Overall DNA Hash:</b>", body_cell_bold), Paragraph(dna_hash, body_mono),
                Paragraph("<b>Mail Software:</b>", body_cell_bold), Paragraph(str(x_mailer)[:30], body_cell)
            ],
            [
                Paragraph("<b>Proxy / VPN Flags:</b>", body_cell_bold), Paragraph(anonymized, body_cell),
                Paragraph("<b>Network Path:</b>", body_cell_bold), Paragraph(str(infra.get("asn_sequence") or "N/A"), body_mono)
            ],
        ]
        dna_table = Table(dna_data, colWidths=[88, 195, 78, 162])
        dna_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 2.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(dna_table)
        story.append(Spacer(1, 6))

        # 4. Section 6: Suspicious Links & Flagged Items (IOCs)
        sec6_header = Table([[
            Paragraph("<b>6. SUSPICIOUS LINKS & FLAGGED ITEMS (IOCs)</b>", section_head)
        ]], colWidths=[523])
        sec6_header.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('LINELEFT', (0, 0), (0, -1), 2.5, colors.HexColor("#0284c7")),
        ]))
        story.append(sec6_header)
        story.append(Spacer(1, 3))

        raw_indicators = intel.get("threat_indicators", [])
        raw_urls = intel.get("urls", [])

        seen_ioc = set()
        ioc_rows = [
            [
                Paragraph("<b>Type</b>", body_cell_bold),
                Paragraph("<b>Found Item (URL / Domain / IP)</b>", body_cell_bold),
                Paragraph("<b>Source Feed</b>", body_cell_bold),
                Paragraph("<b>Safety Verdict</b>", body_cell_bold),
            ]
        ]

        def resolve_source_name(src: str, ctx_val: str = "") -> str:
            s = str(src or "").strip()
            if "Threat Intelligence" in s or "Threat Intel" in s:
                return "Threat Intel Feed"
            elif "VirusTotal" in s:
                return "VirusTotal Feed"
            elif "BODY" in s or "BODY" in str(ctx_val):
                return "Email Body Link"
            elif "REDIRECT" in s or "REDIRECT" in str(ctx_val):
                return "Redirect Link"
            elif "HEADER" in s or "HEADER" in str(ctx_val):
                return "Routing Header"
            elif not s or s == "Intel Feed":
                return "Reputation Feed"
            return s[:20]

        def resolve_verdict_html(raw_v: str) -> str:
            v = str(raw_v or "UNKNOWN").upper().strip()
            if v in ("BENIGN", "CLEAN", "SAFE"):
                return "<font color='#16a34a'><b>CLEAN / SAFE</b></font>"
            elif v in ("MALICIOUS", "CRITICAL"):
                return "<font color='#dc2626'><b>DANGEROUS</b></font>"
            elif v == "SUSPICIOUS":
                return "<font color='#d97706'><b>SUSPICIOUS</b></font>"
            elif v in ("EXTRACTED", "OBSERVED"):
                return "<font color='#475569'><b>FOUND IN EMAIL</b></font>"
            return f"<font color='#64748b'><b>{v}</b></font>"
        
        count = 0
        for ind in raw_indicators:
            val = ind.get("value", "")
            if val in seen_ioc: continue
            seen_ioc.add(val)
            val_disp = val if len(val) <= 50 else val[:47] + "..."
            feed_name = resolve_source_name(ind.get("source", "Threat Intel Feed"))
            verdict_html = resolve_verdict_html(ind.get("verdict", "UNKNOWN"))

            ioc_rows.append([
                Paragraph(ind.get("indicator_type", "IOC"), body_cell_bold),
                Paragraph(val_disp, body_mono),
                Paragraph(feed_name, body_cell),
                Paragraph(verdict_html, body_cell),
            ])
            count += 1
            if count >= 3: break

        for u in raw_urls:
            if count >= 4: break
            u_val = u.get("normalized_url", "")
            if u_val in seen_ioc: continue
            seen_ioc.add(u_val)
            u_disp = u_val if len(u_val) <= 50 else u_val[:47] + "..."
            feed_name = resolve_source_name("BODY_LINK", u.get("context", "BODY"))

            ioc_rows.append([
                Paragraph("URL", body_cell_bold),
                Paragraph(u_disp, body_mono),
                Paragraph(feed_name, body_cell),
                Paragraph("<font color='#475569'><b>FOUND IN EMAIL</b></font>", body_cell),
            ])
            count += 1

        if len(ioc_rows) == 1:
            ioc_rows.append([
                Paragraph("N/A", body_cell),
                Paragraph("No dangerous links or blacklisted indicators flagged.", body_cell),
                Paragraph("Internal Scan", body_cell),
                Paragraph("<font color='#16a34a'><b>CLEAN / SAFE</b></font>", body_cell),
            ])

        ioc_table = Table(ioc_rows, colWidths=[48, 285, 105, 85])
        ioc_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f8fafc")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 2.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(ioc_table)
        story.append(Spacer(1, 6))

        # 5. Section 7: Server Network & Campaign Connections
        sec7_header = Table([[
            Paragraph("<b>7. SERVER NETWORK & CAMPAIGN CONNECTIONS</b>", section_head)
        ]], colWidths=[523])
        sec7_header.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('LINELEFT', (0, 0), (0, -1), 2.5, colors.HexColor("#0284c7")),
        ]))
        story.append(sec7_header)
        story.append(Spacer(1, 3))

        camps = sim.get("campaigns", [])
        locs = geo.get("locations", [])
        
        camp_desc = "No linked phishing campaign found."
        if camps:
            c = camps[0]
            camp_desc = f"Campaign: <b>{c.get('name', 'N/A')}</b> (Status: {c.get('status')}, Confidence: {c.get('confidence_score', 0):.0f}%)"

        geo_desc = "No external relay server coordinates found."
        if locs:
            l = locs[0]
            geo_desc = f"Relay Server: <b>{l.get('ip_address')}</b> ({l.get('country', 'Unknown')}, {l.get('city') or 'N/A'}) | Network: {l.get('asn') or 'N/A'} - {l.get('isp') or 'N/A'}"

        routing_data = [
            [Paragraph("<b>Linked Campaign:</b>", body_cell_bold), Paragraph(camp_desc, body_cell)],
            [Paragraph("<b>Relay Server:</b>", body_cell_bold), Paragraph(geo_desc, body_cell)],
        ]
        routing_table = Table(routing_data, colWidths=[88, 435])
        routing_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor("#ffffff"), colors.HexColor("#f8fafc")]),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(routing_table)
        story.append(Spacer(1, 6))

        # 6. Section 8: Important Notice & Sender Location Disclaimer (Simple, Professional English)
        disclaimer_content = [
            Paragraph(
                "<b>IMPORTANT NOTICE & SENDER LOCATION DISCLAIMER:</b><br/>"
                "This report is generated automatically from email headers, security checks, and threat databases. "
                "The server locations, IP addresses, and network paths listed above indicate the mail servers that processed "
                "or forwarded the message—<b>they do NOT prove the real-world identity or physical location of the human sender</b>. "
                "All scores and findings are decision-support signals to help human security teams investigate.",
                disclaimer_style
            ),
            Spacer(1, 2),
            Paragraph(
                "• <b>Network Path:</b> Early email routing hops can be faked or spoofed before reaching trusted mail servers.<br/>"
                "• <b>Physical Location:</b> Data center and server coordinates belong to the hosting provider, not necessarily the attacker.",
                disclaimer_style
            )
        ]
        disclaimer_table = Table([[disclaimer_content]], colWidths=[523])
        disclaimer_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#fef2f2")),
            ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor("#ef4444")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(disclaimer_table)
        return story

    @classmethod
    def render_pdf_report(cls, data: Dict[str, Any]) -> bytes:
        """
        Builds and renders the official A4 forensic email threat intelligence report.
        Returns raw PDF bytes.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36,
        )
        story = cls.build_email_story(data)
        doc.build(story, canvasmaker=ForensicNumberedCanvas)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

    @classmethod
    def render_multi_email_pdf_report(cls, reports: List[Dict[str, Any]]) -> bytes:
        """
        Builds a consolidated multi-case forensic dossier containing an executive summary
        table followed by each individual email's detailed forensic analysis report.
        Returns raw PDF bytes.
        """
        if not reports:
            return b""
        if len(reports) == 1:
            return cls.render_pdf_report(reports[0])

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36,
        )
        styles = getSampleStyleSheet()
        doc_title_style = ParagraphStyle(
            'BatchTitle', parent=styles['Normal'],
            fontName='Helvetica-Bold', fontSize=15, leading=18, textColor=colors.HexColor('#0f172a')
        )
        doc_sub_style = ParagraphStyle(
            'BatchSub', parent=styles['Normal'],
            fontName='Helvetica-Bold', fontSize=7.5, leading=10, textColor=colors.HexColor('#0284c7')
        )
        table_hdr = ParagraphStyle(
            'BatchTblHdr', parent=styles['Normal'],
            fontName='Helvetica-Bold', fontSize=7, leading=9, textColor=colors.HexColor('#1e293b')
        )
        table_cell = ParagraphStyle(
            'BatchTblCell', parent=styles['Normal'],
            fontName='Helvetica', fontSize=6.5, leading=8.5, textColor=colors.HexColor('#1e293b')
        )
        table_mono = ParagraphStyle(
            'BatchTblMono', parent=styles['Normal'],
            fontName='Courier', fontSize=6.5, leading=8.5, textColor=colors.HexColor('#0f172a')
        )

        full_story: List[Any] = []

        # Executive Summary Cover Sheet
        full_story.append(Paragraph("<b>MailinTeL</b> &bull; Consolidated Forensic Investigation Dossier", doc_title_style))
        full_story.append(Spacer(1, 2))
        full_story.append(Paragraph(
            f"BATCH FORENSIC REPORT &bull; <b>{len(reports)} Cases Preserved</b> &bull; ISO/IEC 27037 Tamper-Evident Custody Chain",
            doc_sub_style
        ))
        full_story.append(Spacer(1, 6))

        # Metrics chips
        mal_count = sum(1 for r in reports if (r.get("explainable_scores", {}).get("threat_risk_score", 0) >= 65))
        susp_count = sum(1 for r in reports if (35 <= r.get("explainable_scores", {}).get("threat_risk_score", 0) < 65))
        safe_count = len(reports) - mal_count - susp_count

        metrics_data = [
            [
                Paragraph(f"<b>Total Cases:</b> {len(reports)}", table_hdr),
                Paragraph(f"<font color='#dc2626'><b>Phishing/Malicious:</b> {mal_count}</font>", table_hdr),
                Paragraph(f"<font color='#d97706'><b>Suspicious:</b> {susp_count}</font>", table_hdr),
                Paragraph(f"<font color='#16a34a'><b>Legitimate/Clean:</b> {safe_count}</font>", table_hdr),
            ]
        ]
        t_metrics = Table(metrics_data, colWidths=[120, 140, 130, 133])
        t_metrics.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
            ('BOX', (0,0), (-1,-1), 0.75, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6),
        ]))
        full_story.append(t_metrics)
        full_story.append(Spacer(1, 8))

        # Table of cases
        case_rows = [
            [
                Paragraph("<b>#</b>", table_hdr),
                Paragraph("<b>Subject / Title</b>", table_hdr),
                Paragraph("<b>Sender Address</b>", table_hdr),
                Paragraph("<b>Date Header</b>", table_hdr),
                Paragraph("<b>Verdict</b>", table_hdr),
                Paragraph("<b>Score</b>", table_hdr),
                Paragraph("<b>SHA-256 Custody Seal</b>", table_hdr),
            ]
        ]
        for idx, r in enumerate(reports, 1):
            m = r.get("email_metadata", {})
            sc = r.get("explainable_scores", {})
            score = float(sc.get("threat_risk_score") or 0.0)
            c = '#dc2626' if score >= 65 else ('#d97706' if score >= 35 else '#16a34a')
            v_name = sc.get("threat_classification") or ("MALICIOUS" if score >= 65 else ("SUSPICIOUS" if score >= 35 else "LEGITIMATE"))
            
            case_rows.append([
                Paragraph(str(idx), table_cell),
                Paragraph(str(m.get("subject") or "Untitled")[:38], table_cell),
                Paragraph(str(m.get("from_address") or "Unknown")[:30], table_cell),
                Paragraph(str(m.get("date_header") or "N/A")[:16], table_cell),
                Paragraph(f"<font color='{c}'><b>{v_name}</b></font>", table_cell),
                Paragraph(f"{score:.0f}/100", table_cell),
                Paragraph(str(m.get("sha256_hash") or "N/A")[:16] + "...", table_mono),
            ])

        t_cases = Table(case_rows, colWidths=[20, 145, 125, 75, 55, 38, 65])
        t_cases.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#ffffff'), colors.HexColor('#f8fafc')]),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
            ('LEFTPADDING', (0,0), (-1,-1), 3),
            ('RIGHTPADDING', (0,0), (-1,-1), 3),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        full_story.append(t_cases)
        full_story.append(PageBreak())

        # For each email case, append its full dossier
        for idx, r in enumerate(reports):
            if idx > 0:
                full_story.append(PageBreak())
            full_story.extend(cls.build_email_story(r))

        doc.build(full_story, canvasmaker=ForensicNumberedCanvas)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes
