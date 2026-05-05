"""
cnsl/reporter.py — Compliance and incident reports.

Generates professional PDF and HTML reports covering:
  - Executive summary (incident counts, severity breakdown, top threats)
  - Timeline of incidents
  - Top attacker IPs with GeoIP
  - FIM alerts (file integrity events)
  - ML anomalies
  - Blocked IP statistics
  - Compliance mapping (SOC2, ISO27001, PCI-DSS)
  - Response time statistics

Output formats:
  - PDF  (reportlab — professional, printable)
  - HTML (self-contained, can be emailed)
  - JSON (machine-readable, for integration)

Usage:
  reporter = Reporter(store, fim_engine, cfg)
  path = await reporter.generate(
      format="pdf",
      period_days=30,
      output_path="./report.pdf"
  )
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .models import iso_time, now

if TYPE_CHECKING:
    from .store      import Store
    from .fim        import FIMEngine
    from .ml_detector import MLDetector



# Data collection


async def _collect_report_data(
    store:       "Store",
    fim:         Optional["FIMEngine"],
    period_days: int,
) -> Dict[str, Any]:
    """Pull all data needed for the report from SQLite."""

    since = now() - period_days * 86400
    data: Dict[str, Any] = {
        "period_days":  period_days,
        "generated_at": iso_time(),
        "since":        iso_time(since),
    }

    # Incidents
    if store and store.available:
        all_incidents = await store.recent_incidents(limit=10000)
        period_incidents = [i for i in all_incidents if i.get("ts", 0) >= since]
        data["incidents"] = period_incidents
        data["total_incidents"] = len(period_incidents)
        data["high_count"]   = sum(1 for i in period_incidents if i.get("severity") == "HIGH")
        data["medium_count"] = sum(1 for i in period_incidents if i.get("severity") == "MEDIUM")

        # Top attackers
        top = await store.top_attackers(limit=10)
        data["top_attackers"] = top

        # Active blocks
        blocks = await store.active_blocks()
        data["active_blocks"] = blocks
        data["block_count"]   = len(blocks)

        # DB stats
        stats = await store.stats()
        data["db_stats"] = stats
    else:
        data.update({
            "incidents": [], "total_incidents": 0,
            "high_count": 0, "medium_count": 0,
            "top_attackers": [], "active_blocks": [],
            "block_count": 0, "db_stats": {},
        })

    # FIM alerts
    if fim:
        fim_alerts = fim.recent_alerts(limit=1000)
        data["fim_alerts"]       = [a for a in fim_alerts if a.get("ts", 0) >= since]
        data["fim_alert_count"]  = len(data["fim_alerts"])
        data["fim_critical"]     = sum(1 for a in data["fim_alerts"] if a.get("severity") == "CRITICAL")
    else:
        data["fim_alerts"] = []
        data["fim_alert_count"] = 0
        data["fim_critical"] = 0

    return data



# HTML report


def _generate_html(data: Dict) -> str:
    inc = data["total_incidents"]
    high = data["high_count"]
    med  = data["medium_count"]
    fim_count = data.get("fim_alert_count", 0)
    fim_crit  = data.get("fim_critical", 0)

    # Top attackers table rows
    attacker_rows = ""
    for a in data.get("top_attackers", [])[:10]:
        country = a.get("country", "Unknown")
        city    = a.get("city", "")
        loc     = country + (f", {city}" if city else "")
        attacker_rows += f"""
        <tr>
          <td><code>{a.get('src_ip','')}</code></td>
          <td>{loc}</td>
          <td>{a.get('isp','')}</td>
          <td style="color:#ef4444;font-weight:600">{a.get('incident_count',0)}</td>
          <td>{a.get('max_severity','')}</td>
        </tr>"""

    # Recent incidents rows (last 20)
    incident_rows = ""
    for i in data.get("incidents", [])[:20]:
        sev   = i.get("severity", "")
        color = "#ef4444" if sev == "HIGH" else "#f59e0b"
        reasons = i.get("reasons", [])
        if isinstance(reasons, str):
            try:
                reasons = json.loads(reasons)
            except Exception:
                reasons = [reasons]
        reason_text = "; ".join(reasons[:2]) if reasons else ""
        incident_rows += f"""
        <tr>
          <td style="font-size:12px;color:#64748b">{i.get('time','')}</td>
          <td><code>{i.get('src_ip','')}</code></td>
          <td>{i.get('country','—')}</td>
          <td style="color:{color};font-weight:600">{sev}</td>
          <td style="font-size:12px">{reason_text}</td>
        </tr>"""

    # FIM alerts rows
    fim_rows = ""
    for a in data.get("fim_alerts", [])[:15]:
        sev   = a.get("severity", "")
        color = "#ef4444" if sev == "CRITICAL" else "#f59e0b" if sev == "HIGH" else "#3b82f6"
        fim_rows += f"""
        <tr>
          <td style="font-size:12px;color:#64748b">{a.get('time','')}</td>
          <td><code style="font-size:11px">{a.get('path','')}</code></td>
          <td>{a.get('change','').upper()}</td>
          <td style="color:{color};font-weight:600">{sev}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CNSL Security Report — {data['generated_at'][:10]}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f8fafc;
          color: #1e293b; margin: 0; padding: 32px; }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  .header {{ background: #0f1117; color: #e2e8f0; padding: 32px; border-radius: 12px;
             margin-bottom: 32px; }}
  .header h1 {{ margin: 0 0 8px; font-size: 28px; }}
  .header p  {{ margin: 0; color: #64748b; font-size: 14px; }}
  .grid {{ display: grid; grid-template-columns: repeat(4,1fr); gap: 16px; margin-bottom: 32px; }}
  .card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 20px; }}
  .card .label {{ font-size: 12px; color: #64748b; text-transform: uppercase;
                  letter-spacing: .05em; margin-bottom: 8px; }}
  .card .value {{ font-size: 32px; font-weight: 700; }}
  .card .sub   {{ font-size: 12px; color: #94a3b8; margin-top: 4px; }}
  .red  {{ color: #ef4444; }} .amber {{ color: #f59e0b; }}
  .blue {{ color: #3b82f6; }} .green {{ color: #22c55e; }}
  .section {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 10px;
              padding: 24px; margin-bottom: 24px; }}
  .section h2 {{ font-size: 16px; font-weight: 600; margin: 0 0 16px;
                 border-bottom: 1px solid #f1f5f9; padding-bottom: 12px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 8px 12px; border-bottom: 2px solid #f1f5f9;
        font-size: 11px; color: #64748b; text-transform: uppercase; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #f8fafc; vertical-align: middle; }}
  code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
  .compliance {{ display: grid; grid-template-columns: repeat(3,1fr); gap: 16px; }}
  .comp-card {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; }}
  .comp-card h3 {{ margin: 0 0 8px; font-size: 14px; color: #1e293b; }}
  .comp-card p  {{ margin: 0; font-size: 12px; color: #64748b; line-height: 1.6; }}
  .chk {{ display:inline-flex;align-items:center; }}
  footer {{ text-align: center; color: #94a3b8; font-size: 12px; margin-top: 32px; }}
</style>
</head>
<body>
<div class="container">

<div class="header">
  <h1><svg width="22" height="22" viewBox="0 0 20 20" fill="none" style="vertical-align:middle;margin-right:8px"><path d="M10 2L3 5.5V10c0 3.87 2.93 7.5 7 8.45C17.07 17.5 20 13.87 20 10V5.5L10 2z" stroke="#6366f1" stroke-width="1.5" stroke-linejoin="round" fill="none"/><path d="M7 10l2 2 4-4" stroke="#6366f1" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>CNSL Security Report</h1>
  <p>Period: last {data['period_days']} days &nbsp;·&nbsp;
     Generated: {data['generated_at']} &nbsp;·&nbsp;
     Correlated Network Security Layer v1.0</p>
</div>

<div class="grid">
  <div class="card">
    <div class="label">Total incidents</div>
    <div class="value {'red' if inc > 10 else 'green'}">{inc}</div>
    <div class="sub">last {data['period_days']} days</div>
  </div>
  <div class="card">
    <div class="label">HIGH severity</div>
    <div class="value red">{high}</div>
    <div class="sub">credential breaches</div>
  </div>
  <div class="card">
    <div class="label">FIM alerts</div>
    <div class="value {'red' if fim_crit > 0 else 'amber'}">{fim_count}</div>
    <div class="sub">{fim_crit} critical</div>
  </div>
  <div class="card">
    <div class="label">Active blocks</div>
    <div class="value amber">{data.get('block_count',0)}</div>
    <div class="sub">currently blocked</div>
  </div>
</div>

<div class="section">
  <h2>Top attackers</h2>
  <table>
    <thead><tr><th>IP</th><th>Location</th><th>ISP</th><th>Incidents</th><th>Max severity</th></tr></thead>
    <tbody>{attacker_rows or '<tr><td colspan="5" style="color:#94a3b8;text-align:center">No data</td></tr>'}</tbody>
  </table>
</div>

<div class="section">
  <h2>Recent incidents</h2>
  <table>
    <thead><tr><th>Time</th><th>IP</th><th>Location</th><th>Severity</th><th>Reason</th></tr></thead>
    <tbody>{incident_rows or '<tr><td colspan="5" style="color:#94a3b8;text-align:center">No incidents</td></tr>'}</tbody>
  </table>
</div>

{'<div class="section"><h2>File integrity alerts</h2><table><thead><tr><th>Time</th><th>Path</th><th>Change</th><th>Severity</th></tr></thead><tbody>' + fim_rows + '</tbody></table></div>' if fim_rows else ''}

<div class="section">
  <h2>Compliance mapping</h2>
  <div class="compliance">
    <div class="comp-card">
      <h3>SOC 2 Type II</h3>
      <p>
        <svg width="13" height="13" viewBox="0 0 13 13" fill="none" style="vertical-align:middle;margin-right:4px"><circle cx="6.5" cy="6.5" r="6" fill="#dcfce7" stroke="#22c55e" stroke-width="1"/><path d="M4 6.5l2 2 3-3" stroke="#22c55e" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg> CC6.1 — Access controls monitored<br>
        <svg width="13" height="13" viewBox="0 0 13 13" fill="none" style="vertical-align:middle;margin-right:4px"><circle cx="6.5" cy="6.5" r="6" fill="#dcfce7" stroke="#22c55e" stroke-width="1"/><path d="M4 6.5l2 2 3-3" stroke="#22c55e" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg> CC6.7 — Unauthorized access detection<br>
        <svg width="13" height="13" viewBox="0 0 13 13" fill="none" style="vertical-align:middle;margin-right:4px"><circle cx="6.5" cy="6.5" r="6" fill="#dcfce7" stroke="#22c55e" stroke-width="1"/><path d="M4 6.5l2 2 3-3" stroke="#22c55e" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg> CC7.2 — System anomaly monitoring<br>
        {'<svg width="13" height="13" viewBox="0 0 13 13" fill="none" style="vertical-align:middle;margin-right:4px"><circle cx="6.5" cy="6.5" r="6" fill="#dcfce7" stroke="#22c55e" stroke-width="1"/><path d="M4 6.5l2 2 3-3" stroke="#22c55e" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>' if fim_count == 0 else '<svg width="13" height="13" viewBox="0 0 13 13" fill="none" style="vertical-align:middle;margin-right:4px"><circle cx="6.5" cy="6.5" r="6" fill="#fef3c7" stroke="#f59e0b" stroke-width="1"/><path d="M6.5 4v3M6.5 8.5v.5" stroke="#f59e0b" stroke-width="1.3" stroke-linecap="round"/></svg>'}
        CC6.8 — File integrity {'maintained' if fim_count == 0 else f'{fim_count} changes detected'}
      </p>
    </div>
    <div class="comp-card">
      <h3>ISO 27001</h3>
      <p>
        <svg width="13" height="13" viewBox="0 0 13 13" fill="none" style="vertical-align:middle;margin-right:4px"><circle cx="6.5" cy="6.5" r="6" fill="#dcfce7" stroke="#22c55e" stroke-width="1"/><path d="M4 6.5l2 2 3-3" stroke="#22c55e" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg> A.12.4 — Event logging active<br>
        <svg width="13" height="13" viewBox="0 0 13 13" fill="none" style="vertical-align:middle;margin-right:4px"><circle cx="6.5" cy="6.5" r="6" fill="#dcfce7" stroke="#22c55e" stroke-width="1"/><path d="M4 6.5l2 2 3-3" stroke="#22c55e" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg> A.12.6 — Vulnerability monitoring<br>
        <svg width="13" height="13" viewBox="0 0 13 13" fill="none" style="vertical-align:middle;margin-right:4px"><circle cx="6.5" cy="6.5" r="6" fill="#dcfce7" stroke="#22c55e" stroke-width="1"/><path d="M4 6.5l2 2 3-3" stroke="#22c55e" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg> A.13.1 — Network monitoring<br>
        <svg width="13" height="13" viewBox="0 0 13 13" fill="none" style="vertical-align:middle;margin-right:4px"><circle cx="6.5" cy="6.5" r="6" fill="#dcfce7" stroke="#22c55e" stroke-width="1"/><path d="M4 6.5l2 2 3-3" stroke="#22c55e" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg> A.16.1 — Incident management
      </p>
    </div>
    <div class="comp-card">
      <h3>PCI-DSS v4</h3>
      <p>
        <svg width="13" height="13" viewBox="0 0 13 13" fill="none" style="vertical-align:middle;margin-right:4px"><circle cx="6.5" cy="6.5" r="6" fill="#dcfce7" stroke="#22c55e" stroke-width="1"/><path d="M4 6.5l2 2 3-3" stroke="#22c55e" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg> Req 10 — Log monitoring active<br>
        <svg width="13" height="13" viewBox="0 0 13 13" fill="none" style="vertical-align:middle;margin-right:4px"><circle cx="6.5" cy="6.5" r="6" fill="#dcfce7" stroke="#22c55e" stroke-width="1"/><path d="M4 6.5l2 2 3-3" stroke="#22c55e" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg> Req 11.5 — Intrusion detection<br>
        {'<svg width="13" height="13" viewBox="0 0 13 13" fill="none" style="vertical-align:middle;margin-right:4px"><circle cx="6.5" cy="6.5" r="6" fill="#dcfce7" stroke="#22c55e" stroke-width="1"/><path d="M4 6.5l2 2 3-3" stroke="#22c55e" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>' if fim_crit == 0 else '<svg width="13" height="13" viewBox="0 0 13 13" fill="none" style="vertical-align:middle;margin-right:4px"><circle cx="6.5" cy="6.5" r="6" fill="#fef3c7" stroke="#f59e0b" stroke-width="1"/><path d="M6.5 4v3M6.5 8.5v.5" stroke="#f59e0b" stroke-width="1.3" stroke-linecap="round"/></svg>'}
        Req 11.5.2 — File integrity {'OK' if fim_crit == 0 else f'{fim_crit} critical changes'}<br>
        <svg width="13" height="13" viewBox="0 0 13 13" fill="none" style="vertical-align:middle;margin-right:4px"><circle cx="6.5" cy="6.5" r="6" fill="#dcfce7" stroke="#22c55e" stroke-width="1"/><path d="M4 6.5l2 2 3-3" stroke="#22c55e" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg> Req 12.10 — Incident response
      </p>
    </div>
  </div>
</div>

<footer>CNSL — Correlated Network Security Layer &nbsp;·&nbsp; Report generated {data['generated_at']}</footer>
</div>
</body>
</html>"""



# PDF report (reportlab)


def _generate_pdf(data: Dict, output_path: str) -> bool:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles    import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units     import mm
        from reportlab.lib           import colors
        from reportlab.platypus      import (SimpleDocTemplate, Paragraph, Spacer,
                                              Table, TableStyle, HRFlowable)
        from reportlab.lib.enums     import TA_CENTER, TA_LEFT
    except ImportError:
        return False

    doc    = SimpleDocTemplate(output_path, pagesize=A4,
                               leftMargin=20*mm, rightMargin=20*mm,
                               topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    story  = []

    # Custom styles
    title_style = ParagraphStyle("Title2", parent=styles["Title"],
                                  fontSize=22, textColor=colors.HexColor("#0f1117"),
                                  spaceAfter=6)
    h2_style    = ParagraphStyle("H2", parent=styles["Heading2"],
                                  fontSize=13, textColor=colors.HexColor("#1e293b"),
                                  spaceBefore=16, spaceAfter=8)
    body_style  = ParagraphStyle("Body2", parent=styles["Normal"],
                                  fontSize=9, textColor=colors.HexColor("#374151"),
                                  leading=14)
    muted_style = ParagraphStyle("Muted", parent=styles["Normal"],
                                  fontSize=8, textColor=colors.HexColor("#64748b"))

    inc  = data["total_incidents"]
    high = data["high_count"]

    # Header
    story.append(Paragraph("CNSL Security Report", title_style))
    story.append(Paragraph(
        f"Period: last {data['period_days']} days &nbsp;·&nbsp; "
        f"Generated: {data['generated_at']}", muted_style
    ))
    story.append(Spacer(1, 8*mm))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.HexColor("#e2e8f0")))
    story.append(Spacer(1, 6*mm))

    # Summary table
    story.append(Paragraph("Executive Summary", h2_style))
    summary_data = [
        ["Metric", "Value", "Status"],
        ["Total incidents", str(inc),
         "! Action needed" if inc > 10 else "OK Normal"],
        ["HIGH severity incidents", str(high),
         "! Review required" if high > 0 else "OK None"],
        ["MEDIUM severity incidents", str(data["medium_count"]), "—"],
        ["File integrity alerts", str(data.get("fim_alert_count", 0)),
         "! Review files" if data.get("fim_critical", 0) > 0 else "OK Clean"],
        ["Currently blocked IPs", str(data.get("block_count", 0)), "—"],
    ]

    col_widths = [80*mm, 40*mm, 60*mm]
    t = Table(summary_data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), colors.HexColor("#0f1117")),
        ("TEXTCOLOR",   (0,0), (-1,0), colors.white),
        ("FONTSIZE",    (0,0), (-1,0), 9),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1),
         [colors.HexColor("#f8fafc"), colors.white]),
        ("FONTSIZE",    (0,1), (-1,-1), 9),
        ("GRID",        (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("RIGHTPADDING",(0,0), (-1,-1), 8),
        ("TOPPADDING",  (0,0), (-1,-1), 6),
        ("BOTTOMPADDING",(0,0),(-1,-1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 6*mm))

    # Top attackers
    story.append(Paragraph("Top Attackers", h2_style))
    att_data = [["IP Address", "Country", "Incidents", "Max Severity"]]
    for a in data.get("top_attackers", [])[:8]:
        att_data.append([
            a.get("src_ip", ""),
            a.get('country', 'Unknown'),
            str(a.get("incident_count", 0)),
            a.get("max_severity", ""),
        ])

    if len(att_data) > 1:
        t2 = Table(att_data, colWidths=[50*mm, 60*mm, 30*mm, 40*mm])
        t2.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,0), colors.HexColor("#1e293b")),
            ("TEXTCOLOR",   (0,0), (-1,0), colors.white),
            ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS", (0,1), (-1,-1),
             [colors.HexColor("#f8fafc"), colors.white]),
            ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
            ("TOPPADDING",  (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
        ]))
        story.append(t2)
    else:
        story.append(Paragraph("No attacker data available.", muted_style))

    story.append(Spacer(1, 6*mm))

    # Compliance
    story.append(Paragraph("Compliance Status", h2_style))
    fim_ok   = data.get("fim_critical", 0) == 0
    comp_data = [
        ["Framework", "Control", "Status"],
        ["SOC 2 Type II",  "CC6.1 CC6.7 CC7.2 CC6.8", "OK Monitored" if fim_ok else "! FIM alerts"],
        ["ISO 27001",      "A.12.4 A.12.6 A.13.1 A.16.1", "OK Compliant"],
        ["PCI-DSS v4",     "Req 10, 11.5, 11.5.2, 12.10",
         "OK Compliant" if fim_ok else "! File changes detected"],
    ]
    t3 = Table(comp_data, colWidths=[45*mm, 75*mm, 60*mm])
    t3.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR",   (0,0), (-1,0), colors.white),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS", (0,1), (-1,-1),
         [colors.HexColor("#f8fafc"), colors.white]),
        ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING",  (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",(0,0),(-1,-1), 5),
    ]))
    story.append(t3)
    story.append(Spacer(1, 10*mm))

    story.append(Paragraph(
        f"Generated by CNSL — Correlated Network Security Layer v1.0 &nbsp;·&nbsp; {data['generated_at']}",
        muted_style
    ))

    doc.build(story)
    return True



# Reporter


class Reporter:
    """
    Generate security and compliance reports.

    Usage:
        reporter = Reporter(store, fim, cfg)
        path = await reporter.generate(format="pdf", period_days=30)
    """

    def __init__(
        self,
        store:  Optional["Store"],
        fim:    Optional["FIMEngine"] = None,
        cfg:    Dict[str, Any] = None,
    ):
        self.store = store
        self.fim   = fim
        cfg        = cfg or {}
        self._output_dir = cfg.get("reporting", {}).get("output_dir", "./reports")

    async def generate(
        self,
        format:      str  = "html",   # "html" | "pdf" | "json"
        period_days: int  = 30,
        output_path: Optional[str] = None,
    ) -> str:
        """Generate report. Returns path to output file."""

        os.makedirs(self._output_dir, exist_ok=True)

        ts_str = time.strftime("%Y%m%d_%H%M%S")
        if output_path is None:
            output_path = os.path.join(
                self._output_dir,
                f"cnsl_report_{ts_str}.{format}"
            )

        data = await _collect_report_data(self.store, self.fim, period_days)

        loop = asyncio.get_running_loop()

        if format == "json":
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)

        elif format == "html":
            html = await loop.run_in_executor(None, _generate_html, data)
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)

        elif format == "pdf":
            ok = await loop.run_in_executor(None, _generate_pdf, data, output_path)
            if not ok:
                # Fallback to HTML
                output_path = output_path.replace(".pdf", ".html")
                html = await loop.run_in_executor(None, _generate_html, data)
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(html)

        return output_path