"""
cnsl/notify.py — Multi-channel alert notifications.

Supported channels:
  - Telegram Bot
  - Discord Webhook
  - Slack Webhook
  - Generic HTTP webhook (POST JSON)
  - Email (SMTP / STARTTLS / SSL)

Configure in config.json under "notifications": { ... }
All channels are optional and independent — failure in one
does not affect others.
"""

from __future__ import annotations

import asyncio
import json
import smtplib
import ssl
import time
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict, List, Optional

from .models import Detection, iso_time


# Notification payload builder


def _tg_escape(text: str) -> str:
    """Escape special characters for Telegram Markdown v1.
    Markdown v1 only uses: *bold*, _italic_, `code`, [text](url).
    Unmatched * or _ in dynamic content (ISP names, city names) will break rendering.
    """
    return text.replace("_", "\\_").replace("*", "\\*").replace("`", "\\`").replace("[", "\\[")


def _build_message(detection: Detection, geo: Optional[Dict] = None) -> str:
    """Build a human-readable alert message."""
    sev_label = {"HIGH": "[HIGH]", "MEDIUM": "[MEDIUM]", "LOW": "[LOW]"}.get(detection.severity, "[ALERT]")
    country = _tg_escape(geo.get("country", "Unknown") if geo else "Unknown")
    city    = _tg_escape(geo.get("city", "") if geo else "")
    isp     = _tg_escape(geo.get("isp", "") if geo else "")
    proxy   = " [PROXY/VPN]" if geo and geo.get("proxy") else ""
    hosting = " [DATACENTER]" if geo and geo.get("hosting") else ""

    location = country
    if city:
        location += f", {city}"

    lines = [
        f"*CNSL ALERT — {detection.severity}*",
        f"",
        f"IP:       `{detection.src_ip}`{proxy}{hosting}",
        f"Location: {location}",
        f"ISP:      {isp}" if isp else "",
        f"",
        f"Stats:",
        f"  Fails:        {detection.fail_count} (window: {detection.window_sec}s)",
        f"  Unique users: {detection.uniq_users}",
        f"",
        f"Reasons:",
    ]
    for r in detection.reasons:
        lines.append(f"  - {_tg_escape(r)}")
    lines.extend([
        f"",
        f"Time: {iso_time()}",
    ])
    return "\n".join(l for l in lines if l is not None)



# Notifier


class Notifier:
    """
    Sends alerts to configured channels.

    Config example:
      "notifications": {
        "telegram": {
          "enabled": true,
          "bot_token": "123456:ABC...",
          "chat_id": "-1001234567890"
        },
        "discord": {
          "enabled": true,
          "webhook_url": "https://discord.com/api/webhooks/..."
        },
        "slack": {
          "enabled": true,
          "webhook_url": "https://hooks.slack.com/services/..."
        },
        "webhook": {
          "enabled": true,
          "url": "https://your-server.com/cnsl-hook",
          "secret_header": "X-CNSL-Secret",
          "secret_value": "mysecret"
        },
        "min_severity": "MEDIUM"
      }
    """

    def __init__(self, cfg: Dict[str, Any]):
        self._cfg = cfg.get("notifications", {})
        self._min_sev = self._cfg.get("min_severity", "MEDIUM")
        self._sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
        # Alert deduplication: (ip, kind) -> last sent timestamp
        self._dedup_window = int(self._cfg.get("dedup_window_sec", 300))  # 5 min default
        self._last_sent: Dict[tuple, float] = {}
        # Daily digest buffer
        self._digest_buffer: List[Detection] = []
        self._digest_task: Optional[asyncio.Task] = None

    def start(self) -> None:
        """Start background daily digest task."""
        digest_cfg = self._cfg.get("daily_digest", {})
        if digest_cfg.get("enabled"):
            self._digest_task = asyncio.ensure_future(self._digest_loop())

    def stop(self) -> None:
        if self._digest_task:
            self._digest_task.cancel()

    async def send(self, detection: Detection, geo: Optional[Dict] = None) -> None:
        """Send alert to all enabled channels (fire-and-forget, errors swallowed)."""
        if self._sev_order.get(detection.severity, 0) < self._sev_order.get(self._min_sev, 1):
            return

        # Deduplication check
        if self._dedup_window > 0:
            dedup_key = (detection.src_ip, detection.severity)
            last = self._last_sent.get(dedup_key, 0)
            if time.time() - last < self._dedup_window:
                # Buffer for digest even if deduped
                self._digest_buffer.append(detection)
                return
            self._last_sent[dedup_key] = time.time()

        # Buffer for daily digest
        self._digest_buffer.append(detection)

        msg = _build_message(detection, geo)
        tasks = []

        tg = self._cfg.get("telegram", {})
        if tg.get("enabled"):
            tasks.append(self._send_telegram(tg["bot_token"], tg["chat_id"], msg))

        dc = self._cfg.get("discord", {})
        if dc.get("enabled"):
            tasks.append(self._send_discord(dc["webhook_url"], detection, geo, msg))

        sl = self._cfg.get("slack", {})
        if sl.get("enabled"):
            tasks.append(self._send_slack(sl["webhook_url"], msg))

        wh = self._cfg.get("webhook", {})
        if wh.get("enabled"):
            tasks.append(self._send_webhook(wh, detection, geo))

        em = self._cfg.get("email", {})
        if em.get("enabled"):
            tasks.append(self._send_email(em, detection, geo, msg))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            # Silently swallow errors so a broken channel never kills the engine

    async def test_channels(self) -> Dict[str, str]:
        """Send a test message to all enabled channels. Returns {channel: 'ok'|error}."""
        results: Dict[str, str] = {}
        test_text = "[CNSL] Webhook test — channels are working correctly."

        async def _try(name: str, coro) -> None:
            try:
                await coro
                results[name] = "ok"
            except Exception as e:
                results[name] = str(e)

        tg = self._cfg.get("telegram", {})
        if tg.get("enabled"):
            await _try("telegram", self._send_telegram(tg["bot_token"], tg["chat_id"], test_text))

        dc = self._cfg.get("discord", {})
        if dc.get("enabled"):
            await _try("discord", _post_json(dc["webhook_url"], {"content": test_text}))

        sl = self._cfg.get("slack", {})
        if sl.get("enabled"):
            await _try("slack", _post_json(sl["webhook_url"], {"text": test_text}))

        wh = self._cfg.get("webhook", {})
        if wh.get("enabled"):
            await _try("webhook", _post_json(wh["url"], {"message": test_text},
                       headers=wh.get("headers", {})))

        return results

    async def _digest_loop(self) -> None:
        """Send daily digest at configured hour (default 08:00)."""
        import datetime
        digest_cfg = self._cfg.get("daily_digest", {})
        target_hour = int(digest_cfg.get("hour", 8))
        while True:
            now = datetime.datetime.now()
            next_run = now.replace(hour=target_hour, minute=0, second=0, microsecond=0)
            if next_run <= now:
                next_run += datetime.timedelta(days=1)
            await asyncio.sleep((next_run - now).total_seconds())
            await self._send_digest()

    async def _send_digest(self) -> None:
        """Send buffered daily summary to all enabled channels."""
        if not self._digest_buffer:
            return
        events = self._digest_buffer[:]
        self._digest_buffer.clear()
        high = sum(1 for e in events if e.severity == "HIGH")
        med  = sum(1 for e in events if e.severity == "MEDIUM")
        low  = sum(1 for e in events if e.severity == "LOW")
        unique_ips = len({e.src_ip for e in events})
        msg = (
            f"[CNSL] Daily Digest\n"
            f"Total alerts: {len(events)} | HIGH: {high} MEDIUM: {med} LOW: {low}\n"
            f"Unique IPs: {unique_ips}\n"
        )
        if events:
            top = sorted(events, key=lambda e: self._sev_order.get(e.severity, 0), reverse=True)[:3]
            msg += "Top events:\n" + "\n".join(
                f"  {e.severity} {e.src_ip} — {e.kind}" for e in top
            )
        tg = self._cfg.get("telegram", {})
        if tg.get("enabled"):
            try:
                await self._send_telegram(tg["bot_token"], tg["chat_id"], msg)
            except Exception:
                pass
        sl = self._cfg.get("slack", {})
        if sl.get("enabled"):
            try:
                await self._send_slack(sl["webhook_url"], msg)
            except Exception:
                pass

    # Telegram 

    async def _send_telegram(self, token: str, chat_id: str, text: str) -> None:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
        await _post_json(url, payload)

    # Discord 

    async def _send_discord(self, url: str, d: Detection, geo: Optional[Dict], text: str) -> None:
        color = {"HIGH": 0xFF0000, "MEDIUM": 0xFF8C00, "LOW": 0x3498DB}.get(d.severity, 0x95A5A6)
        country = geo.get("country", "Unknown") if geo else "Unknown"

        payload = {
            "embeds": [{
                "title": f"CNSL Alert — {d.severity}",
                "color": color,
                "fields": [
                    {"name": "IP",           "value": f"`{d.src_ip}`",  "inline": True},
                    {"name": "Location",     "value": country,          "inline": True},
                    {"name": "Failed Logins","value": str(d.fail_count),"inline": True},
                    {"name": "Unique Users", "value": str(d.uniq_users),"inline": True},
                    {"name": "Reasons",      "value": "\n".join(f"- {r}" for r in d.reasons)},
                ],
                "footer": {"text": f"CNSL | {iso_time()}"},
            }]
        }
        await _post_json(url, payload)

    # Slack 

    async def _send_slack(self, url: str, text: str) -> None:
        payload = {"text": text}
        await _post_json(url, payload)

    #  Generic webhook 

    async def _send_webhook(self, cfg: Dict, d: Detection, geo: Optional[Dict]) -> None:
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        secret_h = cfg.get("secret_header")
        secret_v = cfg.get("secret_value")
        if secret_h and secret_v:
            headers[secret_h] = secret_v

        payload = {
            "type":      "cnsl_alert",
            "time":      iso_time(),
            "ip":        d.src_ip,
            "severity":  d.severity,
            "reasons":   d.reasons,
            "fail_count": d.fail_count,
            "geo":       geo or {},
        }
        await _post_json(cfg["url"], payload, headers=headers)

    #  Email (SMTP) 

    async def _send_email(
        self,
        cfg: Dict,
        d: Detection,
        geo: Optional[Dict],
        plain_text: str,
    ) -> None:
        """Send alert via SMTP. Runs blocking smtplib in a thread executor."""
        smtp_host = cfg.get("smtp_host", "")
        smtp_port = int(cfg.get("smtp_port", 587))
        username  = cfg.get("username", "")
        password  = cfg.get("password", "")
        from_addr = cfg.get("from", username)
        to_addrs  = cfg.get("to", [])
        use_tls   = cfg.get("use_tls", True)   # STARTTLS (port 587)
        use_ssl   = cfg.get("use_ssl", False)   # Implicit SSL (port 465)
        subject_prefix = cfg.get("subject_prefix", "[CNSL]")

        if not smtp_host or not to_addrs:
            return

        subject = f"{subject_prefix} {d.severity} Alert — {d.src_ip}"

        # Build HTML body
        country = geo.get("country", "Unknown") if geo else "Unknown"
        city    = geo.get("city", "") if geo else ""
        isp     = geo.get("isp", "") if geo else ""
        location = f"{country}, {city}" if city else country
        color    = {"HIGH": "#e74c3c", "MEDIUM": "#e67e22", "LOW": "#3498db"}.get(
            d.severity, "#95a5a6"
        )
        reasons_html = "".join(f"<li>{r}</li>" for r in d.reasons)

        html_body = f"""
<html><body style="font-family:monospace;background:#1a1a1a;color:#e0e0e0;padding:24px">
<div style="max-width:600px;margin:auto;background:#2a2a2a;border-radius:8px;
            border-left:4px solid {color};padding:20px">
  <h2 style="color:{color};margin:0 0 16px">CNSL ALERT — {d.severity}</h2>
  <table style="width:100%;border-collapse:collapse">
    <tr><td style="padding:4px 0;color:#888;width:120px">IP</td>
        <td style="color:#fff;font-weight:bold">{d.src_ip}</td></tr>
    <tr><td style="padding:4px 0;color:#888">Location</td>
        <td>{location}</td></tr>
    <tr><td style="padding:4px 0;color:#888">ISP</td>
        <td>{isp or "—"}</td></tr>
    <tr><td style="padding:4px 0;color:#888">Fails</td>
        <td>{d.fail_count} (window: {d.window_sec}s)</td></tr>
    <tr><td style="padding:4px 0;color:#888">Unique users</td>
        <td>{d.uniq_users}</td></tr>
    <tr><td style="padding:4px 0;color:#888">Time</td>
        <td>{iso_time()}</td></tr>
  </table>
  <h3 style="color:#aaa;margin:16px 0 8px">Detection Reasons</h3>
  <ul style="margin:0;padding-left:20px;color:#ccc">{reasons_html}</ul>
  <p style="margin:16px 0 0;font-size:11px;color:#666">Sent by CNSL — Correlated Network Security Layer</p>
</div></body></html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = from_addr
        msg["To"]      = ", ".join(to_addrs) if isinstance(to_addrs, list) else to_addrs
        msg.attach(MIMEText(plain_text, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: _smtp_send(
                smtp_host, smtp_port, username, password,
                from_addr, to_addrs, msg, use_tls, use_ssl,
            ),
        )



# SMTP helper


def _smtp_send(
    host: str,
    port: int,
    username: str,
    password: str,
    from_addr: str,
    to_addrs,
    msg: MIMEMultipart,
    use_tls: bool,
    use_ssl: bool,
) -> None:
    """Blocking SMTP send — run in executor. Errors are swallowed."""
    try:
        recipients = to_addrs if isinstance(to_addrs, list) else [to_addrs]
        if use_ssl:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=ctx, timeout=15) as s:
                if username and password:
                    s.login(username, password)
                s.sendmail(from_addr, recipients, msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=15) as s:
                if use_tls:
                    s.starttls(context=ssl.create_default_context())
                if username and password:
                    s.login(username, password)
                s.sendmail(from_addr, recipients, msg.as_string())
    except Exception:
        pass  # Notification failure must never crash the engine


# HTTP helper


async def _post_json(url: str, payload: Dict, headers: Optional[Dict] = None) -> None:
    try:
        import aiohttp
        h = {"Content-Type": "application/json"}
        if headers:
            h.update(headers)
        async with aiohttp.ClientSession() as s:
            async with s.post(
                url, json=payload, headers=h,
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp:
                _ = await resp.text()
    except Exception:
        pass  # Notification failure must never crash the engine