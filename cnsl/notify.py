"""
cnsl/notify.py — Multi-channel alert notifications.

Supported channels:
  - Telegram Bot
  - Discord Webhook
  - Slack Webhook
  - Generic HTTP webhook (POST JSON)

Configure in config.json under "notifications": { ... }
All channels are optional and independent — failure in one
does not affect others.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

from .models import Detection, iso_time



# Notification payload builder


def _build_message(detection: Detection, geo: Optional[Dict] = None) -> str:
    """Build a human-readable alert message."""
    sev_emoji = {"HIGH": "🚨", "MEDIUM": "⚠️", "LOW": "ℹ️"}.get(detection.severity, "⚠️")
    flag = geo.get("flag", "🌐") if geo else "🌐"
    country = geo.get("country", "Unknown") if geo else "Unknown"
    city = geo.get("city", "") if geo else ""
    isp = geo.get("isp", "") if geo else ""
    proxy = " [PROXY/VPN]" if geo and geo.get("proxy") else ""
    hosting = " [DATACENTER]" if geo and geo.get("hosting") else ""

    location = f"{flag} {country}"
    if city:
        location += f", {city}"

    lines = [
        f"{sev_emoji} *CNSL ALERT — {detection.severity}*",
        f"",
        f"🖥️  IP: `{detection.src_ip}`{proxy}{hosting}",
        f"📍 Location: {location}",
        f"🏢 ISP: {isp}" if isp else "",
        f"",
        f"📊 Stats:",
        f"  • Failed logins: {detection.fail_count} (window: {detection.window_sec}s)",
        f"  • Unique users tried: {detection.uniq_users}",
        f"",
        f"🔍 Reasons:",
    ]
    for r in detection.reasons:
        lines.append(f"  • {r}")
    lines.extend([
        f"",
        f"🕐 Time: {iso_time()}",
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

    async def send(self, detection: Detection, geo: Optional[Dict] = None) -> None:
        """Send alert to all enabled channels (fire-and-forget, errors swallowed)."""
        if self._sev_order.get(detection.severity, 0) < self._sev_order.get(self._min_sev, 1):
            return

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

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            # Silently swallow errors so a broken channel never kills the engine

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
        flag = geo.get("flag", "🌐") if geo else "🌐"
        country = geo.get("country", "Unknown") if geo else "Unknown"

        payload = {
            "embeds": [{
                "title": f"🚨 CNSL Alert — {d.severity}",
                "color": color,
                "fields": [
                    {"name": "IP", "value": f"`{d.src_ip}`", "inline": True},
                    {"name": "Location", "value": f"{flag} {country}", "inline": True},
                    {"name": "Failed Logins", "value": str(d.fail_count), "inline": True},
                    {"name": "Unique Users", "value": str(d.uniq_users), "inline": True},
                    {"name": "Reasons", "value": "\n".join(f"• {r}" for r in d.reasons)},
                ],
                "footer": {"text": f"CNSL • {iso_time()}"},
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