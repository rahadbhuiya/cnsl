"""
cnsl/parsers.py — Log-line parsers for auth.log and tcpdump output.

Design principles:
  - auth.log is the *primary* signal (precise, human-readable, reliable).
  - tcpdump is *secondary / hint* (noisy — used only for observability).
  - Each parser returns an Event or None; no side effects.
"""

from __future__ import annotations

import re
from typing import Optional

from .models import Event, EventKind, now


# ============================================================================
# auth.log (sshd lines) — primary signal
# ============================================================================

# "Failed password for invalid user <user> from <ip> port <p> ssh2"
# "Failed password for <user> from <ip> port <p> ssh2"
# "error: PAM: Authentication failure for <user> from <ip>"
# "authentication failure; ...rhost=<ip>  user=<user>"
_FAIL_RE = re.compile(
    r"sshd\[\d+\]:\s+"
    r"(?:Failed password|authentication failure|Invalid user"
    r"|error: PAM: Authentication failure|"
    r"Connection closed by authenticating user)"
    r".*?(?:from|rhost=)\s*(?P<ip>[\da-fA-F\.:]+)",
    re.IGNORECASE,
)
_FAIL_USER_RE = re.compile(
    r"(?:for invalid user\s+(?P<u1>\S+))|(?:for\s+(?P<u2>\S+))",
    re.IGNORECASE,
)

# "Accepted password for <user> from <ip> port <p> ssh2"
# "Accepted publickey for <user> from <ip> port <p> ssh2"
_SUCCESS_RE = re.compile(
    r"sshd\[\d+\]:\s+Accepted\s+(?:password|publickey)\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>[\da-fA-F\.:]+)",
    re.IGNORECASE,
)

# "session opened for user <user> by ..."  (secondary success signal)
_SESSION_RE = re.compile(
    r"sshd\[\d+\]:\s+pam_unix.*session opened for user\s+(?P<user>\S+)",
    re.IGNORECASE,
)


def parse_auth_event(line: str) -> Optional[Event]:
    """Parse one auth.log line.  Returns an Event or None."""
    s = line.strip()
    if "sshd" not in s.lower():
        return None

    # --- success first (more specific pattern) ---
    m = _SUCCESS_RE.search(s)
    if m:
        return Event(
            ts=now(), source="auth", kind=EventKind.SSH_SUCCESS,
            src_ip=m.group("ip"), user=m.group("user"), raw=s,
        )

    # --- fail ---
    m = _FAIL_RE.search(s)
    if m:
        ip = m.group("ip")
        user: Optional[str] = None
        mu = _FAIL_USER_RE.search(s)
        if mu:
            user = mu.group("u1") or mu.group("u2")
        return Event(
            ts=now(), source="auth", kind=EventKind.SSH_FAIL,
            src_ip=ip, user=user, raw=s,
        )

    return None


# ============================================================================
# tcpdump — secondary / hint signal
# ============================================================================

# "IP 192.168.0.5.445 > 192.168.0.10.53218: Flags ..."
_TCPDUMP_IP_RE = re.compile(
    r"IP6?\s+(?P<src>[\da-fA-F\.:]+?)(?:\.(?P<sp>\d+))?"
    r"\s+>\s+(?P<dst>[\da-fA-F\.:]+?)(?:\.(?P<dp>\d+))?[\s:]"
)


def parse_tcpdump_hint(line: str) -> Optional[Event]:
    """
    Parse one tcpdump output line.  Returns a NET_HINT Event or None.
    Conservative: only produce hints for known-suspicious / interesting traffic.
    """
    s = line.strip()
    lower = s.lower()

    hint: Optional[str] = None

    if " arp" in lower or lower.startswith("arp,") or "who-has" in lower:
        hint = "DISCOVERY"
    elif ".mdns" in lower or " mdns" in lower or "_googlecast" in lower:
        hint = "DISCOVERY"
    elif " nbns" in lower or " netbios" in lower or " smb" in lower:
        hint = "ENUM_HINT"
    elif re.search(r"\.(445|139)\b", lower):
        hint = "ENUM_HINT"
    elif " tcp " in lower and ".22 " in lower:
        hint = "SSH_NET"

    if hint is None:
        return None

    m = _TCPDUMP_IP_RE.search(s)
    src_ip = m.group("src") if m else None
    dst_ip = m.group("dst") if m else None

    return Event(
        ts=now(), source="net", kind=EventKind.NET_HINT,
        src_ip=src_ip, dst_ip=dst_ip, raw=s, meta={"hint": hint},
    )