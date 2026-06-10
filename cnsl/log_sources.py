"""
cnsl/log_sources.py — Multi-log source parsers.

Supported log sources:
  - auth.log / secure     (SSH — existing)
  - nginx access log      (web attacks, scanners)
  - apache access log     (web attacks)
  - mysql error log       (DB brute-force)
  - syslog                (sudo abuse, cron, general)
  - ufw.log               (firewall events)

Each parser returns an Event with:
  - kind: source-specific event type
  - src_ip: attacker IP (if parseable)
  - meta: additional context (status code, path, method, etc.)

Design: parsers are pure functions (line -> Event | None).
New log sources can be added by implementing parse_<name>(line) -> Event | None.
"""

from __future__ import annotations

import re
from typing import Optional

from .models import Event, now
from .parsers import _clean_ip



# Nginx / Apache access log


# Combined Log Format:
# 1.2.3.4 - - [01/Jan/2025:00:00:00 +0000] "GET /path HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
_ACCESS_RE = re.compile(
    r'(?P<ip>[\da-fA-F\.:]+)\s+-\s+-\s+\[.*?\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d\.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# Paths that strongly indicate exploitation attempts
_EXPLOIT_PATHS = re.compile(
    r'(?i)(/\.env|/wp-login\.php|/phpmyadmin|'
    r'/cgi-bin/.*\.(sh|pl|cgi)|/xmlrpc\.php|'
    r'(?:\.\./)(?:\.\./)+(etc|proc|var)|'
    r'/(?:shell|cmd|exec|eval)(?:\b|\.)|'
    r'/(?:passwd|shadow|sudoers)\b|'
    r'\.git/config|/backup.*\.(sql|tar|zip|gz)|'
    r'/dump\.sql|/db\.sql)',
    re.IGNORECASE,
)

# Paths that indicate scanning/enumeration (lower severity than exploit)
_SCAN_PATHS = re.compile(
    r'(?i)(/wp-admin|/admin(?:/|$)|/administrator|'
    r'/config(?:\.|/)|/setup(?:\.|/)|'
    r'/\.htaccess|/web\.config|'
    r'/actuator|/api/v\d|/swagger|'
    r'\.php\?(?:.*=(?:\.\.\/|http://|https://|file://))|'
    r'/(?:login|signin|logon)\.(?:php|asp|aspx)\b)',
    re.IGNORECASE,
)

# Known scanner / attack tool user-agents
_SCANNER_UA = re.compile(
    r'(?i)(sqlmap|nikto|nmap|masscan|zgrab|dirbuster|gobuster|'
    r'nuclei|wfuzz|hydra|medusa|metasploit|nessus|burpsuite|'
    r'acunetix|openvas|netsparker|arachni|'
    r'\bpython-requests/\d|\bgo-http-client/\d|'
    r'\bcurl/\d+\.\d+(?!.*Mozilla))',  # curl but NOT embedded in real UA
    re.IGNORECASE,
)

# Legitimate bots — avoid false positives
_LEGIT_BOTS = re.compile(
    r'(?i)(googlebot|bingbot|yandexbot|duckduckbot|baiduspider|'
    r'facebookexternalhit|twitterbot|linkedinbot|'
    r'uptimerobot|pingdom|datadog|newrelic)',
    re.IGNORECASE,
)


def parse_web_access(line: str, source: str = "nginx") -> Optional[Event]:
    """Parse Nginx or Apache combined access log line."""
    m = _ACCESS_RE.match(line.strip())
    if not m:
        return None

    ip     = _clean_ip(m.group("ip"))
    method = m.group("method").upper()
    path   = m.group("path")
    status = int(m.group("status"))
    ua     = m.group("ua") or ""

    # Skip legitimate bots — no false positives
    if _LEGIT_BOTS.search(ua):
        return None

    kind         = None
    threat_score = 0

    #  Explicit exploitation attempt 
    if _EXPLOIT_PATHS.search(path):
        kind          = "WEB_EXPLOIT_ATTEMPT"
        threat_score += 5
        if method == "POST":
            threat_score += 2

    #  Scanning / enumeration 
    elif _SCAN_PATHS.search(path):
        kind          = "WEB_SCAN"
        threat_score += 3

    #  Scanner user-agent (any path) 
    if _SCANNER_UA.search(ua):
        kind          = kind or "WEB_SCAN"
        threat_score += 3

    #  Authentication failure (only if already suspicious or high volume) 
    if status in (401, 403) and kind is None:
        # Single 401/403 is too noisy — only flag if path is also suspicious
        if _SCAN_PATHS.search(path) or _EXPLOIT_PATHS.search(path):
            kind          = "WEB_AUTH_FAIL"
            threat_score += 2

    #  404 flood — only flag scanner UA or exploit paths 
    # A bare 404 on a normal path is far too noisy to be useful
    if status == 404 and kind is None and _SCANNER_UA.search(ua):
        kind          = "WEB_SCAN"
        threat_score += 1

    if kind is None:
        return None

    return Event(
        ts=now(), source=source, kind=kind,
        src_ip=ip, raw=line.strip(),
        meta={
            "method":       method,
            "path":         path,
            "status":       status,
            "ua":           ua,
            "threat_score": threat_score,
        },
    )



# MySQL error log


# 2025-01-01T00:00:00.000000Z 0 [Warning] Access denied for user 'root'@'1.2.3.4'
_MYSQL_DENY_RE = re.compile(
    r"Access denied for user '(?P<user>[^']+)'@'(?P<ip>[\da-fA-F\.:]+)'",
    re.IGNORECASE,
)


def parse_mysql(line: str) -> Optional[Event]:
    m = _MYSQL_DENY_RE.search(line)
    if not m:
        return None
    return Event(
        ts=now(), source="mysql", kind="DB_AUTH_FAIL",
        src_ip=_clean_ip(m.group("ip")), user=m.group("user"),
        raw=line.strip(),
        meta={"db": "mysql"},
    )



# UFW firewall log


# Jan  1 00:00:00 host kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 ... DPT=22
_UFW_RE = re.compile(
    r'\[UFW (?P<action>BLOCK|ALLOW|LIMIT)\].*?'
    r'SRC=(?P<src>[\da-fA-F\.:]+).*?'
    r'DST=(?P<dst>[\da-fA-F\.:]+)',
    re.IGNORECASE,
)
_UFW_DPT_RE = re.compile(r'DPT=(\d+)')

# Ports that should never get legitimate traffic
_HONEYPOT_PORTS = {23, 2323, 3389, 5900, 5985, 6379, 27017, 9200}


def parse_ufw(line: str) -> Optional[Event]:
    m = _UFW_RE.search(line)
    if not m:
        return None

    action = m.group("action")
    src    = _clean_ip(m.group("src"))
    dst    = _clean_ip(m.group("dst"))
    dpt_m  = _UFW_DPT_RE.search(line)
    dpt    = int(dpt_m.group(1)) if dpt_m else 0

    if action != "BLOCK":
        return None

    kind = "FW_HONEYPOT_PORT" if dpt in _HONEYPOT_PORTS else "FW_BLOCK"

    return Event(
        ts=now(), source="ufw", kind=kind,
        src_ip=src, dst_ip=dst,
        raw=line.strip(),
        meta={"dst_port": dpt, "action": action},
    )



# Syslog — sudo abuse, su failures


# Jan  1 00:00:00 host sudo: baduser : user NOT in sudoers
# Jan  1 00:00:00 host su[1234]: FAILED su for root by baduser
_SUDO_FAIL_RE = re.compile(r'sudo:.*NOT in sudoers|sudo:.*authentication failure', re.I)
_SU_FAIL_RE   = re.compile(r'su\[\d+\].*FAILED su for (\S+) by (\S+)', re.I)


def parse_syslog(line: str) -> Optional[Event]:
    s = line.strip()

    if _SUDO_FAIL_RE.search(s):
        um   = re.search(r'sudo:\s+(\S+)\s+:', s)
        user = um.group(1) if um else None
        return Event(
            ts=now(), source="syslog", kind="SUDO_FAIL",
            src_ip=None, user=user, raw=s,
            meta={"type": "privilege_escalation"},
        )

    m = _SU_FAIL_RE.search(s)
    if m:
        return Event(
            ts=now(), source="syslog", kind="SU_FAIL",
            src_ip=None, user=m.group(2), raw=s,
            meta={"target_user": m.group(1), "type": "privilege_escalation"},
        )

    return None



# Log file tailer factory


import asyncio
from .logger import JsonLogger

_RETRY_DELAY = 5


async def tail_log_file(
    queue:    asyncio.Queue,
    path:     str,
    parser,
    logger:   JsonLogger,
    source:   str,
) -> None:
    """
    Generic async log file tailer.
    Calls parser(line) -> Event | None on each line.
    Retries on failure (handles log rotation via tail -F).
    """
    await logger.log("source_start", {"source": source, "path": path})

    while True:
        import os
        if not os.path.exists(path):
            await logger.log("source_waiting", {
                "source": source, "path": path,
                "msg": "File not found, waiting...",
            })
            await asyncio.sleep(_RETRY_DELAY)
            continue

        try:
            proc = await asyncio.create_subprocess_exec(
                "tail", "-F", path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            assert proc.stdout

            try:
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    text = line.decode(errors="ignore").strip()
                    if not text:
                        continue
                    ev = parser(text)
                    if ev:
                        await queue.put(ev)
            finally:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass

        except Exception as e:
            await logger.log("source_error", {"source": source, "error": str(e)})

        await logger.log("source_restart", {"source": source, "delay": _RETRY_DELAY})
        await asyncio.sleep(_RETRY_DELAY)


def get_log_tasks(cfg: dict, queue: asyncio.Queue, logger: JsonLogger) -> list:
    """
    Build list of asyncio tasks based on configured log sources.
    """
    import asyncio as _asyncio

    sources = cfg.get("log_sources", {})
    tasks   = []

    parsers = {
        "nginx":  lambda line: parse_web_access(line, "nginx"),
        "apache": lambda line: parse_web_access(line, "apache"),
        "mysql":  parse_mysql,
        "ufw":    parse_ufw,
        "syslog": parse_syslog,
    }

    for name, path in sources.items():
        if not path or not isinstance(path, str):
            continue
        parser = parsers.get(name)
        if parser is None:
            continue
        tasks.append(
            _asyncio.create_task(
                tail_log_file(queue, path, parser, logger, name),
                name=f"logsrc_{name}",
            )
        )

    return tasks





# MySQL error log

# 2025-01-01T00:00:00.000000Z 0 [Warning] Access denied for user 'root'@'1.2.3.4'

_MYSQL_DENY_RE = re.compile(
    r"Access denied for user '(?P<user>[^']+)'@'(?P<ip>[\da-fA-F\.:]+)'",
    re.IGNORECASE,
)


def parse_mysql(line: str) -> Optional[Event]:
    m = _MYSQL_DENY_RE.search(line)
    if not m:
        return None
    return Event(
        ts=now(), source="mysql", kind="DB_AUTH_FAIL",
        src_ip=m.group("ip"), user=m.group("user"),
        raw=line.strip(),
        meta={"db": "mysql"},
    )



# UFW firewall log
# Jan  1 00:00:00 host kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 ... DPT=22

_UFW_RE = re.compile(
    r'\[UFW (?P<action>BLOCK|ALLOW|LIMIT)\].*?'
    r'SRC=(?P<src>[\da-fA-F\.:]+).*?'
    r'DST=(?P<dst>[\da-fA-F\.:]+)',
    re.IGNORECASE,
)
_UFW_DPT_RE = re.compile(r'DPT=(\d+)')

# Ports that should never get legitimate traffic
_HONEYPOT_PORTS = {23, 2323, 3389, 5900, 5985, 6379, 27017, 9200}


def parse_ufw(line: str) -> Optional[Event]:
    m = _UFW_RE.search(line)
    if not m:
        return None

    action = m.group("action")
    src    = m.group("src")
    dst    = m.group("dst")
    dpt_m  = _UFW_DPT_RE.search(line)
    dpt    = int(dpt_m.group(1)) if dpt_m else 0

    if action != "BLOCK":
        return None

    kind = "FW_BLOCK"
    if dpt in _HONEYPOT_PORTS:
        kind = "FW_HONEYPOT_PORT"

    return Event(
        ts=now(), source="ufw", kind=kind,
        src_ip=src, dst_ip=dst,
        raw=line.strip(),
        meta={"dst_port": dpt, "action": action},
    )



# Syslog — sudo abuse, su failures

# Jan  1 00:00:00 host sudo: baduser : user NOT in sudoers
# Jan  1 00:00:00 host su[1234]: FAILED su for root by baduser

_SUDO_FAIL_RE  = re.compile(r'sudo:.*NOT in sudoers|sudo:.*authentication failure', re.I)
_SU_FAIL_RE    = re.compile(r'su\[\d+\].*FAILED su for (\S+) by (\S+)', re.I)
_CRON_EDIT_RE  = re.compile(r'crontab.*REPLACE.*by\s+(\S+)', re.I)


def parse_syslog(line: str) -> Optional[Event]:
    s = line.strip()

    if _SUDO_FAIL_RE.search(s):
        # Extract username best-effort
        um = re.search(r'sudo:\s+(\S+)\s+:', s)
        user = um.group(1) if um else None
        return Event(
            ts=now(), source="syslog", kind="SUDO_FAIL",
            src_ip=None, user=user, raw=s,
            meta={"type": "privilege_escalation"},
        )

    m = _SU_FAIL_RE.search(s)
    if m:
        return Event(
            ts=now(), source="syslog", kind="SU_FAIL",
            src_ip=None, user=m.group(2), raw=s,
            meta={"target_user": m.group(1), "type": "privilege_escalation"},
        )

    return None



# Log file tailer factory


import asyncio
from .logger import JsonLogger

_RETRY_DELAY = 5


async def tail_log_file(
    queue:    asyncio.Queue,
    path:     str,
    parser,
    logger:   JsonLogger,
    source:   str,
) -> None:
    """
    Generic async log file tailer.
    Calls parser(line) -> Event | None on each line.
    Retries on failure (handles log rotation via tail -F).
    """
    await logger.log("source_start", {"source": source, "path": path})

    while True:
        import os
        if not os.path.exists(path):
            await logger.log("source_waiting", {
                "source": source, "path": path,
                "msg": "File not found, waiting...",
            })
            await asyncio.sleep(_RETRY_DELAY)
            continue

        try:
            proc = await asyncio.create_subprocess_exec(
                "tail", "-F", path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            assert proc.stdout

            try:
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    text = line.decode(errors="ignore").strip()
                    if not text:
                        continue
                    ev = parser(text)
                    if ev:
                        await queue.put(ev)
            finally:
                # Always kill the subprocess — prevents zombie accumulation
                # on log rotation, EOF, or exception.
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass

        except Exception as e:
            await logger.log("source_error", {"source": source, "error": str(e)})

        await logger.log("source_restart", {"source": source, "delay": _RETRY_DELAY})
        await asyncio.sleep(_RETRY_DELAY)


def get_log_tasks(cfg: dict, queue: asyncio.Queue, logger: JsonLogger) -> list:
    """
    Build list of asyncio tasks based on configured log sources.

    Config example:
      "log_sources": {
        "nginx":  "/var/log/nginx/access.log",
        "apache": "/var/log/apache2/access.log",
        "mysql":  "/var/log/mysql/error.log",
        "ufw":    "/var/log/ufw.log",
        "syslog": "/var/log/syslog"
      }
    """
    import asyncio as _asyncio

    sources = cfg.get("log_sources", {})
    tasks   = []

    parsers = {
        "nginx":  lambda line: parse_web_access(line, "nginx"),
        "apache": lambda line: parse_web_access(line, "apache"),
        "mysql":  parse_mysql,
        "ufw":    parse_ufw,
        "syslog": parse_syslog,
    }

    for name, path in sources.items():
        if not path or not isinstance(path, str):
            continue
        parser = parsers.get(name)
        if parser is None:
            continue
        tasks.append(
            _asyncio.create_task(
                tail_log_file(queue, path, parser, logger, name),
                name=f"logsrc_{name}",
            )
        )

    return tasks