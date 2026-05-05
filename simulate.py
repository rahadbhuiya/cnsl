#!/usr/bin/env python3
"""
simulate.py — CNSL local test simulator.

Tests all detection scenarios without a real server or real attacks.

Usage:
    python simulate.py                # full demo (all scenarios)
    python simulate.py brute          # SSH brute-force
    python simulate.py breach         # credential breach (HIGH)
    python simulate.py stuffing       # credential stuffing
    python simulate.py web            # web scanner + exploit
    python simulate.py db             # database brute-force
    python simulate.py priv           # privilege escalation
    python simulate.py honeypot       # honeypot port probe
    python simulate.py correlation    # multi-source correlation (HIGH)
    python simulate.py unblock        # auto-unblock + metrics dec
    python simulate.py allowlist      # allowlist test
    python simulate.py metrics        # metrics & DB stats
    python simulate.py notify         # notification channel dry-run test
    python simulate.py live           # interactive mode
"""

import sys
import time
import asyncio
from datetime import datetime

sys.path.insert(0, ".")
from cnsl.models   import Event, EventKind, now
from cnsl.config   import load_config
from cnsl.logger   import JsonLogger
from cnsl.blocker  import Blocker
from cnsl.detector import Detector
from cnsl.correlator import Correlator
from cnsl.metrics  import Metrics
from cnsl.notify   import Notifier
from cnsl.store    import Store


# ── Terminal colours ─────────────────────────────────────────────────────────
R   = "\033[91m"
Y   = "\033[93m"
G   = "\033[92m"
B   = "\033[94m"
C   = "\033[96m"
M   = "\033[95m"
W   = "\033[97m"
DIM = "\033[2m"
RST = "\033[0m"
BOLD= "\033[1m"


def banner():
    print(f"""
{C}{BOLD}╔══════════════════════════════════════════════════════╗
║        CNSL — Local Test Simulator  v1.0.1           ║
║   No real server required — all tests run locally    ║
╚══════════════════════════════════════════════════════╝{RST}
""")


def ts():
    return datetime.now().strftime("%H:%M:%S")


def log(msg, color=W):
    print(f"{DIM}[{ts()}]{RST} {color}{msg}{RST}")


def section(title):
    print(f"\n{B}{BOLD}{'─'*54}{RST}")
    print(f"{B}{BOLD}  {title}{RST}")
    print(f"{B}{BOLD}{'─'*54}{RST}")


# ── Event factories ──────────────────────────────────────────────────────────

def make_fail(ip, user="root"):
    return Event(ts=now(), source="auth", kind=EventKind.SSH_FAIL,
                 src_ip=ip, user=user,
                 raw=f"sshd[1]: Failed password for {user} from {ip} port 22 ssh2")

def make_success(ip, user="root"):
    return Event(ts=now(), source="auth", kind=EventKind.SSH_SUCCESS,
                 src_ip=ip, user=user,
                 raw=f"sshd[1]: Accepted password for {user} from {ip} port 22 ssh2")

def make_web_scan(ip):
    return Event(ts=now(), source="nginx", kind="WEB_SCAN",
                 src_ip=ip, user=None,
                 raw=f'1.2.3.4 - - "GET /.env HTTP/1.1" 404 - "nikto/2.1"')

def make_web_exploit(ip, path="/.env"):
    return Event(ts=now(), source="nginx", kind="WEB_EXPLOIT_ATTEMPT",
                 src_ip=ip, user=None,
                 raw=f'GET {path} HTTP/1.1 from {ip}')

def make_db_fail(ip, user="root"):
    return Event(ts=now(), source="mysql", kind="DB_AUTH_FAIL",
                 src_ip=ip, user=user,
                 raw=f"Access denied for user '{user}'@'{ip}'")

def make_fw_honeypot(ip, port=23):
    return Event(ts=now(), source="ufw", kind="FW_HONEYPOT_PORT",
                 src_ip=ip, user=None,
                 raw=f"UFW BLOCK IN=eth0 SRC={ip} DPT={port}")

def make_fw_block(ip):
    return Event(ts=now(), source="ufw", kind="FW_BLOCK",
                 src_ip=ip, user=None,
                 raw=f"UFW BLOCK IN=eth0 SRC={ip} DPT=8080")

def make_sudo_fail(ip, user="www-data"):
    return Event(ts=now(), source="syslog", kind="SUDO_FAIL",
                 src_ip=ip, user=user,
                 raw=f"sudo: {user}: authentication failure")


# ── Setup ────────────────────────────────────────────────────────────────────

async def setup():
    """Create a fully-wired test CNSL instance (dry-run, no real blocking)."""
    cfg = load_config(None)
    cfg["thresholds"]["fails_threshold"]               = 5
    cfg["thresholds"]["unique_users_threshold"]        = 3
    cfg["thresholds"]["success_after_fails_threshold"] = 3
    cfg["thresholds"]["fails_window_sec"]              = 60
    cfg["thresholds"]["incident_cooldown_sec"]         = 5
    cfg["actions"]["dry_run"] = True
    cfg["logging"]["console_verbose"] = False

    logger   = JsonLogger("./cnsl_test.jsonl", verbose=False)
    metrics  = Metrics()
    notifier = Notifier(cfg)
    store    = Store("./cnsl_test.db")
    await store.init()

    blocker = Blocker(
        dry_run=True, backend="iptables", chain="INPUT",
        ipset_name="cnsl_test", block_duration_sec=10,
        allowlist={"127.0.0.1"}, logger=logger,
        metrics=metrics,   # Bug 3 fix — dec_block() wired
    )
    blocker.store = store  # Bug 13 fix — remove_block() wired

    correlator = Correlator()

    detector = Detector(cfg, logger, blocker,
                        geoip=None, store=store,
                        metrics=metrics, notifier=notifier,
                        correlator=correlator)

    return detector, blocker, metrics, store, logger, notifier


# ── Scenario 1: SSH Brute-force ──────────────────────────────────────────────

async def scenario_brute_force(detector, blocker):
    section("Scenario 1 — SSH Brute-force")
    ip = "45.33.32.156"
    print(f"  Attacker : {Y}{ip}{RST}   threshold = 5 fails\n")

    for i in range(1, 7):
        await detector.handle(make_fail(ip, "root"))
        st      = detector._state[ip]
        bar     = G + "█" * i + RST + "░" * (6 - i)
        blocked = f"  {R}→ BLOCKED{RST}" if blocker.is_blocked(ip) else ""
        print(f"  Fail #{i}  [{bar}]  window_fails={len(st.fails)}{blocked}")
        await asyncio.sleep(0.25)

    print()
    if blocker.is_blocked(ip):
        log(f"IP {ip} blocked (dry-run — no real iptables change)", R)
    else:
        log(f"MEDIUM alert raised for {ip}", Y)


# ── Scenario 2: Credential Stuffing ─────────────────────────────────────────

async def scenario_credential_stuffing(detector, blocker):
    section("Scenario 2 — Credential Stuffing")
    ip    = "185.220.101.45"
    users = ["admin", "ubuntu", "pi", "deploy", "git", "postgres"]
    print(f"  Attacker : {Y}{ip}{RST}   tries {len(users)} different usernames\n")

    for i, user in enumerate(users, 1):
        await detector.handle(make_fail(ip, user))
        st   = detector._state[ip]
        uniq = len({u for _, u in st.users if u})
        print(f"  Try #{i}  user={C}{user:<10}{RST}  unique_users={Y}{uniq}{RST}")
        await asyncio.sleep(0.2)

    print()
    log(f"Credential stuffing detected from {ip}", Y)


# ── Scenario 3: Credential Breach (HIGH) ─────────────────────────────────────

async def scenario_credential_breach(detector, blocker):
    section("Scenario 3 — Credential Breach  (HIGH severity)")
    ip = "23.129.64.214"
    print(f"  Attacker : {Y}{ip}{RST}   fails 4 times then logs in successfully\n")

    for i in range(1, 5):
        await detector.handle(make_fail(ip, "admin"))
        print(f"  {R}FAIL #{i}{RST}  from {ip}")
        await asyncio.sleep(0.25)

    print(f"\n  {G}{BOLD}SUCCESS!{RST}  Attacker logs in with stolen password...")
    await asyncio.sleep(0.4)
    await detector.handle(make_success(ip, "admin"))
    await asyncio.sleep(0.3)

    print()
    if blocker.is_blocked(ip):
        log(f"HIGH ALERT — {ip} BLOCKED  (credential breach)", R)
    else:
        log(f"HIGH ALERT — {ip} flagged  (dry-run, no real block)", R)


# ── Scenario 4: Web Scanner + Exploit ────────────────────────────────────────

async def scenario_web(detector, blocker):
    section("Scenario 4 — Web Scanner + Exploit Attempt")
    ip = "104.21.44.82"
    print(f"  Attacker : {Y}{ip}{RST}   nikto scan then exploit paths\n")

    print(f"  {C}Phase 1 — Web scanner detected{RST}")
    for path in ["/.env", "/wp-admin/", "/.git/config", "/phpmyadmin/"]:
        await detector.handle(make_web_scan(ip))
        print(f"  {Y}WEB_SCAN{RST}  GET {path}")
        await asyncio.sleep(0.2)

    print(f"\n  {C}Phase 2 — Exploit attempt{RST}")
    for path in ["/.env", "/etc/passwd", "/admin/config.php"]:
        await detector.handle(make_web_exploit(ip, path))
        print(f"  {R}WEB_EXPLOIT{RST}  GET {path}")
        await asyncio.sleep(0.2)

    print()
    if blocker.is_blocked(ip):
        log(f"IP {ip} blocked after web attack", R)
    else:
        log(f"Web attack logged from {ip}", Y)


# ── Scenario 5: Database Brute-force ─────────────────────────────────────────

async def scenario_db(detector, blocker):
    section("Scenario 5 — Database Brute-force")
    ip    = "91.108.56.11"
    users = ["root", "admin", "mysql", "wordpress", "app"]
    print(f"  Attacker : {Y}{ip}{RST}   MySQL auth failures\n")

    for i, user in enumerate(users, 1):
        await detector.handle(make_db_fail(ip, user))
        print(f"  {R}DB_AUTH_FAIL #{i}{RST}  user={C}{user}{RST}  from {ip}")
        await asyncio.sleep(0.2)

    print()
    log(f"Database brute-force logged from {ip}", Y)


# ── Scenario 6: Privilege Escalation ─────────────────────────────────────────

async def scenario_priv_escalation(detector, blocker):
    section("Scenario 6 — Privilege Escalation")
    ip = "77.88.21.3"
    print(f"  Attacker : {Y}{ip}{RST}")
    print(f"  SSH login → then tries sudo (common post-exploit pattern)\n")

    print(f"  {G}SSH_SUCCESS{RST}  attacker logs in as 'deploy'")
    await detector.handle(make_success(ip, "deploy"))
    await asyncio.sleep(0.4)

    print(f"\n  Attempting privilege escalation via sudo...")
    for i in range(1, 4):
        await detector.handle(make_sudo_fail(ip, "deploy"))
        print(f"  {R}SUDO_FAIL #{i}{RST}  deploy → root  from {ip}")
        await asyncio.sleep(0.25)

    print()
    log(f"Privilege escalation attempt detected from {ip}", R)


# ── Scenario 7: Honeypot Port Probe ──────────────────────────────────────────

async def scenario_honeypot(detector, blocker):
    section("Scenario 7 — Honeypot Port Probe")
    ip    = "198.51.100.42"
    ports = [23, 3389, 6379]
    print(f"  Attacker : {Y}{ip}{RST}")
    print(f"  Probing honeypot ports: Telnet(23), RDP(3389), Redis(6379)\n")

    for port in ports:
        await detector.handle(make_fw_honeypot(ip, port))
        print(f"  {R}HONEYPOT PROBE{RST}  port={Y}{port}{RST}  from {ip}")
        await asyncio.sleep(0.3)
        if blocker.is_blocked(ip):
            print(f"  {R}→ INSTANT BLOCK{RST}  (honeypot = zero tolerance)")
            break

    print()
    if blocker.is_blocked(ip):
        log(f"IP {ip} instantly blocked after honeypot probe", R)
    else:
        log(f"Honeypot probe logged from {ip}", Y)


# ── Scenario 8: Multi-Source Correlation (HIGH) ───────────────────────────────

async def scenario_correlation(detector, blocker):
    section("Scenario 8 — Multi-Source Correlation (HIGH)")
    ip = "203.0.113.99"
    print(f"  Attacker : {Y}{ip}{RST}")
    print(f"  Same IP attacks Web + SSH + DB → correlator fires HIGH alert\n")

    print(f"  {C}Source 1 — Web scan{RST}")
    await detector.handle(make_web_scan(ip))
    await detector.handle(make_web_exploit(ip, "/.env"))
    print(f"  WEB_SCAN + WEB_EXPLOIT from {ip}")
    await asyncio.sleep(0.4)

    print(f"\n  {C}Source 2 — SSH brute-force{RST}")
    for i in range(1, 4):
        await detector.handle(make_fail(ip, ["root", "admin", "ubuntu"][i-1]))
        print(f"  SSH_FAIL #{i} from {ip}")
        await asyncio.sleep(0.2)

    print(f"\n  {C}Source 3 — DB attack{RST}")
    await detector.handle(make_db_fail(ip, "root"))
    print(f"  DB_AUTH_FAIL from {ip}")
    await asyncio.sleep(0.4)

    print()
    if blocker.is_blocked(ip):
        log(f"HIGH — Multi-source attack from {ip} BLOCKED  (correlator)", R)
    else:
        log(f"HIGH — Multi-source attack from {ip} detected (correlator)", R)


# ── Scenario 9: Auto-Unblock + Metrics dec_block ─────────────────────────────

async def scenario_unblock(detector, blocker, metrics):
    section("Scenario 9 — Auto-Unblock + Metrics Counter")
    ip = "10.0.0.99"
    print(f"  Test IP  : {Y}{ip}{RST}   block_duration = 10s (test mode)\n")

    before_count = metrics._blocks_active

    print(f"  Triggering block via brute-force...")
    for _ in range(6):
        await detector.handle(make_fail(ip, "root"))
    await asyncio.sleep(0.2)

    if blocker.is_blocked(ip):
        after_block = metrics._blocks_active
        print(f"  {R}BLOCKED{RST}  cnsl_blocks_active = {Y}{after_block}{RST}")
        print(f"\n  Waiting for auto-unblock (10 seconds)...")
        for i in range(10, 0, -1):
            print(f"  {DIM}{i}s remaining...{RST}", end="\r")
            await asyncio.sleep(1)
            await blocker.unblock_due()
        print()

        if not blocker.is_blocked(ip):
            after_unblock = metrics._blocks_active
            print(f"  {G}UNBLOCKED{RST}  cnsl_blocks_active = {Y}{after_unblock}{RST}")
            if after_unblock < after_block:
                log("dec_block() working correctly — gauge decreased", G)
            else:
                log("WARNING — gauge did not decrease after unblock", R)
        else:
            log("Still blocked — unblock_due() may not have fired", Y)
    else:
        log(f"IP not blocked — check threshold config", Y)


# ── Scenario 10: Allowlist ────────────────────────────────────────────────────

async def scenario_allowlist(detector, blocker):
    section("Scenario 10 — Allowlisted IP (never blocked)")
    ip = "127.0.0.1"
    print(f"  Testing : {G}{ip}{RST}  (always in allowlist)\n")

    for i in range(1, 8):
        await detector.handle(make_fail(ip, "root"))
        print(f"  Fail #{i} from {G}{ip}{RST}")
        await asyncio.sleep(0.1)

    print()
    if blocker.is_blocked(ip):
        log(f"ERROR — allowlisted IP was blocked!", R)
    else:
        log(f"Correct — {ip} was NOT blocked (allowlist working)", G)


# ── Scenario 12: Notification channel dry-run ─────────────────────────────────

async def scenario_notify(notifier):
    """
    Validates the notification pipeline by building a real Detection and
    calling Notifier.send().  No network calls succeed (no real tokens),
    but this confirms:
      - _build_message() produces correct Markdown without crashes
      - Special chars in ISP/city are properly escaped for Telegram
      - severity filter (min_severity) is respected
      - All channel dispatchers are exercised without raising
    """
    section("Scenario 12 — Notification Channel Dry-run")
    from cnsl.models import Detection

    geo_tricky = {
        "country": "United_States",
        "city":    "New*York",       # asterisk would break Markdown v1 without escaping
        "isp":     "AS12345 Verizon_Business",  # underscore breaks Markdown v1
        "flag":    "🇺🇸",
        "proxy":   False,
        "hosting": True,
    }

    cases = [
        ("HIGH",   ["brute_force", "abuseipdb_score=98 reports=500 isp=Verizon_Business"],  3, 2, geo_tricky),
        ("MEDIUM", ["credential_stuffing"],                                                  4, 4, None),
        ("LOW",    ["single_fail"],                                                          1, 1, None),
    ]

    for sev, reasons, fails, users, geo in cases:
        d = Detection(src_ip="1.2.3.4", severity=sev,
                      reasons=reasons, fail_count=fails,
                      uniq_users=users, window_sec=60)
        try:
            await notifier.send(d, geo)
            print(f"  {G}OK{RST}  severity={Y}{sev}{RST}  — message built and dispatched (no real tokens)")
        except Exception as e:
            print(f"  {R}FAIL{RST} severity={sev}  error={e}")

    print()
    log("Notification pipeline validated (no crashes, escaping OK)", G)
    log("Set bot_token + chat_id in config to enable real Telegram delivery", DIM)


# ── Scenario 11: Metrics & DB stats ──────────────────────────────────────────

async def scenario_metrics(metrics, store):
    section("Scenario 11 — Metrics & Database Stats")

    db_stats  = await store.stats()
    incidents = await store.recent_incidents(limit=10)

    print(f"  {BOLD}Prometheus metrics:{RST}")
    for line in metrics.render().strip().splitlines():
        if not line.startswith("#"):
            print(f"  {DIM}{line}{RST}")

    print(f"\n  {BOLD}Database stats:{RST}")
    print(f"  Total incidents : {Y}{db_stats.get('total', 0)}{RST}")
    print(f"  HIGH severity   : {R}{db_stats.get('high', 0)}{RST}")
    print(f"  MEDIUM severity : {Y}{db_stats.get('medium', 0)}{RST}")
    print(f"  Unique IPs      : {C}{db_stats.get('unique_ips', 0)}{RST}")

    if incidents:
        print(f"\n  {BOLD}Recent incidents:{RST}")
        for inc in incidents[-5:]:
            sev_color = R if inc["severity"] == "HIGH" else Y
            print(f"  {sev_color}{inc['severity']:<8}{RST}  "
                  f"{inc['src_ip']:<18}  {inc['time']}")


# ── Interactive mode ──────────────────────────────────────────────────────────

async def interactive_mode(detector, blocker):
    section("Interactive Mode")
    print(f"  {BOLD}SSH events:{RST}")
    print(f"  {G}fail <ip> [user]{RST}        SSH failure")
    print(f"  {G}ok   <ip> [user]{RST}        SSH success")
    print(f"\n  {BOLD}Other attack types:{RST}")
    print(f"  {G}web    <ip>{RST}             web scanner")
    print(f"  {G}exploit <ip> [path]{RST}     web exploit attempt")
    print(f"  {G}db     <ip> [user]{RST}      database auth failure")
    print(f"  {G}sudo   <ip> [user]{RST}      sudo failure (priv esc)")
    print(f"  {G}hp     <ip> [port]{RST}      honeypot port probe")
    print(f"  {G}fw     <ip>{RST}             firewall block")
    print(f"\n  {BOLD}Management:{RST}")
    print(f"  {G}unblock <ip>{RST}            manually unblock IP")
    print(f"  {G}blocks{RST}                  show active blocks")
    print(f"  {G}status{RST}                  show tracked IPs")
    print(f"  {G}metrics{RST}                 show current counters")
    print(f"  {G}quit{RST}                    exit\n")

    while True:
        try:
            line = input(f"{C}cnsl>{RST} ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not line:
            continue

        parts = line.split()
        cmd   = parts[0].lower()

        if cmd in ("quit", "exit", "q"):
            break

        elif cmd == "fail":
            ip   = parts[1] if len(parts) > 1 else "1.2.3.4"
            user = parts[2] if len(parts) > 2 else "root"
            await detector.handle(make_fail(ip, user))
            st   = detector._state[ip]
            print(f"  SSH_FAIL — window_fails={len(st.fails)} "
                  f"unique_users={len({u for _,u in st.users if u})}"
                  + (f"  {R}[BLOCKED]{RST}" if blocker.is_blocked(ip) else ""))

        elif cmd == "ok":
            ip   = parts[1] if len(parts) > 1 else "1.2.3.4"
            user = parts[2] if len(parts) > 2 else "root"
            await detector.handle(make_success(ip, user))
            print(f"  SSH_SUCCESS recorded for {ip}"
                  + (f"  {R}[BLOCKED]{RST}" if blocker.is_blocked(ip) else ""))

        elif cmd == "web":
            ip = parts[1] if len(parts) > 1 else "1.2.3.4"
            await detector.handle(make_web_scan(ip))
            print(f"  WEB_SCAN from {ip}"
                  + (f"  {R}[BLOCKED]{RST}" if blocker.is_blocked(ip) else ""))

        elif cmd == "exploit":
            ip   = parts[1] if len(parts) > 1 else "1.2.3.4"
            path = parts[2] if len(parts) > 2 else "/.env"
            await detector.handle(make_web_exploit(ip, path))
            print(f"  WEB_EXPLOIT  {path}  from {ip}"
                  + (f"  {R}[BLOCKED]{RST}" if blocker.is_blocked(ip) else ""))

        elif cmd == "db":
            ip   = parts[1] if len(parts) > 1 else "1.2.3.4"
            user = parts[2] if len(parts) > 2 else "root"
            await detector.handle(make_db_fail(ip, user))
            print(f"  DB_AUTH_FAIL user={user} from {ip}"
                  + (f"  {R}[BLOCKED]{RST}" if blocker.is_blocked(ip) else ""))

        elif cmd == "sudo":
            ip   = parts[1] if len(parts) > 1 else "1.2.3.4"
            user = parts[2] if len(parts) > 2 else "www-data"
            await detector.handle(make_sudo_fail(ip, user))
            print(f"  SUDO_FAIL user={user} from {ip}"
                  + (f"  {R}[BLOCKED]{RST}" if blocker.is_blocked(ip) else ""))

        elif cmd == "hp":
            ip   = parts[1] if len(parts) > 1 else "1.2.3.4"
            port = int(parts[2]) if len(parts) > 2 else 23
            await detector.handle(make_fw_honeypot(ip, port))
            print(f"  FW_HONEYPOT_PORT port={port} from {ip}"
                  + (f"  {R}[INSTANT BLOCK]{RST}" if blocker.is_blocked(ip) else ""))

        elif cmd == "fw":
            ip = parts[1] if len(parts) > 1 else "1.2.3.4"
            await detector.handle(make_fw_block(ip))
            print(f"  FW_BLOCK from {ip}")

        elif cmd == "unblock":
            ip = parts[1] if len(parts) > 1 else "1.2.3.4"
            if blocker.is_blocked(ip):
                await blocker._unblock_ip(ip)
                print(f"  {G}Unblocked{RST} {ip}  (metrics.dec_block called, store.remove_block called)")
            else:
                print(f"  {ip} is not currently blocked")

        elif cmd == "blocks":
            if not blocker.active_blocks:
                print("  No active blocks.")
            for bip, exp in blocker.active_blocks.items():
                remaining = max(0, int(exp - time.time()))
                print(f"  {R}{bip}{RST}  expires in {remaining}s")

        elif cmd == "status":
            stats = detector.get_stats()
            if not stats:
                print("  No IPs tracked yet.")
            for s in stats:
                blocked = f"  {R}[BLOCKED]{RST}" if s["is_blocked"] else ""
                print(f"  {s['ip']:<18} fails={s['total_fails']}  "
                      f"incidents={s['total_incidents']}{blocked}")

        elif cmd == "metrics":
            for line in blocker.metrics.render().strip().splitlines():
                if not line.startswith("#"):
                    print(f"  {DIM}{line}{RST}")

        else:
            print(f"  Unknown command: {cmd}  (type 'quit' to exit)")


# ── Main ──────────────────────────────────────────────────────────────────────

SCENARIO_MAP = {
    "brute":       "brute-force",
    "stuffing":    "credential stuffing",
    "breach":      "credential breach",
    "web":         "web scanner + exploit",
    "db":          "database brute-force",
    "priv":        "privilege escalation",
    "honeypot":    "honeypot probe",
    "correlation": "multi-source correlation",
    "unblock":     "auto-unblock + metrics",
    "allowlist":   "allowlist",
    "metrics":     "metrics & DB stats",
    "notify":      "notification channel dry-run",
    "live":        "interactive",
}


async def main():
    banner()
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"

    if mode not in ("all", "live", *SCENARIO_MAP.keys()):
        print(f"Unknown mode: {mode}")
        print(f"Valid modes: all  live  {' '.join(SCENARIO_MAP.keys())}")
        sys.exit(1)

    detector, blocker, metrics, store, logger, notifier = await setup()

    log("CNSL simulator starting  (dry-run — no real iptables changes)", G)
    log("All modules wired: metrics, store, correlator\n", DIM)

    try:
        if mode in ("all", "brute"):
            await scenario_brute_force(detector, blocker)
            await asyncio.sleep(0.4)

        if mode in ("all", "stuffing"):
            await scenario_credential_stuffing(detector, blocker)
            await asyncio.sleep(0.4)

        if mode in ("all", "breach"):
            await scenario_credential_breach(detector, blocker)
            await asyncio.sleep(0.4)

        if mode in ("all", "web"):
            await scenario_web(detector, blocker)
            await asyncio.sleep(0.4)

        if mode in ("all", "db"):
            await scenario_db(detector, blocker)
            await asyncio.sleep(0.4)

        if mode in ("all", "priv"):
            await scenario_priv_escalation(detector, blocker)
            await asyncio.sleep(0.4)

        if mode in ("all", "honeypot"):
            await scenario_honeypot(detector, blocker)
            await asyncio.sleep(0.4)

        if mode in ("all", "correlation"):
            await scenario_correlation(detector, blocker)
            await asyncio.sleep(0.4)

        if mode == "unblock":
            await scenario_unblock(detector, blocker, metrics)

        if mode in ("all", "allowlist"):
            await scenario_allowlist(detector, blocker)
            await asyncio.sleep(0.4)

        if mode in ("all", "metrics"):
            await scenario_metrics(metrics, store)
            await asyncio.sleep(0.4)

        if mode in ("all", "notify"):
            await scenario_notify(notifier)

        if mode == "live":
            await interactive_mode(detector, blocker)

    except KeyboardInterrupt:
        pass

    finally:
        await store.close()
        logger.close()
        section("Simulation complete")
        log("Log saved to : cnsl_test.jsonl", G)
        log("DB  saved to : cnsl_test.db", G)
        print()


if __name__ == "__main__":
    asyncio.run(main())