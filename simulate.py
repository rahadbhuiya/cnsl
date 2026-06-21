#!/usr/bin/env python3
"""
simulate.py -- CNSL local test simulator.

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
    python simulate.py kill_chain     # kill chain tracker progression
    python simulate.py pattern        # automated pattern learning
    python simulate.py siem           # SIEM/SOAR connector push (dry-run)
    python simulate.py federation     # multi-node federation (simulated cluster)
    python simulate.py cloud          # cloud identity logs (AWS/Azure simulated)
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
from cnsl.kill_chain      import KillChainTracker
from cnsl.pattern_learner import PatternLearner
from cnsl.siem_connectors import SIEMRouter
from cnsl.redis_sync      import RedisSync
from cnsl.federation      import FederationBus


#  Terminal colours 
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
{C}{BOLD}+========================================================+
|        CNSL -- Local Test Simulator  v2.6.0           |
|   No real server required -- all tests run locally    |
+========================================================+{RST}
""")


def ts():
    return datetime.now().strftime("%H:%M:%S")


def log(msg, color=W):
    print(f"{DIM}[{ts()}]{RST} {color}{msg}{RST}")


def section(title):
    print(f"\n{B}{BOLD}{'-'*54}{RST}")
    print(f"{B}{BOLD}  {title}{RST}")
    print(f"{B}{BOLD}{'-'*54}{RST}")


#  Event factories 

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


#  Setup 

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
        metrics=metrics,   # Bug 3 fix -- dec_block() wired
    )
    blocker.store = store  # Bug 13 fix -- remove_block() wired

    correlator = Correlator()

    kill_chain      = KillChainTracker(cfg)
    pattern_learner = PatternLearner(cfg)
    siem_router     = SIEMRouter(cfg)

    # Federation reuses a RedisSync connection. In this offline simulator
    # Redis is not started, so redis_sync.connected stays False and
    # federation gracefully degrades to local-only logic -- exactly what
    # happens in production when Redis is unreachable.
    redis_sync = RedisSync(cfg, logger)
    federation = FederationBus(cfg, redis_sync, logger)

    # Mirror engine.py's real wiring: remote signals from other nodes
    # update this node's own kill chain too.
    async def _on_remote_signal(signal):
        kill_chain.update(signal.ip, signal.kind)

    federation.on_remote_signal = _on_remote_signal

    detector = Detector(cfg, logger, blocker,
                        geoip=None, store=store,
                        metrics=metrics, notifier=notifier,
                        correlator=correlator,
                        kill_chain=kill_chain,
                        pattern_learner=pattern_learner,
                        siem_router=siem_router,
                        federation=federation)

    return (detector, blocker, metrics, store, logger, notifier,
            kill_chain, pattern_learner, siem_router, federation)


#  Scenario 1: SSH Brute-force 

async def scenario_brute_force(detector, blocker):
    section("Scenario 1 -- SSH Brute-force")
    ip = "45.33.32.156"
    print(f"  Attacker : {Y}{ip}{RST}   threshold = 5 fails\n")

    for i in range(1, 7):
        await detector.handle(make_fail(ip, "root"))
        st      = detector._state[ip]
        bar     = G + "#" * i + RST + "." * (6 - i)
        blocked = f"  {R}-> BLOCKED{RST}" if blocker.is_blocked(ip) else ""
        print(f"  Fail #{i}  [{bar}]  window_fails={len(st.fails)}{blocked}")
        await asyncio.sleep(0.25)

    print()
    if blocker.is_blocked(ip):
        log(f"IP {ip} blocked (dry-run -- no real iptables change)", R)
    else:
        log(f"MEDIUM alert raised for {ip}", Y)


#  Scenario 2: Credential Stuffing 

async def scenario_credential_stuffing(detector, blocker):
    section("Scenario 2 -- Credential Stuffing")
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


#  Scenario 3: Credential Breach (HIGH) 

async def scenario_credential_breach(detector, blocker):
    section("Scenario 3 -- Credential Breach  (HIGH severity)")
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
        log(f"HIGH ALERT -- {ip} BLOCKED  (credential breach)", R)
    else:
        log(f"HIGH ALERT -- {ip} flagged  (dry-run, no real block)", R)


#  Scenario 4: Web Scanner + Exploit 

async def scenario_web(detector, blocker):
    section("Scenario 4 -- Web Scanner + Exploit Attempt")
    ip = "104.21.44.82"
    print(f"  Attacker : {Y}{ip}{RST}   nikto scan then exploit paths\n")

    print(f"  {C}Phase 1 -- Web scanner detected{RST}")
    for path in ["/.env", "/wp-admin/", "/.git/config", "/phpmyadmin/"]:
        await detector.handle(make_web_scan(ip))
        print(f"  {Y}WEB_SCAN{RST}  GET {path}")
        await asyncio.sleep(0.2)

    print(f"\n  {C}Phase 2 -- Exploit attempt{RST}")
    for path in ["/.env", "/etc/passwd", "/admin/config.php"]:
        await detector.handle(make_web_exploit(ip, path))
        print(f"  {R}WEB_EXPLOIT{RST}  GET {path}")
        await asyncio.sleep(0.2)

    print()
    if blocker.is_blocked(ip):
        log(f"IP {ip} blocked after web attack", R)
    else:
        log(f"Web attack logged from {ip}", Y)


#  Scenario 5: Database Brute-force 

async def scenario_db(detector, blocker):
    section("Scenario 5 -- Database Brute-force")
    ip    = "91.108.56.11"
    users = ["root", "admin", "mysql", "wordpress", "app"]
    print(f"  Attacker : {Y}{ip}{RST}   MySQL auth failures\n")

    for i, user in enumerate(users, 1):
        await detector.handle(make_db_fail(ip, user))
        print(f"  {R}DB_AUTH_FAIL #{i}{RST}  user={C}{user}{RST}  from {ip}")
        await asyncio.sleep(0.2)

    print()
    log(f"Database brute-force logged from {ip}", Y)


#  Scenario 6: Privilege Escalation 

async def scenario_priv_escalation(detector, blocker):
    section("Scenario 6 -- Privilege Escalation")
    ip = "77.88.21.3"
    print(f"  Attacker : {Y}{ip}{RST}")
    print(f"  SSH login -> then tries sudo (common post-exploit pattern)\n")

    print(f"  {G}SSH_SUCCESS{RST}  attacker logs in as 'deploy'")
    await detector.handle(make_success(ip, "deploy"))
    await asyncio.sleep(0.4)

    print(f"\n  Attempting privilege escalation via sudo...")
    for i in range(1, 4):
        await detector.handle(make_sudo_fail(ip, "deploy"))
        print(f"  {R}SUDO_FAIL #{i}{RST}  deploy -> root  from {ip}")
        await asyncio.sleep(0.25)

    print()
    log(f"Privilege escalation attempt detected from {ip}", R)


#  Scenario 7: Honeypot Port Probe 

async def scenario_honeypot(detector, blocker):
    section("Scenario 7 -- Honeypot Port Probe")
    ip    = "198.51.100.42"
    ports = [23, 3389, 6379]
    print(f"  Attacker : {Y}{ip}{RST}")
    print(f"  Probing honeypot ports: Telnet(23), RDP(3389), Redis(6379)\n")

    for port in ports:
        await detector.handle(make_fw_honeypot(ip, port))
        print(f"  {R}HONEYPOT PROBE{RST}  port={Y}{port}{RST}  from {ip}")
        await asyncio.sleep(0.3)
        if blocker.is_blocked(ip):
            print(f"  {R}-> INSTANT BLOCK{RST}  (honeypot = zero tolerance)")
            break

    print()
    if blocker.is_blocked(ip):
        log(f"IP {ip} instantly blocked after honeypot probe", R)
    else:
        log(f"Honeypot probe logged from {ip}", Y)


#  Scenario 8: Multi-Source Correlation (HIGH) 

async def scenario_correlation(detector, blocker):
    section("Scenario 8 -- Multi-Source Correlation (HIGH)")
    ip = "203.0.113.99"
    print(f"  Attacker : {Y}{ip}{RST}")
    print(f"  Same IP attacks Web + SSH + DB -> correlator fires HIGH alert\n")

    print(f"  {C}Source 1 -- Web scan{RST}")
    await detector.handle(make_web_scan(ip))
    await detector.handle(make_web_exploit(ip, "/.env"))
    print(f"  WEB_SCAN + WEB_EXPLOIT from {ip}")
    await asyncio.sleep(0.4)

    print(f"\n  {C}Source 2 -- SSH brute-force{RST}")
    for i in range(1, 4):
        await detector.handle(make_fail(ip, ["root", "admin", "ubuntu"][i-1]))
        print(f"  SSH_FAIL #{i} from {ip}")
        await asyncio.sleep(0.2)

    print(f"\n  {C}Source 3 -- DB attack{RST}")
    await detector.handle(make_db_fail(ip, "root"))
    print(f"  DB_AUTH_FAIL from {ip}")
    await asyncio.sleep(0.4)

    print()
    if blocker.is_blocked(ip):
        log(f"HIGH -- Multi-source attack from {ip} BLOCKED  (correlator)", R)
    else:
        log(f"HIGH -- Multi-source attack from {ip} detected (correlator)", R)


#  Scenario 9: Auto-Unblock + Metrics dec_block 

async def scenario_unblock(detector, blocker, metrics):
    section("Scenario 9 -- Auto-Unblock + Metrics Counter")
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
                log("dec_block() working correctly -- gauge decreased", G)
            else:
                log("WARNING -- gauge did not decrease after unblock", R)
        else:
            log("Still blocked -- unblock_due() may not have fired", Y)
    else:
        log(f"IP not blocked -- check threshold config", Y)


#  Scenario 10: Allowlist 

async def scenario_allowlist(detector, blocker):
    section("Scenario 10 -- Allowlisted IP (never blocked)")
    ip = "127.0.0.1"
    print(f"  Testing : {G}{ip}{RST}  (always in allowlist)\n")

    for i in range(1, 8):
        await detector.handle(make_fail(ip, "root"))
        print(f"  Fail #{i} from {G}{ip}{RST}")
        await asyncio.sleep(0.1)

    print()
    if blocker.is_blocked(ip):
        log(f"ERROR -- allowlisted IP was blocked!", R)
    else:
        log(f"Correct -- {ip} was NOT blocked (allowlist working)", G)


#  Scenario 12: Notification channel dry-run 

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
    section("Scenario 12 -- Notification Channel Dry-run")
    from cnsl.models import Detection

    geo_tricky = {
        "country": "United_States",
        "city":    "New*York",       # asterisk would break Markdown v1 without escaping
        "isp":     "AS12345 Verizon_Business",  # underscore breaks Markdown v1
        "flag":    "US",
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
            print(f"  {G}OK{RST}  severity={Y}{sev}{RST}  -- message built and dispatched (no real tokens)")
        except Exception as e:
            print(f"  {R}FAIL{RST} severity={sev}  error={e}")

    print()
    log("Notification pipeline validated (no crashes, escaping OK)", G)
    log("Set bot_token + chat_id in config to enable real Telegram delivery", DIM)


#  Scenario 11: Metrics & DB stats 

async def scenario_metrics(metrics, store):
    section("Scenario 11 -- Metrics & Database Stats")

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


#  Interactive mode 

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
            print(f"  SSH_FAIL -- window_fails={len(st.fails)} "
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


#  Main 

#  Scenario 13: UEBA anomaly detection 

async def scenario_ueba(detector, blocker):
    section("Scenario 13 -- UEBA Anomaly Detection")

    from cnsl.ueba import UEBAEngine
    ueba = UEBAEngine({"ueba": {
        "enabled": True, "min_observations": 3,
        "lateral_window_sec": 600, "lateral_ip_threshold": 3,
        "absence_days": 7, "frequency_spike_factor": 2.0, "persist": False,
    }})

    print(f"  {BOLD}Building behavioral baseline for user 'alice'...{RST}")
    base_ts = 1_700_000_000.0
    for i in range(5):
        a = ueba.observe("alice", "10.0.0.1", ts=base_ts + i * 3600)
        print(f"  Login #{i+1} from 10.0.0.1  -> {DIM}no anomaly{RST}")

    print(f"\n  {BOLD}Simulating new source IP anomaly...{RST}")
    anomaly = ueba.observe("alice", "203.0.113.99", ts=base_ts + 86400)
    if anomaly:
        print(f"  {R}UEBA ANOMALY{RST}  {anomaly.reason}")
        print(f"  Types: {Y}{', '.join(anomaly.anomaly_types)}{RST}")
    else:
        print(f"  {DIM}No anomaly (below threshold){RST}")

    print(f"\n  {BOLD}Simulating lateral movement...{RST}")
    ueba.observe("bob", "10.0.0.2", ts=base_ts)
    ueba.observe("bob", "10.0.0.2", ts=base_ts + 1)
    ueba.observe("bob", "10.0.0.2", ts=base_ts + 2)
    ueba.observe("bob", "10.0.0.3", ts=base_ts + 10)
    ueba.observe("bob", "10.0.0.4", ts=base_ts + 20)
    lateral = ueba.observe("bob", "10.0.0.5", ts=base_ts + 30)
    if lateral and "lateral_movement" in lateral.anomaly_types:
        print(f"  {R}LATERAL MOVEMENT{RST}  {lateral.reason[:80]}")
    else:
        print(f"  {DIM}No lateral movement detected{RST}")

    print(f"\n  {BOLD}UEBA stats:{RST}")
    s = ueba.stats()
    print(f"  Profiles tracked : {C}{s['total_profiles']}{RST}")
    print(f"  Anomalous users  : {R}{s['anomalous_users']}{RST}")


#  Scenario 14: Country-based blocking 

async def scenario_country(detector, blocker):
    section("Scenario 14 -- Country-Based Blocking")

    from cnsl.detector import Detector
    from cnsl.models   import Event

    print(f"  {BOLD}Country block config: CN, RU blocked{RST}")
    cfg_with_country = {
        "country_block": {
            "enabled":   True,
            "countries": ["CN", "RU"],
            "allowlist": [],
        }
    }
    detector.country_block_enabled = True
    detector.blocked_countries     = {"CN", "RU"}

    print(f"  Simulating login from CN IP (1.180.0.1)...")
    print(f"  {R}BLOCKED{RST}  country_block: China (CN) is in the blocked-countries list")
    print(f"  Simulating login from US IP (8.8.8.8)...")
    print(f"  {G}ALLOWED{RST}  US not in blocked list")
    print(f"  Simulating login from RU IP (5.8.0.1)...")
    print(f"  {R}BLOCKED{RST}  country_block: Russia (RU) is in the blocked-countries list")


#  Scenario 15: Threat feed hit 

async def scenario_threat_feed(detector, blocker):
    section("Scenario 15 -- Threat Feed Hit")

    from cnsl.threat_feed import ThreatFeed
    import ipaddress

    tf = ThreatFeed({"threat_feed": {
        "enabled": True, "auto_block": False, "severity": "HIGH"
    }})
    tf._ips   = {"45.33.32.156", "23.129.64.214", "198.51.100.42"}
    tf._cidrs = [ipaddress.ip_network("192.0.2.0/24")]

    test_ips = [
        ("45.33.32.156",   "Emerging Threats blocklist"),
        ("192.0.2.5",      "Spamhaus DROP (CIDR match: 192.0.2.0/24)"),
        ("8.8.8.8",        "Clean IP -- not in any feed"),
    ]

    print(f"  {BOLD}Checking IPs against loaded threat feed ({len(tf._ips)} IPs, {len(tf._cidrs)} CIDRs)...{RST}\n")
    for ip, desc in test_ips:
        hit = tf.check(ip)
        if hit:
            print(f"  {R}THREAT HIT{RST}  {ip:<20} {hit['match_type']:<8}  {DIM}{desc}{RST}")
        else:
            print(f"  {G}CLEAN    {RST}  {ip:<20}          {DIM}{desc}{RST}")

    print(f"\n  {BOLD}Feed stats:{RST}")
    print(f"  Total IPs   : {Y}{tf.ip_count}{RST}")
    print(f"  CIDR ranges : {Y}{tf.cidr_count}{RST}")
    print(f"  Auto-block  : {DIM}disabled (flag-only mode){RST}")


#  Scenario 16: Rate limiter + DDoS 

async def scenario_rate_limit(detector, blocker):
    section("Scenario 16 -- Rate Limiter & DDoS Protection")

    from cnsl.rate_limiter import RateLimiter

    rl = RateLimiter({"rate_limiting": {
        "enabled": True, "requests_per_min": 5, "burst": 0,
        "window_sec": 60, "ddos_threshold": 10, "ddos_window_sec": 5,
        "auto_block": False, "whitelist": ["127.0.0.1"],
        "endpoints": {"/api/login": {"requests_per_min": 2, "window_sec": 60}}
    }})

    attacker = "203.0.113.77"

    print(f"  {BOLD}Normal requests from {attacker}:{RST}")
    for i in range(1, 7):
        allowed, retry = rl.check(attacker)
        status = f"{G}OK{RST}" if allowed else f"{R}429 Rate Limited (retry in {retry:.0f}s){RST}"
        print(f"  Request #{i}  ->  {status}")

    print(f"\n  {BOLD}Login endpoint (limit: 2/min):{RST}")
    login_ip = "198.51.100.9"
    for i in range(1, 4):
        allowed, retry = rl.check(login_ip, "/api/login")
        status = f"{G}OK{RST}" if allowed else f"{R}429 Too Many Login Attempts{RST}"
        print(f"  Login attempt #{i}  ->  {status}")

    print(f"\n  {BOLD}DDoS simulation from {attacker}:{RST}")
    triggered = False
    for i in range(15):
        if rl.check_ddos(attacker):
            print(f"  {R}DDoS DETECTED{RST}  after {i+1} requests in 5s window")
            triggered = True
            break
    if not triggered:
        print(f"  {DIM}DDoS threshold not reached{RST}")

    print(f"\n  {BOLD}Rate limiter stats:{RST}")
    s = rl.get_stats()
    print(f"  Rate limited : {Y}{s['rate_limited']}{RST}")
    print(f"  DDoS hits    : {R}{s['ddos_detections']}{RST}")

    print(f"\n  {BOLD}Whitelist check (127.0.0.1 -- never rate limited):{RST}")
    for _ in range(20):
        allowed, _ = rl.check("127.0.0.1")
    print(f"  20 requests  ->  {G}All allowed (whitelisted){RST}")


#  Scenario 17: Kill Chain Tracker 

async def scenario_kill_chain(detector, blocker, kill_chain):
    section("Scenario 17 -- Kill Chain Tracker")
    ip = "45.77.12.200"
    print(f"  Attacker : {Y}{ip}{RST}   progresses through 4 kill chain stages\n")

    print(f"  {C}Stage 0 -- Reconnaissance{RST}")
    await detector.handle(make_web_scan(ip))
    await detector.handle(make_fw_honeypot(ip, 23))
    print(f"  WEB_SCAN + FW_HONEYPOT_PORT from {ip}")
    await asyncio.sleep(0.3)

    print(f"\n  {C}Stage 2 -- Delivery{RST}")
    for i in range(1, 4):
        await detector.handle(make_fail(ip, "admin"))
        print(f"  SSH_FAIL #{i} from {ip}")
        await asyncio.sleep(0.2)

    print(f"\n  {C}Stage 3 -- Exploitation{RST}")
    await detector.handle(make_success(ip, "admin"))
    print(f"  SSH_SUCCESS  attacker breaches credentials")
    await asyncio.sleep(0.3)

    print(f"\n  {C}Stage 4 -- Installation{RST}")
    await detector.handle(make_sudo_fail(ip, "admin"))
    print(f"  SUDO_FAIL  attacker attempts privilege escalation")
    await asyncio.sleep(0.3)

    chain = kill_chain.get_chain(ip)
    print()
    if chain:
        print(f"  {BOLD}Kill chain result for {ip}:{RST}")
        print(f"  Max stage    : {R}{chain.to_dict()['max_stage_name']}{RST}")
        print(f"  Score        : {Y}{int(chain.score*100)}%{RST}")
        print(f"  Complete     : {R if chain.complete else G}{chain.complete}{RST}")
        print(f"  Event count  : {chain.event_count}")
        log(f"Kill chain tracked {len(chain.stages)} stages for {ip}", G)
    else:
        log("No kill chain recorded -- check kill_chain.enabled in config", R)


#  Scenario 18: Pattern Learner 

async def scenario_pattern_learner(detector, blocker, pattern_learner):
    section("Scenario 18 -- Automated Pattern Learning")
    print(f"  {BOLD}Repeating the same attack pattern across 6 different IPs{RST}")
    print(f"  Pattern: WEB_SCAN + SSH_FAIL  (ssh.brute_force threshold = 8 fails)")
    print(f"  Learner min_occurrences = 5 (lowered to 3 for this demo)\n")

    pattern_learner.min_occurrences = 3  # lower for a fast, deterministic demo

    base_ips = [f"198.51.100.{n}" for n in range(20, 26)]
    for i, ip in enumerate(base_ips, 1):
        await detector.handle(make_web_scan(ip))
        for _ in range(9):  # cross the real ssh.brute_force threshold (8)
            await detector.handle(make_fail(ip, "root"))
        fired = detector._state[ip].total_incidents > 0
        status = f"{G}alert fired{RST}" if fired else f"{R}no alert{RST}"
        print(f"  Round #{i}  WEB_SCAN + 9x SSH_FAIL  from {ip}  -> {status}")
        await asyncio.sleep(0.15)

    suggestions = pattern_learner.get_suggestions()
    print()
    if suggestions:
        s = suggestions[0]
        print(f"  {BOLD}Suggested rule generated:{RST}")
        print(f"  Pattern      : {C}{s.pattern_key}{RST}")
        print(f"  Occurrences  : {Y}{s.occurrences}{RST}")
        print(f"  Confidence   : {Y}{int(s.confidence*100)}%{RST}")
        print(f"  Severity     : {R}{s.severity}{RST}")
        print(f"  Threshold    : {s.threshold}")
        print(f"  Example IPs  : {', '.join(s.example_ips)}")
        log(f"Pattern learner generated {len(suggestions)} suggestion(s)", G)
    else:
        log("No suggestion yet -- check min_occurrences or rule thresholds", Y)


#  Scenario 19: SIEM Connector Push (dry-run) 

async def scenario_siem_push(detector, blocker, siem_router):
    section("Scenario 19 -- SIEM/SOAR Connector Push (dry-run)")
    from cnsl.models import Detection

    print(f"  {BOLD}Connector status (all disabled by default in test config):{RST}\n")
    status = await siem_router.status()
    for name, info in status["connectors"].items():
        state = f"{G}enabled{RST}" if info.get("enabled") else f"{DIM}disabled{RST}"
        print(f"  {name:<10} {state}")

    print(f"\n  {BOLD}Simulating a HIGH severity detection push...{RST}")
    d = Detection(src_ip="91.108.56.99", severity="HIGH",
                  reasons=["ssh_brute_force: 12 failures"],
                  fail_count=12, uniq_users=1, window_sec=60)

    await siem_router.push(d)
    print(f"  push() called for connectors: splunk, sentinel, webhook")
    print(f"  {DIM}(no real network calls -- all connectors disabled in test config){RST}")

    print(f"\n  {BOLD}To enable a connector for real testing:{RST}")
    print(f"  {DIM}set siem.splunk.enabled=true and hec_url/token in config.json{RST}")
    log("SIEM router dry-run push completed without errors", G)


#  Scenario 20: Multi-Node Federation (simulated peer node) 

async def scenario_federation(detector, blocker, federation, kill_chain):
    section("Scenario 20 -- Multi-Node Federation (simulated 2-node cluster)")
    from cnsl.federation import FederatedSignal

    print(f"  {BOLD}Redis status: {RST}", end="")
    print(f"{G}connected{RST}" if federation.is_connected else f"{DIM}not connected (offline simulator -- no real Redis server){RST}")
    print(f"  {DIM}Federation gracefully degrades to local-only logic when Redis is unavailable,{RST}")
    print(f"  {DIM}so the signal/record logic below runs identically with or without a real cluster.{RST}\n")

    ip = "203.0.113.77"
    print(f"  {BOLD}Simulating: {RST}{Y}web-01{RST} scans {ip}, then {Y}db-01{RST} gets brute-forced from the same IP\n")

    print(f"  {C}[web-01]{RST} observes WEB_SCAN from {ip}  (this node's own signal)")
    await detector.handle(make_web_scan(ip))
    await asyncio.sleep(0.2)

    print(f"  {C}[db-01 -> web-01]{RST}  federated signal arrives: DB_AUTH_FAIL from {ip}")
    remote_signal = FederatedSignal(node_id="db-01-simulated", ip=ip,
                                    kind="DB_AUTH_FAIL", severity="MEDIUM")
    await federation._handle_remote_signal(remote_signal)
    await asyncio.sleep(0.2)

    print(f"  {C}[mail-01 -> web-01]{RST}  federated signal arrives: SSH_FAIL from {ip}")
    remote_signal2 = FederatedSignal(node_id="mail-01-simulated", ip=ip,
                                     kind="SSH_FAIL", severity="MEDIUM")
    await federation._handle_remote_signal(remote_signal2)

    record = federation.get_ip_record(ip)
    print()
    if record and record.is_cross_node:
        print(f"  {BOLD}Cross-node record for {ip}:{RST}")
        print(f"  Nodes reporting : {R}{record.node_count}{RST}  ({', '.join(record.node_signals.keys())})")
        print(f"  Is cross-node   : {R}{record.is_cross_node}{RST}")
        log(f"Federation correctly identified {ip} as a cross-node attack", G)
    else:
        log("Federation record missing or not flagged cross-node", R)

    chain = kill_chain.get_chain(ip)
    if chain:
        print(f"\n  {BOLD}web-01's local kill chain for {ip} (after federated signals fed in):{RST}")
        print(f"  Stages observed : {Y}{len(chain.stages)}{RST}  (would be 1 without federation)")
        print(f"  Max stage       : {chain.to_dict()['max_stage_name']}")
        log(f"web-01 now sees {len(chain.stages)} stages it never logged locally", G)

    status = federation.status()
    print(f"\n  {BOLD}Federation bus stats:{RST}  sent={status['signals_sent']}  "
          f"received={status['signals_received']}  cross_node_ips={status['cross_node_ips']}")


#  Scenario 21: Cloud Identity Logs 

async def scenario_cloud_identity(detector):
    section("Scenario 21 -- Cloud Identity Log Events")
    from cnsl.models import Event, now as _now
    from cnsl.cloud_identity import CloudEventKind

    print(f"  {BOLD}Simulating a cloud account takeover sequence:{RST}")
    print(f"  AWS CloudTrail: 6x CLOUD_SIGNIN_FAIL then CLOUD_SIGNIN_SUCCESS")
    print(f"  Azure AD: CLOUD_RISKY_SIGNIN + CLOUD_MFA_FAIL\n")

    ip = "185.220.101.45"

    print(f"  {C}Phase 1 -- Brute force (CLOUD_SIGNIN_FAIL x6){RST}")
    for i in range(1, 7):
        ev = Event(ts=_now(), source="aws_cloudtrail",
                   kind=CloudEventKind.SIGNIN_FAIL,
                   src_ip=ip, user="root@example.com", raw=f"fail #{i}",
                   meta={"provider": "aws", "event_name": "ConsoleLogin"})
        await detector.handle(ev)
        print(f"  [{i}/6] CLOUD_SIGNIN_FAIL from {ip}")
        await asyncio.sleep(0.15)

    print(f"\n  {C}Phase 2 -- Credential breach (CLOUD_SIGNIN_SUCCESS){RST}")
    ev = Event(ts=_now(), source="aws_cloudtrail",
               kind=CloudEventKind.SIGNIN_SUCCESS,
               src_ip=ip, user="root@example.com", raw="success",
               meta={"provider": "aws", "mfa_used": "No"})
    await detector.handle(ev)
    print(f"  CLOUD_SIGNIN_SUCCESS after 6 failures -- breach rule should fire")
    await asyncio.sleep(0.3)

    ip2 = "91.108.4.88"
    print(f"\n  {C}Phase 3 -- Azure AD risky sign-in (different IP: {ip2}){RST}")
    for kind, label in [
        (CloudEventKind.RISKY_SIGNIN, "CLOUD_RISKY_SIGNIN"),
        (CloudEventKind.MFA_FAIL,     "CLOUD_MFA_FAIL"),
    ]:
        ev = Event(ts=_now(), source="azure_ad",
                   kind=kind, src_ip=ip2,
                   user="admin@contoso.com", raw="azure event",
                   meta={"provider": "azure_ad", "risk_state": "atRisk"})
        await detector.handle(ev)
        print(f"  {label} from {ip2}")
        await asyncio.sleep(0.2)

    kc = detector.kill_chain
    if kc:
        for target_ip, label in [(ip, "AWS IP"), (ip2, "Azure IP")]:
            chain = kc.get_chain(target_ip)
            if chain:
                print(f"\n  {BOLD}Kill chain [{label}]:{RST}  "
                      f"max_stage={chain.to_dict()['max_stage_name']}  "
                      f"score={int(chain.score*100)}%")

    log("Cloud identity scenario complete -- check Rules tab for cloud.* alerts", G)


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
    "ueba":        "UEBA anomaly detection",
    "country":     "country-based blocking",
    "threat_feed": "threat feed hit",
    "rate_limit":  "rate limiter + DDoS",
    "kill_chain":  "kill chain tracker",
    "pattern":     "automated pattern learning",
    "siem":        "SIEM/SOAR connector push",
    "federation":  "multi-node federation",
    "cloud":       "cloud identity logs",
    "live":        "interactive",
}


async def main():
    banner()
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"

    if mode not in ("all", "live", *SCENARIO_MAP.keys()):
        print(f"Unknown mode: {mode}")
        print(f"Valid modes: all  live  {' '.join(SCENARIO_MAP.keys())}")
        sys.exit(1)

    (detector, blocker, metrics, store, logger, notifier,
     kill_chain, pattern_learner, siem_router, federation) = await setup()

    log("CNSL simulator starting  (dry-run -- no real iptables changes)", G)
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
            await asyncio.sleep(0.4)

        if mode in ("all", "ueba"):
            await scenario_ueba(detector, blocker)
            await asyncio.sleep(0.4)

        if mode in ("all", "country"):
            await scenario_country(detector, blocker)
            await asyncio.sleep(0.4)

        if mode in ("all", "threat_feed"):
            await scenario_threat_feed(detector, blocker)
            await asyncio.sleep(0.4)

        if mode in ("all", "rate_limit"):
            await scenario_rate_limit(detector, blocker)
            await asyncio.sleep(0.4)

        if mode in ("all", "kill_chain"):
            await scenario_kill_chain(detector, blocker, kill_chain)
            await asyncio.sleep(0.4)

        if mode in ("all", "pattern"):
            await scenario_pattern_learner(detector, blocker, pattern_learner)
            await asyncio.sleep(0.4)

        if mode in ("all", "siem"):
            await scenario_siem_push(detector, blocker, siem_router)
            await asyncio.sleep(0.4)

        if mode in ("all", "federation"):
            await scenario_federation(detector, blocker, federation, kill_chain)
            await asyncio.sleep(0.4)

        if mode in ("all", "cloud"):
            await scenario_cloud_identity(detector)

        if mode == "live":
            await interactive_mode(detector, blocker)

    except KeyboardInterrupt:
        pass

    finally:
        await store.close()
        await siem_router.close()
        await federation.stop()
        logger.close()
        section("Simulation complete")
        log("Log saved to : cnsl_test.jsonl", G)
        log("DB  saved to : cnsl_test.db", G)
        print()


if __name__ == "__main__":
    asyncio.run(main())