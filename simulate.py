#!/usr/bin/env python3
"""
simulate.py — CNSL local test simulator.

CNSL can be tested without a real server or real attacks.
It generates fake auth.log events to demonstrate all features of CNSL.

Usage:
    python simulate.py            # full demo (all scenarios)
    python simulate.py brute      # only brute-force
    python simulate.py breach     # only credential breach
    python simulate.py stuffing   # only credential stuffing
    python simulate.py live       # interactive — type events manually
"""

import sys
import time
import asyncio
from datetime import datetime

# ── CNSL imports ────────────────────────────────────────────────────────────
sys.path.insert(0, ".")
from cnsl.models    import Event, EventKind, now
from cnsl.config    import load_config
from cnsl.logger    import JsonLogger
from cnsl.blocker   import Blocker
from cnsl.detector  import Detector
from cnsl.metrics   import Metrics
from cnsl.notify    import Notifier
from cnsl.store     import Store


# ── Colors for terminal output ──────────────────────────────────────────────
R  = "\033[91m"   # red
Y  = "\033[93m"   # yellow
G  = "\033[92m"   # green
B  = "\033[94m"   # blue
C  = "\033[96m"   # cyan
W  = "\033[97m"   # white
DIM= "\033[2m"
RST= "\033[0m"
BOLD="\033[1m"


def banner():
    print(f"""
{C}{BOLD}╔══════════════════════════════════════════════════╗
║       CNSL — Local Test Simulator                ║
║  No real server required — all tests run locally ║
╚══════════════════════════════════════════════════╝{RST}
""")


def ts():
    return datetime.now().strftime("%H:%M:%S")


def log(msg, color=W):
    print(f"{DIM}[{ts()}]{RST} {color}{msg}{RST}")


def section(title):
    print(f"\n{B}{BOLD}{'─'*50}{RST}")
    print(f"{B}{BOLD}  {title}{RST}")
    print(f"{B}{BOLD}{'─'*50}{RST}")


def make_fail(ip, user="root"):
    return Event(
        ts=now(), source="auth", kind=EventKind.SSH_FAIL,
        src_ip=ip, user=user,
        raw=f"sshd[1234]: Failed password for {user} from {ip} port 22 ssh2"
    )


def make_success(ip, user="root"):
    return Event(
        ts=now(), source="auth", kind=EventKind.SSH_SUCCESS,
        src_ip=ip, user=user,
        raw=f"sshd[1234]: Accepted password for {user} from {ip} port 22 ssh2"
    )


async def setup():
    """Create a test CNSL instance (dry-run, no real blocking)."""
    cfg = load_config(None)
    cfg["thresholds"]["fails_threshold"]              = 5
    cfg["thresholds"]["unique_users_threshold"]       = 3
    cfg["thresholds"]["success_after_fails_threshold"]= 3
    cfg["thresholds"]["fails_window_sec"]             = 60
    cfg["thresholds"]["incident_cooldown_sec"]        = 5
    cfg["actions"]["dry_run"] = True
    cfg["logging"]["console_verbose"] = False   # we print our own output

    logger   = JsonLogger("./cnsl_test.jsonl", verbose=False)
    blocker  = Blocker(dry_run=True, backend="iptables", chain="INPUT",
                       ipset_name="cnsl_test", block_duration_sec=60,
                       allowlist={"127.0.0.1"}, logger=logger)
    metrics  = Metrics()
    notifier = Notifier(cfg)
    store    = Store("./cnsl_test.db")
    await store.init()

    detector = Detector(cfg, logger, blocker,
                        geoip=None, store=store,
                        metrics=metrics, notifier=notifier)
    return detector, blocker, metrics, store, logger


# ── Scenario 1: Brute-force ─────────────────────────────────────────────────

async def scenario_brute_force(detector, blocker):
    section("Scenario 1 — Brute-force attack")
    print(f"  Attacker IP: {Y}45.33.32.156{RST} (iptables threshold = 5 fails)")
    print(f"  Sending 6 SSH failures in a row...\n")

    ip = "45.33.32.156"
    for i in range(1, 7):
        ev = make_fail(ip, user="root")
        await detector.handle(ev)
        st = detector._state[ip]
        bar = G + "█" * i + RST + "░" * (6 - i)
        blocked = f"{R}  BLOCKED!{RST}" if blocker.is_blocked(ip) else ""
        print(f"  Fail #{i}  [{bar}]  window_fails={len(st.fails)}{blocked}")
        await asyncio.sleep(0.3)

    print()
    if blocker.is_blocked(ip):
        log(f"CNSL blocked {ip} (dry-run — no real iptables)", R)
    else:
        log(f"CNSL logged MEDIUM alert for {ip}", Y)


# ── Scenario 2: Credential stuffing ─────────────────────────────────────────

async def scenario_credential_stuffing(detector, blocker):
    section("Scenario 2 — Credential stuffing")
    print(f"  Attacker IP: {Y}185.220.101.45{RST}")
    print(f"  Tries many different usernames (stolen username list)...\n")

    ip = "185.220.101.45"
    users = ["admin", "ubuntu", "pi", "deploy", "git", "postgres"]
    for i, user in enumerate(users, 1):
        ev = make_fail(ip, user=user)
        await detector.handle(ev)
        st = detector._state[ip]
        uniq = len({u for _, u in st.users if u})
        print(f"  Try #{i}  user={C}{user:<10}{RST}  unique_users={Y}{uniq}{RST}")
        await asyncio.sleep(0.25)

    print()
    log(f"Credential stuffing detected from {ip}", Y)


# ── Scenario 3: Credential breach (HIGH) ────────────────────────────────────

async def scenario_credential_breach(detector, blocker):
    section("Scenario 3 — Credential breach  (HIGH severity)")
    print(f"  Attacker IP: {Y}23.129.64.214{RST}")
    print(f"  Fails 4 times, then SUCCEEDS (stolen password used)...\n")

    ip = "23.129.64.214"
    for i in range(1, 5):
        ev = make_fail(ip, user="admin")
        await detector.handle(ev)
        print(f"  {R}FAIL #{i}{RST}  from {ip}")
        await asyncio.sleep(0.3)

    print(f"\n  {G}{BOLD}SUCCESS!{RST}  Attacker logs in with correct password")
    await asyncio.sleep(0.5)
    ev = make_success(ip, user="admin")
    await detector.handle(ev)
    await asyncio.sleep(0.5)

    print()
    if blocker.is_blocked(ip):
        log(f"HIGH ALERT — {ip} BLOCKED! (credential breach detected)", R)
    else:
        log(f"HIGH ALERT — {ip} flagged (dry-run mode, no real block)", R)


# ── Scenario 4: Allowlisted IP ──────────────────────────────────────────────

async def scenario_allowlist(detector, blocker):
    section("Scenario 4 — Allowlisted IP (never blocked)")
    print(f"  Testing with {G}127.0.0.1{RST} (always in allowlist)...\n")

    ip = "127.0.0.1"
    for i in range(1, 8):
        ev = make_fail(ip, user="root")
        await detector.handle(ev)
        print(f"  Fail #{i} from {G}{ip}{RST}")
        await asyncio.sleep(0.15)

    print()
    if blocker.is_blocked(ip):
        log(f"ERROR — allowlisted IP was blocked!", R)
    else:
        log(f"Correct — {ip} was NOT blocked (allowlist working)", G)


# ── Scenario 5: Metrics summary ─────────────────────────────────────────────

async def scenario_metrics(metrics, store):
    section("Scenario 5 — Metrics & stats summary")

    db_stats = await store.stats()
    incidents = await store.recent_incidents(limit=10)

    print(f"  {BOLD}Prometheus metrics:{RST}")
    print(metrics.render())

    print(f"\n  {BOLD}Database stats:{RST}")
    print(f"  Total incidents : {Y}{db_stats.get('total', 0)}{RST}")
    print(f"  HIGH severity   : {R}{db_stats.get('high', 0)}{RST}")
    print(f"  MEDIUM severity : {Y}{db_stats.get('medium', 0)}{RST}")
    print(f"  Unique IPs      : {C}{db_stats.get('unique_ips', 0)}{RST}")

    if incidents:
        print(f"\n  {BOLD}Recent incidents:{RST}")
        for inc in incidents[-5:]:
            sev_color = R if inc['severity'] == 'HIGH' else Y
            print(f"  {sev_color}{inc['severity']:<8}{RST}  {inc['src_ip']:<18}  {inc['time']}")


# ── Interactive mode ─────────────────────────────────────────────────────────

async def interactive_mode(detector, blocker):
    section("Interactive Mode")
    print("  Commands:")
    print(f"  {G}fail <ip> [user]{RST}     — simulate SSH failure")
    print(f"  {G}ok   <ip> [user]{RST}     — simulate SSH success")
    print(f"  {G}status{RST}               — show tracked IPs")
    print(f"  {G}blocks{RST}               — show active blocks")
    print(f"  {G}quit{RST}                 — exit\n")

    while True:
        try:
            line = input(f"{C}cnsl>{RST} ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not line:
            continue

        parts = line.split()
        cmd = parts[0].lower()

        if cmd in ("quit", "exit", "q"):
            break

        elif cmd == "fail":
            ip   = parts[1] if len(parts) > 1 else "1.2.3.4"
            user = parts[2] if len(parts) > 2 else "root"
            await detector.handle(make_fail(ip, user))
            st = detector._state[ip]
            print(f"  fail recorded — window_fails={len(st.fails)} unique_users={len({u for _,u in st.users if u})}")

        elif cmd == "ok":
            ip   = parts[1] if len(parts) > 1 else "1.2.3.4"
            user = parts[2] if len(parts) > 2 else "root"
            await detector.handle(make_success(ip, user))
            print(f"  success recorded for {ip}")

        elif cmd == "status":
            stats = detector.get_stats()
            if not stats:
                print("  No IPs tracked yet.")
            for s in stats:
                blocked = f"{R}[BLOCKED]{RST}" if s['is_blocked'] else ""
                print(f"  {s['ip']:<18} fails={s['total_fails']}  incidents={s['total_incidents']} {blocked}")

        elif cmd == "blocks":
            if not blocker.active_blocks:
                print("  No active blocks.")
            for ip, exp in blocker.active_blocks.items():
                remaining = max(0, int(exp - time.time()))
                print(f"  {R}{ip}{RST}  expires in {remaining}s")

        else:
            print(f"  Unknown command: {cmd}")


# ── Main ─────────────────────────────────────────────────────────────────────

async def main():
    banner()
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    detector, blocker, metrics, store, logger = await setup()

    log("CNSL simulator starting (dry-run mode)...", G)
    log("All blocking is simulated — no real iptables changes\n", DIM)

    try:
        if mode in ("all", "brute"):
            await scenario_brute_force(detector, blocker)
            await asyncio.sleep(0.5)

        if mode in ("all", "stuffing"):
            await scenario_credential_stuffing(detector, blocker)
            await asyncio.sleep(0.5)

        if mode in ("all", "breach"):
            await scenario_credential_breach(detector, blocker)
            await asyncio.sleep(0.5)

        if mode in ("all", "allowlist"):
            await scenario_allowlist(detector, blocker)
            await asyncio.sleep(0.5)

        if mode in ("all", "metrics"):
            await scenario_metrics(metrics, store)

        if mode == "live":
            await interactive_mode(detector, blocker)

    except KeyboardInterrupt:
        pass

    finally:
        await store.close()
        logger.close()
        section("Simulation complete")
        log("Log saved to: cnsl_test.jsonl", G)
        log("DB  saved to: cnsl_test.db", G)
        print()


if __name__ == "__main__":
    asyncio.run(main())