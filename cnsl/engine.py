"""
cnsl/engine.py — Main async engine loop + CLI entrypoint.
"""

from __future__ import annotations

import asyncio
import signal
from typing import Any, Dict, List

from .blocker import Blocker, ensure_ipset
from .config import apply_cli_overrides, load_config, safe_int
from .detector import Detector
from .geoip import GeoIP
from .logger import JsonLogger
from .metrics import Metrics
from .models import Event, iso_time, now
from .notify import Notifier
from .sources import run_tcpdump, tail_authlog
from .store import Store


# ---------------------------------------------------------------------------
# Engine loop
# ---------------------------------------------------------------------------

async def engine_loop(
    queue:    asyncio.Queue,
    detector: Detector,
    blocker:  Blocker,
    logger:   JsonLogger,
) -> None:
    await logger.log("startup", {
        "msg":     "CNSL Guard started",
        "time":    iso_time(),
        "dry_run": blocker.dry_run,
    })

    while True:
        try:
            ev: Event = await asyncio.wait_for(queue.get(), timeout=1.0)
            await detector.handle(ev)
        except asyncio.TimeoutError:
            await blocker.unblock_due()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            await logger.log("engine_error", {"error": str(e)})


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser():
    import argparse

    ap = argparse.ArgumentParser(
        prog="cnsl",
        description="CNSL Guard — Cyber Network Security Layer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python -m cnsl                          # dry-run (safe)
  sudo python -m cnsl --execute                # live blocking
  sudo python -m cnsl --execute --backend ipset
  sudo python -m cnsl --dashboard              # open web UI
  sudo python -m cnsl --no-tcpdump             # auth.log only
  sudo python -m cnsl --config /etc/cnsl/config.json
""",
    )

    ap.add_argument("--config",      default=None)
    ap.add_argument("--iface",       default=None)
    ap.add_argument("--authlog",     default=None)
    ap.add_argument("--execute",     action="store_true", help="Enable real blocking")
    ap.add_argument("--no-tcpdump",  action="store_true")
    ap.add_argument("--backend",     choices=["iptables", "ipset"], default=None)
    ap.add_argument("--dashboard",   action="store_true", help="Enable web dashboard")
    ap.add_argument("--api",         action="store_true", help="Enable REST API (legacy)")
    ap.add_argument("--no-geoip",    action="store_true", help="Disable GeoIP lookups")
    ap.add_argument("--no-db",       action="store_true", help="Disable SQLite persistence")
    ap.add_argument("--version",     action="version", version="CNSL Guard 1.0.0")
    return ap


async def _main_async(args: Any, cfg: Dict) -> None:
    log_path = cfg["logging"]["json_log_path"]
    verbose  = bool(cfg["logging"].get("console_verbose", True))
    logger   = JsonLogger(log_path, verbose=verbose)

    allowlist      = set(cfg.get("allowlist", []))
    dry_run        = bool(cfg["actions"].get("dry_run", True))
    block_duration = safe_int(cfg["actions"].get("block_duration_sec"), 900)
    chain          = cfg["actions"].get("chain", "INPUT")
    backend        = args.backend or cfg["actions"].get("block_backend", "iptables")
    ipset_name     = cfg["actions"].get("ipset_name", "cnsl_blocklist")

    blocker = Blocker(
        dry_run=dry_run, backend=backend, chain=chain,
        ipset_name=ipset_name, block_duration_sec=block_duration,
        allowlist=allowlist, logger=logger,
    )

    if backend == "ipset" and not dry_run:
        await ensure_ipset(ipset_name, logger)

    # Optional modules
    geoip    = GeoIP() if not getattr(args, "no_geoip", False) else None
    metrics  = Metrics()
    notifier = Notifier(cfg)

    store = Store(cfg.get("store", {}).get("db_path", "./cnsl_state.db"))
    if not getattr(args, "no_db", False):
        ok = await store.init()
        if not ok:
            await logger.log("store_warning", {"msg": "SQLite unavailable (install aiosqlite). Running without persistence."})
    
    detector = Detector(cfg, logger, blocker,
                        geoip=geoip, store=store,
                        metrics=metrics, notifier=notifier)

    queue: asyncio.Queue = asyncio.Queue()
    tasks: List[asyncio.Task] = []

    tasks.append(asyncio.create_task(
        engine_loop(queue, detector, blocker, logger), name="engine"
    ))

    authlog_path = cfg.get("authlog_path", "/var/log/auth.log")
    tasks.append(asyncio.create_task(
        tail_authlog(queue, authlog_path, logger), name="authlog"
    ))

    if cfg.get("tcpdump_enabled", True):
        iface = cfg.get("iface", "any")
        bpf   = cfg.get("tcpdump_bpf", "")
        tasks.append(asyncio.create_task(
            run_tcpdump(queue, iface, bpf, logger), name="tcpdump"
        ))

    # Dashboard (includes API + SSE + metrics + manual block/unblock)
    use_dashboard = getattr(args, "dashboard", False) or cfg.get("dashboard", {}).get("enabled", False)
    if use_dashboard:
        from .dashboard import start_dashboard
        dash_cfg  = cfg.get("dashboard", {})
        dash_host = dash_cfg.get("host", "127.0.0.1")
        dash_port = safe_int(dash_cfg.get("port"), 8765)
        tasks.append(asyncio.create_task(
            start_dashboard(dash_host, dash_port, detector, blocker,
                            store, metrics, logger, dry_run=dry_run),
            name="dashboard",
        ))

    # Graceful shutdown
    stop = asyncio.Event()

    def _handle_sig(*_):
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_sig)
        except NotImplementedError:
            signal.signal(sig, lambda s, f: stop.set())

    print("", flush=True)
    print("╔═══════════════════════════════════════════╗")
    print("║  CNSL Guard — Cyber Network Security Layer ║")
    print("╠═══════════════════════════════════════════╣")
    print(f"║  Auth log  : {authlog_path:<28} ║")
    print(f"║  Mode      : {'DRY-RUN (planning only)' if dry_run else 'LIVE BLOCKING ENABLED':<28} ║")
    print(f"║  Backend   : {backend:<28} ║")
    print(f"║  GeoIP     : {'enabled' if geoip else 'disabled':<28} ║")
    print(f"║  Database  : {'enabled (SQLite)' if store.available else 'disabled':<28} ║")
    print(f"║  Dashboard : {'http://127.0.0.1:8765' if use_dashboard else 'disabled':<28} ║")
    print("╚═══════════════════════════════════════════╝")
    print("  Press Ctrl+C to stop.\n", flush=True)

    await stop.wait()
    await logger.log("shutdown", {"msg": "Stopping CNSL Guard"})
    await store.close()
    logger.close()

    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


def main() -> None:
    ap = build_arg_parser()
    args = ap.parse_args()
    cfg = load_config(args.config)
    apply_cli_overrides(
        cfg,
        execute=args.execute,
        no_tcpdump=args.no_tcpdump,
        iface=args.iface,
        authlog=args.authlog,
        api=args.api or args.dashboard,
    )
    if args.backend:
        cfg["actions"]["block_backend"] = args.backend

    try:
        asyncio.run(_main_async(args, cfg))
    except KeyboardInterrupt:
        pass