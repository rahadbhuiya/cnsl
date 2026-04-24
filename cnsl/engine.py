"""
cnsl/engine.py — Main async engine loop + CLI entrypoint.
"""

from __future__ import annotations

import asyncio
import signal
from typing import Any, Dict, List

from .assets       import AssetInventory
from .auth         import AuthManager
from .grafana      import export_dashboard
from .honeypot     import ActiveResponse, FakeSSHServer
from .rbac         import RBAC, Perm
from .fim          import FIMEngine
from .ml_detector  import MLDetector
from .reporter     import Reporter
from .correlator   import Correlator
from .log_sources  import get_log_tasks
from .redis_sync   import RedisSync
from .threat_intel import AbuseIPDB, BehavioralBaseline
from .blocker   import Blocker, ensure_ipset
from .config import apply_cli_overrides, load_config, safe_int
from .detector import Detector
from .geoip     import GeoIP
from .validator import validate_and_exit
from .logger import JsonLogger
from .metrics import Metrics
from .models import Event, iso_time, now
from .notify import Notifier
from .sources import run_tcpdump, tail_authlog
from .store import Store



# Engine loop


async def engine_loop(
    queue:       asyncio.Queue,
    detector:    Detector,
    blocker:     Blocker,
    logger:      JsonLogger,
    ml_detector: "MLDetector | None" = None,
) -> None:
    await logger.log("startup", {
        "msg":     "CNSL started",
        "time":    iso_time(),
        "dry_run": blocker.dry_run,
    })

    while True:
        try:
            ev: Event = await asyncio.wait_for(queue.get(), timeout=1.0)
            await detector.handle(ev)
            if ml_detector.enabled:
                try:
                    await ml_detector.ingest(ev)
                except Exception:
                    pass
        except asyncio.TimeoutError:
            await blocker.unblock_due()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            await logger.log("engine_error", {"error": str(e)})



# CLI


def build_arg_parser():
    import argparse

    ap = argparse.ArgumentParser(
        prog="cnsl",
        description="CNSL — Cyber Network Security Layer",
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
    ap.add_argument("--version",     action="version", version="CNSL 1.0.0")
    ap.add_argument("--report",       default=None,
                    choices=["html","pdf","json"],
                    help="Generate a report and exit")
    ap.add_argument("--grafana-export", action="store_true",
                    help="Export Grafana dashboard JSON and exit")
    ap.add_argument("--report-days",  type=int, default=30,
                    help="Report period in days (default: 30)")
    return ap


async def _main_async(args: Any, cfg: Dict) -> None:
    validate_and_exit(cfg)

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

    auth = AuthManager(cfg)

    # Optional modules
    geoip    = GeoIP(cfg) if not (getattr(args, "no_geoip", False) or cfg.get("_no_geoip")) else None
    metrics  = Metrics()
    notifier = Notifier(cfg)
    blocker.metrics = metrics  # wire in so dec_block() is called on unblock

    correlator = Correlator()
    abuseipdb  = AbuseIPDB(cfg)
    baseline   = BehavioralBaseline(cfg)

    redis_sync      = RedisSync(cfg, logger)
    rbac            = RBAC()
    active_response = ActiveResponse(cfg, logger)
    asset_inventory = AssetInventory(cfg)
    asset_inventory.set_allowlist(list(allowlist))
    fim_engine      = FIMEngine(cfg, logger)
    ml_detector = MLDetector(cfg, logger)
    if cfg.get("redis", {}).get("enabled"):
        await redis_sync.connect()

    store    = Store(cfg.get("store", {}).get("db_path", "./cnsl_state.db"))
    blocker.store = store      # wire in so remove_block() is called on unblock
    reporter = Reporter(store=store, fim=fim_engine, cfg=cfg)
    if not (getattr(args, "no_db", False) or cfg.get("_no_db")):
        ok = await store.init()
        if not ok:
            await logger.log("store_warning", {"msg": "SQLite unavailable (install aiosqlite). Running without persistence."})
    
    detector = Detector(cfg, logger, blocker,
                        geoip=geoip,     store=store,
                        metrics=metrics,  notifier=notifier,
                        correlator=correlator, abuseipdb=abuseipdb,
                        baseline=baseline, redis_sync=redis_sync)

    # Patch engine loop to update asset inventory on every event
    _orig_handle = detector.handle
    async def _handle_with_assets(ev):
        if ev.src_ip:
            asset_inventory.ingest_auth_event(
                ip=ev.src_ip, kind=ev.kind, user=ev.user,
                geo=detector.geoip.get_cached(ev.src_ip) if detector.geoip else None
            )
        await _orig_handle(ev)
    detector.handle = _handle_with_assets

    queue_size = safe_int(cfg.get('queue', {}).get('maxsize', 10000), 10000)
    queue: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
    tasks: List[asyncio.Task] = []

    tasks.append(asyncio.create_task(
        engine_loop(queue, detector, blocker, logger, ml_detector=ml_detector), name="engine"
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

    # Phase 4: Honeypot / active response
    if active_response.enabled:
        async def _on_hp_session(session):
            asset_inventory.mark_known(session.attacker_ip)
            await logger.log("honeypot_session_complete", session.to_dict())
        await active_response.start_honeypot(on_session=_on_hp_session)

    # Phase 3: File Integrity Monitoring
    await fim_engine.initialize()
    if fim_engine.enabled:
        tasks.append(asyncio.create_task(fim_engine.start(), name="fim"))

        # Wire FIM alerts to notifier
        async def _on_fim_alert(alert):
            from .notify import _build_message
            from .models import Detection, Severity
            d = Detection(src_ip="localhost", severity=alert.severity if alert.severity != "CRITICAL" else Severity.HIGH,
                         reasons=[f"FIM {alert.change}: {alert.path}"],
                         fail_count=0, uniq_users=0, window_sec=0)
            if notifier:
                await notifier.send(d, None)
        fim_engine.on_alert = _on_fim_alert

    # Phase 3: ML anomaly detection
    if ml_detector.enabled:
        await logger.log("ml_started", ml_detector.status())

    # Multi-log sources (nginx, apache, mysql, ufw, syslog)
    tasks.extend(get_log_tasks(cfg, queue, logger))

    # Redis distributed sync
    if redis_sync.connected:
        tasks.append(asyncio.create_task(redis_sync.subscribe_loop(), name="redis_sub"))
        tasks.append(asyncio.create_task(redis_sync.heartbeat_loop(), name="redis_hb"))
        # When a remote block comes in, apply it locally too
        async def _on_remote_block(ip, reason, ttl):
            await blocker.block_ip(ip, reason=f"remote:{reason}")
        redis_sync.on_remote_block = _on_remote_block
        # When a remote unblock comes in, remove it locally too
        async def _on_remote_unblock(ip):
            await blocker._unblock_ip(ip)
        redis_sync.on_remote_unblock = _on_remote_unblock
        # When we unblock locally, propagate to the cluster
        async def _on_local_unblock(ip):
            await redis_sync.publish_unblock(ip)
        blocker.on_unblock = _on_local_unblock

    # Dashboard (includes API + SSE + metrics + manual block/unblock)
    use_dashboard = getattr(args, "dashboard", False) or cfg.get("dashboard", {}).get("enabled", False)
    if use_dashboard:
        from .dashboard import start_dashboard
        dash_cfg  = cfg.get("dashboard", {})
        dash_host = dash_cfg.get("host", "127.0.0.1")
        dash_port = safe_int(dash_cfg.get("port"), 8765)
        tasks.append(asyncio.create_task(
            start_dashboard(dash_host, dash_port, detector, blocker,
                            store, metrics, logger, auth=auth,
                            rbac=rbac, assets=asset_inventory,
                            honeypot=active_response, dry_run=dry_run),
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
    print("║  CNSL — Correlated Network Security Layer ║")
    print("╠═══════════════════════════════════════════╣")
    print(f"║  Auth log  : {authlog_path:<28} ║")
    print(f"║  Mode      : {'DRY-RUN (planning only)' if dry_run else 'LIVE BLOCKING ENABLED':<28} ║")
    print(f"║  Backend   : {backend:<28} ║")
    print(f"║  GeoIP     : {'enabled ('+geoip.backend+')' if geoip else 'disabled':<28} ║")
    print(f"║  Redis     : {'enabled (node:'+redis_sync.node_id+')' if redis_sync.connected else 'disabled':<28} ║")
    print(f"║  AbuseIPDB : {'enabled' if abuseipdb.enabled else 'disabled':<28} ║")
    print(f"║  FIM       : {'enabled' if fim_engine.enabled else 'disabled':<28} ║")
    print(f"║  ML detect : {'enabled' if ml_detector.enabled else 'disabled':<28} ║")
    print(f"║  Honeypot  : {active_response.mode if active_response.enabled else 'disabled':<28} ║")
    print(f"║  Assets    : {'tracking' if asset_inventory.enabled else 'disabled':<28} ║")
    print(f"║  Database  : {'enabled (SQLite)' if store.available else 'disabled':<28} ║")
    print(f"║  Dashboard : {'http://127.0.0.1:8765' if use_dashboard else 'disabled':<28} ║")
    print("╚═══════════════════════════════════════════╝")
    print("  Press Ctrl+C to stop.\n", flush=True)

    await stop.wait()
    await logger.log("shutdown", {"msg": "Stopping CNSL"})
    fim_engine.close()
    await redis_sync.close()
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

    # Grafana export mode
    if getattr(args, 'grafana_export', False):
        path = export_dashboard()
        print(f"Grafana dashboard exported to: {path}")
        print("Import in Grafana: Dashboards → Import → Upload JSON file")
        return

    # Report-only mode
    if getattr(args, 'report', None):
        async def _report_only():
            from .store    import Store
            from .fim      import FIMEngine
            from .reporter import Reporter
            s = Store(cfg.get('store',{}).get('db_path','./cnsl_state.db'))
            await s.init()
            r = Reporter(store=s, cfg=cfg)
            path = await r.generate(format=args.report, period_days=args.report_days)
            print(f"Report saved to: {path}")
            await s.close()
        asyncio.run(_report_only())
        return

    try:
        asyncio.run(_main_async(args, cfg))
    except KeyboardInterrupt:
        pass