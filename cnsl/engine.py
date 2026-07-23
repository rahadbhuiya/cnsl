"""
cnsl/engine.py — Main async engine loop + CLI entrypoint.
"""

from __future__ import annotations

import asyncio
import signal
from typing import Any, Dict, List

from .assets          import AssetInventory
from .auth            import AuthManager
from .grafana         import export_dashboard
from .honeypot        import ActiveResponse, FakeSSHServer
from .rbac            import RBAC, Perm
from .fim             import FIMEngine
from .ml_detector     import MLDetector
from .reporter        import Reporter
from .correlator      import Correlator
from .log_sources     import get_log_tasks
from .redis_sync      import RedisSync
from .threat_intel    import AbuseIPDB, BehavioralBaseline
from .blocker         import Blocker, ensure_ipset
from .config          import apply_cli_overrides, load_config, safe_int
from .detector        import Detector
from .geoip           import GeoIP
from .validator       import validate_and_exit, validate_and_print
from .logger          import JsonLogger
from .metrics         import Metrics
from .models          import Event, iso_time, now
from .notify          import Notifier
from .sources         import run_tcpdump, tail_authlog
from .store           import Store
from .cases           import CaseManager
from .audit            import AuditLog
from .threat_feed     import ThreatFeed
from .ueba            import UEBAEngine
from .kafka_consumer  import KafkaConsumer
from .tenants         import TenantManager
from .rate_limiter    import RateLimiter
from .huddle_integration import HuddleManager
from .search_engine   import SearchEngine, ElasticsearchPusher
from .syslog_receiver import SyslogReceiver
from .kill_chain      import KillChainTracker
from .pattern_learner import PatternLearner
from .siem_connectors import SIEMRouter
from .federation      import FederationBus
from .cloud_identity  import CloudIdentityPoller
from .zero_trust      import ZeroTrustEngine



# Engine loop


async def engine_loop(
    queue:          asyncio.Queue,
    detector:       Detector,
    blocker:        Blocker,
    logger:         JsonLogger,
    ml_detector:    "MLDetector | None"    = None,
    pattern_learner: "PatternLearner | None" = None,
) -> None:
    from .normalizer import normalize as _normalize

    await logger.log("startup", {
        "msg":     "CNSL started",
        "time":    iso_time(),
        "dry_run": blocker.dry_run,
    })

    while True:
        try:
            ev: Event = await asyncio.wait_for(queue.get(), timeout=1.0)

            # Normalize to ECS schema — attached to event meta for downstream use
            try:
                norm = _normalize(ev)
                ev.meta["_ecs"] = norm.to_dict()
            except Exception:
                pass  # normalization failure must never stop detection

            await detector.handle(ev)
            if ml_detector and ml_detector.enabled:
                try:
                    ml_alert = await ml_detector.ingest(ev)
                    if ml_alert and pattern_learner:
                        try:
                            pattern_learner.on_ml_anomaly(
                                ml_alert.ip, ml_alert.top_reasons
                            )
                        except Exception:
                            pass
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
    ap.add_argument("--version",     action="version", version="CNSL 3.4.4")
    ap.add_argument("--report",       default=None,
                    choices=["html","pdf","json"],
                    help="Generate a report and exit")
    ap.add_argument("--grafana-export", action="store_true",
                    help="Export Grafana dashboard JSON and exit")
    ap.add_argument("--report-days",  type=int, default=30,
                    help="Report period in days (default: 30)")
    # v2.1.1 flags
    ap.add_argument("--tenant",        default=None, metavar="ID",
                    help="Run as a specific tenant (multi-tenant mode)")
    ap.add_argument("--no-kafka",      action="store_true",
                    help="Disable Kafka ingestion even if enabled in config")
    ap.add_argument("--no-rate-limit", action="store_true",
                    help="Disable rate limiting even if enabled in config")
    ap.add_argument("--agent-mode",    action="store_true",
                    help="Run as a log-forwarding agent (shortcut for: python -m cnsl.agent)")
    ap.add_argument("--status",        action="store_true",
                    help="Show running status and block counts, then exit")
    ap.add_argument("--init",          action="store_true",
                    help="Interactive setup wizard — create /etc/cnsl/config.json")
    ap.add_argument("--check-update",     action="store_true",
                    help="Check if a newer version is available on PyPI")
    ap.add_argument("--validate-config",  action="store_true",
                    help="Validate config file and print all errors/warnings, then exit")
    ap.add_argument("--backup",        default=None, metavar="PATH",
                    help="Back up config + store DB + FIM baseline to PATH (tar.gz), then exit")
    ap.add_argument("--restore",       default=None, metavar="PATH",
                    help="Restore config + store DB + FIM baseline from a backup PATH, then exit")
    ap.add_argument("--force",         action="store_true",
                    help="With --restore, overwrite existing files without prompting")
    ap.add_argument("--migrate-db",    default=None, metavar="POSTGRES_DSN",
                    help="Migrate incidents+blocks from the configured SQLite DB "
                         "to this PostgreSQL DSN, then exit")
    ap.add_argument("--sqlite-path",   default=None, metavar="PATH",
                    help="With --migrate-db, override the source SQLite DB path "
                         "(default: store.db_path from config)")
    ap.add_argument("--migrate-batch-size", type=int, default=500, metavar="N",
                    help="With --migrate-db, rows per batch (default: 500)")
    ap.add_argument("--migrate-dry-run", action="store_true",
                    help="With --migrate-db, only report row counts -- write nothing")
    ap.add_argument("--migrate-truncate-target", action="store_true",
                    help="With --migrate-db, TRUNCATE the target tables first "
                         "for a clean one-shot copy (default: append/upsert)")
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
    notifier.start()  # start daily digest background task
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

    # Federation bus -- shares detection signals over the redis_sync connection
    federation = FederationBus(cfg, redis_sync, logger)

    # Cloud identity poller -- AWS CloudTrail + Azure AD
    cloud_identity = CloudIdentityPoller(cfg)

    # Zero-trust engine -- per-entity trust scoring
    zero_trust = ZeroTrustEngine(cfg)
    if store.available:
        await zero_trust.load_all(store)

    # Handle --agent-mode shortcut (before anything else)
    if getattr(args, "agent_mode", False):
        from .agent import run_agent, load_agent_config
        agent_cfg = load_agent_config(args.config)
        await run_agent(agent_cfg)
        return

    # Apply --no-kafka / --no-rate-limit overrides
    if getattr(args, "no_kafka", False):
        cfg.setdefault("kafka", {})["enabled"] = False
    if getattr(args, "no_rate_limit", False):
        cfg.setdefault("rate_limiting", {})["enabled"] = False

    store    = Store(cfg)  # accepts full cfg; reads store.backend + store.dsn
    blocker.store = store      # wire in so remove_block() is called on unblock
    if not (getattr(args, "no_db", False) or cfg.get("_no_db")):
        ok = await store.init()
        if not ok:
            await logger.log("store_warning", {"msg": "SQLite unavailable (install aiosqlite). Running without persistence."})

    # Case management
    case_manager = CaseManager(store)
    if store.available:
        await case_manager.init()

    # Compliance audit trail (manual block/unblock, secret rotation, etc.)
    audit_log = AuditLog(store)
    if store.available:
        await audit_log.init()

    # Community threat feed
    threat_feed = ThreatFeed(cfg)
    if threat_feed.enabled:
        await threat_feed.start()

    # UEBA engine
    ueba = UEBAEngine(cfg, store)
    if ueba.enabled:
        await ueba.init()

    # Kill chain tracker + pattern learner -- load in parallel from SQLite
    kill_chain_tracker = KillChainTracker(cfg)
    pattern_learner    = PatternLearner(cfg)
    if store.available:
        await asyncio.gather(
            kill_chain_tracker.load_all(store),
            pattern_learner.load_all(store),
        )

    # SIEM/SOAR connectors
    siem_router = SIEMRouter(cfg)
    # Wire federation: remote signals from other nodes update this node's
    # kill chain too, so each node sees the attacker's full cross-node path
    async def _on_remote_signal(signal):
        try:
            kill_chain_tracker.update(signal.ip, signal.kind)
        except Exception:
            pass

    federation.on_remote_signal = _on_remote_signal

    # Tenant manager
    tenant_manager = TenantManager(cfg)

    # Rate limiter (uses Redis for distributed counting when available)
    rate_limiter = RateLimiter(cfg, redis_sync=redis_sync)

    # HuddleCluster integration (multi-node load balancing)
    huddle = HuddleManager(cfg, metrics=metrics, logger=logger)

    # Search engine
    search_engine = SearchEngine(
        db_path = cfg.get("store", {}).get("db_path", "./cnsl_state.db"),
        es_cfg  = cfg,
    )
    if store.available:
        await search_engine.init()

    # Optional Elasticsearch/OpenSearch push
    es_pusher = ElasticsearchPusher(cfg)

    # Detector (must be before reporter and kafka)
    detector = Detector(cfg, logger, blocker,
                        geoip=geoip,     store=store,
                        metrics=metrics,  notifier=notifier,
                        correlator=correlator, abuseipdb=abuseipdb,
                        baseline=baseline, redis_sync=redis_sync,
                        case_manager=case_manager,
                        threat_feed=threat_feed,
                        ueba=ueba,
                        kill_chain=kill_chain_tracker,
                        pattern_learner=pattern_learner,
                        siem_router=siem_router,
                        federation=federation,
                        cloud_identity=None,
                        zero_trust=zero_trust)

    # Reporter (after detector so rule_engine is available)
    reporter = Reporter(store=store, fim=fim_engine, cfg=cfg,
                        ueba=ueba, case_manager=case_manager,
                        rule_engine=getattr(detector, "rules", None),
                        rate_limiter=rate_limiter,
                        kill_chain=kill_chain_tracker,
                        pattern_learner=pattern_learner)

    # Kafka consumer (after detector)
    kafka = KafkaConsumer(cfg, detector, logger)
    if kafka.enabled:
        await kafka.start()

    # HuddleCluster — start after detector so queue_ref is available
    if huddle.enabled:
        await huddle.start()

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
        engine_loop(queue, detector, blocker, logger,
                    ml_detector=ml_detector,
                    pattern_learner=pattern_learner), name="engine"
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
        await federation.start()

    # Cloud identity polling (if any connector is enabled)
    if cloud_identity.any_enabled:
        tasks.append(asyncio.create_task(
            cloud_identity.run(queue, logger), name="cloud_identity",
        ))
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
                            honeypot=active_response, dry_run=dry_run,
                            ml_detector=ml_detector, fim=fim_engine,
                            search_engine=search_engine,
                            es_pusher=es_pusher,
                            case_manager=case_manager,
                            threat_feed=threat_feed,
                            ueba=ueba,
                            tenant_manager=tenant_manager,
                            rate_limiter=rate_limiter,
                            kafka=kafka,
                            huddle=huddle,
                            notifier=notifier,
                            kill_chain=kill_chain_tracker,
                            pattern_learner=pattern_learner,
                            siem_router=siem_router,
                            federation=federation,
                            cloud_identity=cloud_identity,
                            zero_trust=zero_trust,
                            queue=queue,
                            redis_sync=redis_sync,
                            audit_log=audit_log),
            name="dashboard",
        ))

    # Graceful shutdown
    stop = asyncio.Event()

    def _handle_sig(*_):
        stop.set()

    # SIGHUP: reload config file without restarting the process.
    # Applies updated rule thresholds, severities, and enable/disable flags.
    # Does NOT restart log tailers, Redis connections, or dashboard.
    _cfg_path = args.config if args.config else None

    def _handle_sighup(*_):
        if _cfg_path:
            try:
                new_cfg = load_config(_cfg_path)
                detector.rules._apply_config(new_cfg)
                await_log = logger.log("config_reloaded", {
                    "path": _cfg_path, "msg": "rules reloaded via SIGHUP"
                })
                asyncio.ensure_future(await_log)
            except Exception as e:
                asyncio.ensure_future(logger.log("config_reload_error",
                                                  {"error": str(e)}))

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_sig)
        except NotImplementedError:
            signal.signal(sig, lambda s, f: stop.set())

    try:
        loop.add_signal_handler(signal.SIGHUP, _handle_sighup)
    except (NotImplementedError, AttributeError):
        pass  # Windows does not support SIGHUP

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
    await federation.stop()
    await cloud_identity.stop()
    await siem_router.close()
    await store.close()
    logger.close()

    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


def _run_init_wizard() -> None:
    """Interactive setup wizard — creates /etc/cnsl/config.json."""
    import json, os, pathlib, secrets as _sec
    print("CNSL Setup Wizard")
    print("-" * 40)
    out_path  = input("Config path [/etc/cnsl/config.json]: ").strip() or "/etc/cnsl/config.json"
    own_ip    = input("Your server/allowlist IP (e.g. 1.2.3.4): ").strip() or "127.0.0.1"
    dry_run   = input("Enable dry-run mode? (real blocking disabled) [Y/n]: ").strip().lower()
    execute   = dry_run in ("n", "no")
    dashboard = input("Enable web dashboard? [Y/n]: ").strip().lower() not in ("n", "no")

    print("\n--- Notifications (leave blank to skip) ---")
    tg_token  = input("Telegram bot token: ").strip()
    tg_chat   = input("Telegram chat ID: ").strip() if tg_token else ""

    email_host = input("SMTP host (e.g. smtp.gmail.com): ").strip()
    email_cfg  = None
    if email_host:
        email_port = input("SMTP port [587]: ").strip() or "587"
        email_user = input("SMTP username: ").strip()
        email_pass = input("SMTP password: ").strip()
        email_to   = input("Alert recipient email: ").strip()
        email_cfg  = {
            "enabled":   True,
            "smtp_host": email_host,
            "smtp_port": int(email_port),
            "use_tls":   True,
            "username":  email_user,
            "password":  email_pass,
            "from":      f"CNSL Alerts <{email_user}>",
            "to":        [email_to],
        }

    cfg: Dict[str, Any] = {
        "allowlist": ["127.0.0.1", own_ip],
        "actions": {"dry_run": not execute, "block_duration_sec": 900},
        "auth": {"enabled": dashboard, "secret_key": _sec.token_hex(32)},
        "store": {"db_path": "/var/lib/cnsl/cnsl_state.db"},
        "notifications": {
            "min_severity": "MEDIUM",
            "dedup_window_sec": 300,
            "daily_digest": {"enabled": bool(tg_token or email_cfg), "hour": 8},
        },
    }
    if tg_token and tg_chat:
        cfg["notifications"]["telegram"] = {"enabled": True, "bot_token": tg_token, "chat_id": tg_chat}
    if email_cfg:
        cfg["notifications"]["email"] = email_cfg

    pathlib.Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(cfg, f, indent=2)
    print(f"\nConfig written to {out_path}")
    print(f"Run: sudo python -m cnsl --config {out_path}" + (" --dashboard" if dashboard else ""))


async def _show_status(cfg: Dict) -> None:
    """Print running status and block counts."""
    from .store import Store
    import os
    db_path = cfg.get("store", {}).get("db_path", "./cnsl_state.db")
    if not os.path.exists(db_path):
        print("CNSL status: no database found — not running or no events yet.")
        return
    s = Store(db_path)
    await s.init()
    try:
        st      = await s.stats()
        blocks  = await s.active_blocks()
        print("CNSL Status")
        print("-" * 30)
        print(f"  Database   : {db_path}")
        print(f"  Events     : {st.get('total', 0)}")
        print(f"  HIGH       : {st.get('high', 0)}")
        print(f"  MEDIUM     : {st.get('medium', 0)}")
        print(f"  Unique IPs : {st.get('unique_ips', 0)}")
        print(f"  Blocked IPs: {len(blocks)}")
        print(f"  Dry-run    : {cfg.get('actions', {}).get('dry_run', True)}")
    finally:
        await s.close()


async def _check_update() -> None:
    """Check PyPI for a newer CNSL version."""
    import json as _json
    from cnsl import __version__
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get("https://pypi.org/pypi/cnsl/json", timeout=aiohttp.ClientTimeout(total=5)) as r:
                data = await r.json()
        latest = data["info"]["version"]
        if latest == __version__:
            print(f"CNSL {__version__} is up to date.")
        else:
            print(f"Update available: {__version__} → {latest}")
            print("Run: pip install --upgrade cnsl")
    except Exception as e:
        print(f"Could not check for updates: {e}")


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

    # Init wizard
    if getattr(args, 'init', False):
        _run_init_wizard()
        return

    # Status
    if getattr(args, 'status', False):
        asyncio.run(_show_status(cfg))
        return

    # Config validation (--validate-config)
    if getattr(args, 'validate_config', False):
        ok = validate_and_print(cfg)
        raise SystemExit(0 if ok else 1)

    # Backup (--backup PATH)
    if getattr(args, 'backup', None):
        from .backup import create_backup
        from .config import resolve_config_path
        config_path = resolve_config_path(args.config)
        result = create_backup(cfg, config_path, args.backup)
        print(f"Backup written to: {result['path']}")
        for item in result["included"]:
            print(f"  included: {item}")
        for item in result["skipped"]:
            print(f"  skipped:  {item}")
        return

    # Restore (--restore PATH)
    if getattr(args, 'restore', None):
        from .backup import restore_backup

        def _confirm(path: str) -> bool:
            ans = input(f"Overwrite existing file {path}? [y/N] ").strip().lower()
            return ans == "y"

        result = restore_backup(args.restore, force=args.force,
                                 confirm=None if args.force else _confirm)
        m = result["manifest"]
        print(f"Restored from backup created {m.get('created')} (CNSL {m.get('cnsl_version')})")
        for item in result["restored"]:
            print(f"  restored: {item}")
        for item in result["skipped"]:
            print(f"  skipped:  {item}")
        if result["skipped"]:
            print("\nSkipped files were left untouched. Re-run with --force to overwrite them.")
        return

    # PostgreSQL migration (--migrate-db DSN)
    if getattr(args, 'migrate_db', None):
        from .migrate import migrate as run_migration

        sqlite_path = args.sqlite_path or cfg.get("store", {}).get("db_path", "./cnsl_state.db")
        try:
            result = asyncio.run(run_migration(
                sqlite_path=sqlite_path,
                pg_dsn=args.migrate_db,
                batch_size=args.migrate_batch_size,
                dry_run=args.migrate_dry_run,
                truncate_target=args.migrate_truncate_target,
            ))
        except (FileNotFoundError, ValueError, ImportError) as e:
            print(f"Migration failed: {e}")
            raise SystemExit(1)

        if result["dry_run"]:
            print("Dry run -- nothing written. Source row counts:")
        else:
            print("Migration complete:")
        print(f"  incidents: {result['incidents']['source_count']} in source, "
              f"{result['incidents']['migrated']} migrated")
        print(f"  blocks:    {result['blocks']['source_count']} in source, "
              f"{result['blocks']['migrated']} migrated")
        print("\nNot migrated (no PostgreSQL schema yet):")
        for item in result["skipped_tables"]:
            print(f"  - {item}")
        if not result["dry_run"]:
            print("\nUpdate config.json's store.backend to \"postgresql\" to start using it.")
        return

    # Update check
    if getattr(args, 'check_update', False):
        asyncio.run(_check_update())
        return

    # Report-only mode
    if getattr(args, 'report', None):
        async def _report_only():
            from .store    import Store
            from .fim      import FIMEngine
            from .reporter import Reporter
            s = Store(cfg)
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