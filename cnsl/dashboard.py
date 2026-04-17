"""
cnsl/dashboard.py — Live web dashboard (aiohttp + SSE).

Routes:
  GET  /                     — main dashboard HTML
  GET  /api/stats            — JSON stats snapshot
  GET  /api/incidents        — recent incidents JSON
  GET  /api/top-attackers    — top attacker IPs JSON
  GET  /api/blocks           — active blocks JSON
  GET  /api/metrics          — Prometheus text metrics
  POST /api/block            — manually block IP
  POST /api/unblock          — manually unblock IP
  GET  /stream               — SSE live event stream

The HTML dashboard is fully self-contained (no CDN in production mode),
using Chart.js from CDN for charts and vanilla JS for SSE.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:
    from .blocker import Blocker
    from .detector import Detector
    from .geoip import GeoIP
    from .logger import JsonLogger
    from .metrics import Metrics
    from .store import Store


# ---------------------------------------------------------------------------
# Dashboard HTML (single-file, self-contained)
# ---------------------------------------------------------------------------

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CNSL Guard — Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  :root {
    --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3a;
    --text: #e2e8f0; --muted: #64748b; --accent: #6366f1;
    --red: #ef4444; --amber: #f59e0b; --green: #22c55e;
    --blue: #3b82f6; --purple: #a855f7;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; }
  header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 14px 24px; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 16px; font-weight: 600; }
  .badge { font-size: 11px; padding: 2px 8px; border-radius: 99px; background: var(--accent); color: #fff; }
  #live-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); margin-left: auto; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
  .layout { display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 16px; padding: 20px 24px; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 18px; }
  .stat-card .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; margin-bottom: 8px; }
  .stat-card .value { font-size: 28px; font-weight: 700; }
  .stat-card .sub { font-size: 11px; color: var(--muted); margin-top: 4px; }
  .red   { color: var(--red); }
  .amber { color: var(--amber); }
  .green { color: var(--green); }
  .blue  { color: var(--blue); }
  .section { padding: 0 24px 20px; }
  .section h2 { font-size: 13px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; margin-bottom: 12px; }
  .chart-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; padding: 0 24px 20px; }
  .chart-box { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
  .chart-box h3 { font-size: 12px; color: var(--muted); margin-bottom: 12px; text-transform: uppercase; }
  canvas { max-height: 200px; }
  table { width: 100%; border-collapse: collapse; }
  th { text-align: left; font-size: 11px; color: var(--muted); text-transform: uppercase; padding: 8px 12px; border-bottom: 1px solid var(--border); }
  td { padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 13px; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  .table-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
  .sev { font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 4px; }
  .sev-HIGH   { background: rgba(239,68,68,.15);  color: var(--red); }
  .sev-MEDIUM { background: rgba(245,158,11,.15); color: var(--amber); }
  .sev-LOW    { background: rgba(59,130,246,.15); color: var(--blue); }
  .ip { font-family: monospace; font-size: 12px; }
  .flag { font-size: 16px; margin-right: 4px; }
  .block-btn { font-size: 11px; padding: 3px 10px; border-radius: 4px; border: 1px solid var(--red); color: var(--red); background: transparent; cursor: pointer; }
  .block-btn:hover { background: rgba(239,68,68,.1); }
  .unblock-btn { font-size: 11px; padding: 3px 10px; border-radius: 4px; border: 1px solid var(--green); color: var(--green); background: transparent; cursor: pointer; }
  .unblock-btn:hover { background: rgba(34,197,94,.1); }
  .live-feed { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; height: 200px; overflow-y: auto; padding: 12px; font-family: monospace; font-size: 12px; }
  .feed-line { padding: 2px 0; border-bottom: 1px solid rgba(255,255,255,.04); }
  .feed-line.alert { color: var(--red); }
  .feed-line.warn  { color: var(--amber); }
  .feed-line.ok    { color: var(--green); }
  .feed-line.info  { color: var(--muted); }
  .dry-run-banner { background: rgba(245,158,11,.12); border: 1px solid var(--amber); border-radius: 8px; padding: 10px 16px; margin: 0 24px 16px; font-size: 12px; color: var(--amber); display: flex; align-items: center; gap: 8px; }
</style>
</head>
<body>

<header>
  <span style="font-size:20px">🛡️</span>
  <h1>CNSL Guard</h1>
  <span class="badge">v1.0</span>
  <div id="live-dot" title="Live"></div>
</header>

<div id="dry-run-banner" style="display:none" class="dry-run-banner">
  ⚠️ <strong>DRY-RUN MODE</strong> — Block plans are logged but no iptables commands are executed. Pass <code>--execute</code> to enable real blocking.
</div>

<!-- Stats row -->
<div class="layout">
  <div class="stat-card">
    <div class="label">Total Incidents</div>
    <div class="value" id="s-total">—</div>
    <div class="sub">all time</div>
  </div>
  <div class="stat-card">
    <div class="label">HIGH Severity</div>
    <div class="value red" id="s-high">—</div>
    <div class="sub">credential breaches</div>
  </div>
  <div class="stat-card">
    <div class="label">Active Blocks</div>
    <div class="value amber" id="s-blocks">—</div>
    <div class="sub">currently blocked IPs</div>
  </div>
  <div class="stat-card">
    <div class="label">Unique Attackers</div>
    <div class="value blue" id="s-unique">—</div>
    <div class="sub">distinct IPs</div>
  </div>
</div>

<!-- Charts -->
<div class="chart-row">
  <div class="chart-box">
    <h3>Incidents over time (last 24h)</h3>
    <canvas id="chart-timeline"></canvas>
  </div>
  <div class="chart-box">
    <h3>Severity breakdown</h3>
    <canvas id="chart-severity"></canvas>
  </div>
</div>

<!-- Active blocks + Top Attackers -->
<div class="chart-row">
  <div class="section" style="padding:0">
    <h2 style="margin-bottom:12px">🔒 Active Blocks</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>IP</th><th>Location</th><th>Blocked at</th><th>Expires</th><th></th></tr></thead>
        <tbody id="blocks-body"><tr><td colspan="5" style="color:var(--muted);text-align:center">No active blocks</td></tr></tbody>
      </table>
    </div>
  </div>
  <div class="section" style="padding:0">
    <h2 style="margin-bottom:12px">🎯 Top Attackers</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>IP</th><th>Location</th><th>Incidents</th><th>Last seen</th></tr></thead>
        <tbody id="attackers-body"><tr><td colspan="4" style="color:var(--muted);text-align:center">No data yet</td></tr></tbody>
      </table>
    </div>
  </div>
</div>

<!-- Recent incidents + Live feed -->
<div class="chart-row">
  <div class="section" style="padding:0">
    <h2 style="margin-bottom:12px">🚨 Recent Incidents</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Time</th><th>IP</th><th>Location</th><th>Severity</th><th>Fails</th></tr></thead>
        <tbody id="incidents-body"><tr><td colspan="5" style="color:var(--muted);text-align:center">No incidents yet</td></tr></tbody>
      </table>
    </div>
  </div>
  <div class="section" style="padding:0">
    <h2 style="margin-bottom:12px">📡 Live Feed</h2>
    <div class="live-feed" id="live-feed"></div>
  </div>
</div>

<script>
// ── Helpers ────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const fmt = ts => ts ? new Date(ts * 1000).toLocaleTimeString() : '';
const fmtDate = ts => ts ? new Date(ts * 1000).toLocaleString() : '';

function addFeedLine(text, cls='info') {
  const feed = $('live-feed');
  const line = document.createElement('div');
  line.className = `feed-line ${cls}`;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
  feed.prepend(line);
  // Keep max 200 lines
  while (feed.children.length > 200) feed.removeChild(feed.lastChild);
}

// ── Charts setup ───────────────────────────────────────────────────────────
const timelineCtx = $('chart-timeline').getContext('2d');
const timelineChart = new Chart(timelineCtx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      { label: 'HIGH',   data: [], borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,.1)',   tension: 0.3, fill: true },
      { label: 'MEDIUM', data: [], borderColor: '#f59e0b', backgroundColor: 'rgba(245,158,11,.1)', tension: 0.3, fill: true },
    ]
  },
  options: {
    responsive: true, maintainAspectRatio: true,
    plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } },
    scales: {
      x: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: '#1e2130' } },
      y: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: '#1e2130' }, beginAtZero: true }
    }
  }
});

const sevCtx = $('chart-severity').getContext('2d');
const sevChart = new Chart(sevCtx, {
  type: 'doughnut',
  data: {
    labels: ['HIGH', 'MEDIUM', 'LOW'],
    datasets: [{ data: [0,0,0], backgroundColor: ['#ef4444','#f59e0b','#3b82f6'], borderWidth: 0 }]
  },
  options: {
    responsive: true, maintainAspectRatio: true,
    plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } }
  }
});

// ── API fetchers ───────────────────────────────────────────────────────────
async function fetchStats() {
  try {
    const r = await fetch('/api/stats');
    const d = await r.json();
    $('s-total').textContent  = d.total ?? '0';
    $('s-high').textContent   = d.high  ?? '0';
    $('s-blocks').textContent = d.active_blocks ?? '0';
    $('s-unique').textContent = d.unique_ips ?? '0';
    sevChart.data.datasets[0].data = [d.high||0, d.medium||0, d.low||0];
    sevChart.update('none');
    if (d.dry_run) $('dry-run-banner').style.display = 'flex';
  } catch(e) {}
}

async function fetchIncidents() {
  try {
    const r = await fetch('/api/incidents');
    const rows = await r.json();
    const tbody = $('incidents-body');
    if (!rows.length) return;
    tbody.innerHTML = rows.slice(0,20).map(row => `
      <tr>
        <td style="color:var(--muted);font-size:11px">${fmtDate(row.ts)}</td>
        <td class="ip">${row.src_ip}</td>
        <td><span class="flag">${row.flag||'🌐'}</span>${row.country||''}</td>
        <td><span class="sev sev-${row.severity}">${row.severity}</span></td>
        <td>${row.fail_count}</td>
      </tr>`).join('');
  } catch(e) {}
}

async function fetchBlocks() {
  try {
    const r = await fetch('/api/blocks');
    const rows = await r.json();
    const tbody = $('blocks-body');
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="color:var(--muted);text-align:center">No active blocks</td></tr>';
      return;
    }
    tbody.innerHTML = rows.map(row => `
      <tr>
        <td class="ip">${row.ip}</td>
        <td><span class="flag">${row.flag||'🌐'}</span>${row.country||''}</td>
        <td style="font-size:11px;color:var(--muted)">${fmtDate(row.blocked_at)}</td>
        <td style="font-size:11px;color:var(--amber)">${fmtDate(row.unblock_at)}</td>
        <td><button class="unblock-btn" onclick="doUnblock('${row.ip}')">Unblock</button></td>
      </tr>`).join('');
  } catch(e) {}
}

async function fetchTopAttackers() {
  try {
    const r = await fetch('/api/top-attackers');
    const rows = await r.json();
    const tbody = $('attackers-body');
    if (!rows.length) return;
    tbody.innerHTML = rows.map(row => `
      <tr>
        <td class="ip">${row.src_ip}</td>
        <td><span class="flag">${row.flag||'🌐'}</span>${row.country||''} ${row.city ? '· '+row.city : ''}</td>
        <td style="color:var(--red);font-weight:600">${row.incident_count}</td>
        <td style="font-size:11px;color:var(--muted)">${fmtDate(row.last_seen)}</td>
      </tr>`).join('');
  } catch(e) {}
}

async function doUnblock(ip) {
  try {
    await fetch('/api/unblock', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ip}) });
    addFeedLine(`Manual unblock: ${ip}`, 'ok');
    fetchBlocks();
    fetchStats();
  } catch(e) {}
}

// ── SSE live feed ──────────────────────────────────────────────────────────
function connectSSE() {
  const es = new EventSource('/stream');
  es.onmessage = e => {
    try {
      const d = JSON.parse(e.data);
      if (d.type === 'incident') {
        const sev = d.payload?.severity;
        const ip  = d.payload?.src_ip || d.payload?.ip;
        const cls = sev === 'HIGH' ? 'alert' : sev === 'MEDIUM' ? 'warn' : 'info';
        addFeedLine(`${sev} — ${ip} — ${(d.payload?.reasons||[]).join('; ')}`, cls);
        fetchStats(); fetchIncidents(); fetchBlocks();
      } else if (d.type === 'action_block_executed' || d.type === 'action_block_scheduled') {
        addFeedLine(`BLOCKED: ${d.payload?.ip}`, 'alert');
        fetchBlocks(); fetchStats();
      } else if (d.type === 'event_auth') {
        const k = d.payload?.kind;
        if (k === 'SSH_FAIL') addFeedLine(`SSH FAIL from ${d.payload?.src_ip} user=${d.payload?.user||'?'}`, 'warn');
        else if (k === 'SSH_SUCCESS') addFeedLine(`SSH OK from ${d.payload?.src_ip} user=${d.payload?.user||'?'}`, 'ok');
      }
    } catch(err) {}
  };
  es.onerror = () => {
    addFeedLine('SSE disconnected, reconnecting...', 'info');
    es.close();
    setTimeout(connectSSE, 3000);
  };
}

// ── Init ───────────────────────────────────────────────────────────────────
async function refresh() {
  await Promise.all([fetchStats(), fetchIncidents(), fetchBlocks(), fetchTopAttackers()]);
}

refresh();
connectSSE();
setInterval(refresh, 10000);  // full refresh every 10s
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Dashboard server
# ---------------------------------------------------------------------------

async def start_dashboard(
    host:      str,
    port:      int,
    detector:  "Detector",
    blocker:   "Blocker",
    store:     "Store",
    metrics:   "Metrics",
    logger:    "JsonLogger",
    dry_run:   bool = True,
) -> None:
    try:
        from aiohttp import web
        from aiohttp.web import Response
    except ImportError:
        await logger.log("dashboard_error", {"error": "aiohttp not installed. Run: pip install aiohttp"})
        return

    # SSE subscribers
    _subscribers: list = []

    # Patch logger to fan out to SSE
    _orig_log = logger.log

    async def _patched_log(event_type: str, payload: dict) -> None:
        await _orig_log(event_type, payload)
        msg = json.dumps({"type": event_type, "payload": payload})
        dead = []
        for q in list(_subscribers):
            try:
                q.put_nowait(msg)
            except Exception:
                dead.append(q)
        for d in dead:
            try:
                _subscribers.remove(d)
            except ValueError:
                pass

    logger.log = _patched_log  # type: ignore

    router = web.RouteTableDef()

    @router.get("/")
    async def index(_: web.Request) -> Response:
        return Response(text=_HTML, content_type="text/html")

    @router.get("/api/stats")
    async def api_stats(_: web.Request) -> Response:
        db_stats = await store.stats() if store.available else {}
        active_blocks = len(blocker.active_blocks)
        return web.json_response({
            "total":         db_stats.get("total", 0),
            "high":          db_stats.get("high", 0),
            "medium":        db_stats.get("medium", 0),
            "low":           0,
            "unique_ips":    db_stats.get("unique_ips", len(detector._state)),
            "active_blocks": active_blocks,
            "dry_run":       dry_run,
            "uptime_sec":    metrics.events_processed,
        })

    @router.get("/api/incidents")
    async def api_incidents(req: web.Request) -> Response:
        limit = int(req.rel_url.query.get("limit", 50))
        rows = await store.recent_incidents(limit) if store.available else []
        return web.json_response(rows)

    @router.get("/api/top-attackers")
    async def api_top(_: web.Request) -> Response:
        rows = await store.top_attackers() if store.available else []
        return web.json_response(rows)

    @router.get("/api/blocks")
    async def api_blocks(_: web.Request) -> Response:
        rows = await store.active_blocks() if store.available else []
        # Enrich with live active_blocks (in case store is unavailable)
        if not rows:
            rows = [
                {"ip": ip, "unblock_at": exp, "blocked_at": exp - blocker.block_duration_sec}
                for ip, exp in blocker.active_blocks.items()
            ]
        return web.json_response(rows)

    @router.get("/api/metrics")
    async def api_metrics(_: web.Request) -> Response:
        return Response(text=metrics.render(), content_type="text/plain")

    @router.post("/api/block")
    async def api_block(req: web.Request) -> Response:
        body = await req.json()
        ip = body.get("ip", "").strip()
        if not ip:
            return web.json_response({"error": "ip required"}, status=400)
        ok = await blocker.block_ip(ip, reason="dashboard-manual")
        await logger.log("dashboard_manual_block", {"ip": ip, "ok": ok})
        return web.json_response({"blocked": ok, "ip": ip})

    @router.post("/api/unblock")
    async def api_unblock(req: web.Request) -> Response:
        body = await req.json()
        ip = body.get("ip", "").strip()
        if not ip:
            return web.json_response({"error": "ip required"}, status=400)
        await blocker._unblock_ip(ip)
        await logger.log("dashboard_manual_unblock", {"ip": ip})
        return web.json_response({"unblocked": True, "ip": ip})

    @router.get("/stream")
    async def sse_stream(req: web.Request) -> Response:
        """Server-Sent Events endpoint for live dashboard updates."""
        resp = web.StreamResponse(headers={
            "Content-Type":  "text/event-stream",
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        })
        await resp.prepare(req)

        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        _subscribers.append(q)

        try:
            # Send a heartbeat every 15s to keep connection alive
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=15.0)
                    await resp.write(f"data: {msg}\n\n".encode())
                except asyncio.TimeoutError:
                    await resp.write(b": heartbeat\n\n")
        except (ConnectionResetError, Exception):
            pass
        finally:
            try:
                _subscribers.remove(q)
            except ValueError:
                pass

        return resp

    app = web.Application()
    app.add_routes(router)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    await logger.log("dashboard_started", {"url": f"http://{host}:{port}"})
    print(f"\n  📊 Dashboard → http://{host}:{port}\n", flush=True)

    await asyncio.Event().wait()