"""
cnsl/dashboard.py — Live web dashboard with JWT auth, SSE, REST API.

Routes:
  GET  /                     HTML dashboard (requires auth if enabled)
  GET  /login                Login page
  POST /api/login            Get JWT token
  POST /api/logout           Revoke token
  GET  /api/stats            Engine summary
  GET  /api/incidents        Recent incidents
  GET  /api/top-attackers    Top attacker IPs
  GET  /api/blocks           Active blocks
  GET  /api/metrics          Prometheus text metrics
  POST /api/block            Manual block
  POST /api/unblock          Manual unblock
  GET  /stream               SSE live event stream
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:
    from .auth    import AuthManager
    from .blocker import Blocker
    from .detector import Detector
    from .logger  import JsonLogger
    from .metrics import Metrics
    from .store   import Store


# Login page HTML


_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CNSL — Login</title>
<style>
  :root { --bg:#0f1117; --surface:#1a1d27; --border:#2a2d3a; --text:#e2e8f0;
          --muted:#64748b; --accent:#6366f1; --red:#ef4444; --green:#22c55e; }
  * { box-sizing:border-box; margin:0; padding:0; }

  body { 
    background:var(--bg); 
    color:var(--text); f
    ont-family:system-ui,sans-serif;
    display:flex; 
    align-items:center; 
    justify-content:center; 
    min-height:100vh; 
  
  }
  .card { 
    background:var(--surface); 
    border:1px solid var(--border); 
    border-radius:12px;
    padding:2rem; 
    width:100%; 
    max-width:360px; 
  
  }
  h1 { font-size:20px; font-weight:600; margin-bottom:8px; }

  .sub { font-size:13px; color:var(--muted); margin-bottom:1.5rem; }

  label { 
    font-size:12px; 
    color:var(--muted); 
    display:block; 
    margin-bottom:4px; 
  }
  input { 
    width:100%; 
    padding:10px 12px; 
    background:#0f1117; 
    border:1px solid var(--border);
    border-radius:8px; 
    color:var(--text); 
    font-size:14px; 
    margin-bottom:1rem; 
    outline:none; 
  }
  input:focus { border-color:var(--accent); }
  button {
    width:100%; 
    padding:11px; 
    background:var(--accent); 
    color:#fff; 
    border:none;
    border-radius:8px; 
    font-size:14px; f
    ont-weight:500; 
    cursor:pointer; 
    
    }
  button:hover { opacity:.9; }
  .err { 
    color:var(--red); 
    font-size:13px; 
    margin-top:1rem; 
    display:none; 
  }
  .warn { 
    background:rgba(245,158,11,.1); 
    border:1px solid #f59e0b; 
    border-radius:8px;
    padding:10px 12px; 
    font-size:12px; 
    color:#f59e0b; 
    margin-bottom:1rem; 
  
  }
</style>
</head>
<body>
<div class="card">
  <h1>🛡️ CNSL</h1>
  <p class="sub">Correlated Network Security Layer</p>
  <div id="warn" class="warn" style="display:none">
    Default password in use. Change it in config after login.
  </div>
  <label>Username</label>
  <input type="text" id="user" value="admin" autocomplete="username">
  <label>Password</label>
  <input type="password" id="pass" autocomplete="current-password"
         onkeydown="if(event.key==='Enter')doLogin()">
  <button onclick="doLogin()">Sign in</button>
  <div class="err" id="err"></div>
</div>
<script>
async function doLogin() {
  const u = document.getElementById('user').value;
  const p = document.getElementById('pass').value;
  try {
    const r = await fetch('/api/login', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({username:u, password:p})
    });
    const d = await r.json();
    if (d.token) {
      localStorage.setItem('cnsl_token', d.token);
      if (d.must_change_password) {
        document.getElementById('warn').style.display = 'block';
        setTimeout(() => location.href = '/', 2000);
      } else {
        location.href = '/';
      }
    } else {
      const err = document.getElementById('err');
      err.textContent = d.error || 'Login failed';
      err.style.display = 'block';
    }
  } catch(e) {
    document.getElementById('err').textContent = 'Network error';
    document.getElementById('err').style.display = 'block';
  }
}
// Show default password warning
fetch('/api/auth-info').then(r=>r.json()).then(d=>{
  if(d.default_password) document.getElementById('warn').style.display='block';
}).catch(()=>{});
</script>
</body>
</html>"""


# Main dashboard HTML


_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CNSL — Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  :root {
    --bg:#0f1117; --surface:#1a1d27; --border:#2a2d3a;
    --text:#e2e8f0; --muted:#64748b; --accent:#6366f1;
    --red:#ef4444; --amber:#f59e0b; --green:#22c55e; --blue:#3b82f6;
  }
  *{box-sizing:border-box;margin:0;padding:0;}

  body{
    background:var(--bg);
    color:var(--text);
    font-family:'Segoe UI',system-ui,sans-serif;
    font-size:14px;
  }
  header{
    background:var(--surface);
    border-bottom:1px solid var(--border);
    padding:14px 24px;
    display:flex;
    align-items:center;
    gap:12px;
  }
  header h1{font-size:16px;font-weight:600;}

  .badge{
    font-size:11px;
    padding:2px 8px;
    border-radius:99px;
    background:var(--accent);
    color:#fff;
  }
  
  #live-dot{width:8px;height:8px;border-radius:50%;background:var(--green);
            margin-left:auto;animation:pulse 2s infinite;}
  #logout-btn{font-size:12px;padding:4px 12px;border:1px solid var(--border);border-radius:6px;
              background:transparent;color:var(--muted);cursor:pointer;margin-left:8px;}
  #logout-btn:hover{color:var(--red);border-color:var(--red);}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

  .layout{
    display:grid;
    grid-template-columns:1fr 1fr 1fr 1fr;
    gap:16px;
    padding:20px 24px;
  }
  .stat-card{
    background:var(--surface);
    border:1px solid var(--border);
    border-radius:10px;
    padding:18px;
  }
  .stat-card .label{
    font-size:11px;
    color:var(--muted);
    text-transform:uppercase;
    letter-spacing:.05em;
    margin-bottom:8px;
  
  }
  .stat-card .value{font-size:28px;font-weight:700;}

  .red{
  color:var(--red);} .amber{color:var(--amber);} .green{color:var(--green);} .blue{color:var(--blue);
  
  }
  .section{padding:0 24px 20px;}

  .section h2{
    font-size:13px;
    font-weight:600;
    color:var(--muted);
    text-transform:uppercase;
    letter-spacing:.06em;
    margin-bottom:12px;
  
  }
  .chart-row{
    display:grid;
    grid-template-columns:1fr 1fr;
    gap:16px;
    padding:0 24px 20px;
  }
  .chart-box{
    background:var(--surface);
    border:1px solid var(--border);
    border-radius:10px;
    padding:16px;
  }
  .chart-box h3{
    font-size:12px;
    color:var(--muted);
    margin-bottom:12px;
    text-transform:uppercase;
  
  }
  canvas{max-height:200px;}

  table{width:100%;border-collapse:collapse;}

  th{
    text-align:left;
    font-size:11px;
    color:var(--muted);
    text-transform:uppercase;
    padding:8px 12px;
    border-bottom:1px solid var(--border);
  }
  td{
    padding:10px 12px;
    border-bottom:1px solid var(--border);
    font-size:13px;
    vertical-align:middle;
  
  }
  tr:last-child td{border-bottom:none;}

  .table-wrap{
    background:var(--surface);
    border:1px solid var(--border);
    border-radius:10px;
    overflow:hidden;
  }
  .sev{font-size:11px;font-weight:600;padding:2px 8px;border-radius:4px;}
  .sev-HIGH{background:rgba(239,68,68,.15);color:var(--red);}
  .sev-MEDIUM{background:rgba(245,158,11,.15);color:var(--amber);}
  .sev-LOW{background:rgba(59,130,246,.15);color:var(--blue);}
  .ip{font-family:monospace;font-size:12px;}

  .unblock-btn{
    font-size:11px;
    padding:3px 10px;
    border-radius:4px;
    border:1px solid var(--green);
    color:var(--green);
    background:transparent;
    cursor:pointer;
  }
  .unblock-btn:hover{background:rgba(34,197,94,.1);}

  .live-feed{
    background:var(--surface);
    border:1px solid var(--border);
    border-radius:10px;
    height:200px;
    overflow-y:auto;
    padding:12px;
    font-family:monospace;
    font-size:12px;
  
  }
  .feed-line{padding:2px 0;border-bottom:1px solid rgba(255,255,255,.04);}
  .feed-line.alert{color:var(--red);} .feed-line.warn{color:var(--amber);}
  .feed-line.ok{color:var(--green);} .feed-line.info{color:var(--muted);}

  .dry-run-banner{
    background:rgba(245,158,11,.12);
    border:1px solid var(--amber);
    border-radius:8px;
    padding:10px 16px;
    margin:0 24px 16px;
    font-size:12px;
    color:var(--amber);
    display:flex;
    align-items:center;
    gap:8px;
  }
  .default-pw-banner{
    background:rgba(239,68,68,.12);
    border:1px solid var(--red);
    border-radius:8px;
    padding:10px 16px;
    margin:0 24px 16px;
    font-size:12px;
    color:var(--red);
  }
</style>
</head>
<body>
<header>
  <span style="font-size:20px">🛡️</span>
  <h1>CNSL</h1>
  <span class="badge">v1.0</span>
  <div id="live-dot" title="Live"></div>
  <button id="logout-btn" onclick="doLogout()">Logout</button>
</header>

<div id="dry-run-banner" style="display:none" class="dry-run-banner">
  ⚠️ <strong>DRY-RUN MODE</strong> — No real iptables commands executed. Pass --execute to enable.
</div>
<div id="default-pw-banner" style="display:none" class="default-pw-banner">
  🔒 <strong>Security warning:</strong> Default password in use. Update auth.users in config.json.
</div>

<div class="layout">
  <div class="stat-card"><div class="label">Total Incidents</div>
    <div class="value" id="s-total">—</div><div class="sub" style="font-size:11px;color:var(--muted)">all time</div></div>
  <div class="stat-card"><div class="label">HIGH Severity</div>
    <div class="value red" id="s-high">—</div><div class="sub" style="font-size:11px;color:var(--muted)">credential breaches</div></div>
  <div class="stat-card"><div class="label">Active Blocks</div>
    <div class="value amber" id="s-blocks">—</div><div class="sub" style="font-size:11px;color:var(--muted)">currently blocked IPs</div></div>
  <div class="stat-card"><div class="label">Unique Attackers</div>
    <div class="value blue" id="s-unique">—</div><div class="sub" style="font-size:11px;color:var(--muted)">distinct IPs</div></div>
</div>

<div class="chart-row">
  <div class="chart-box"><h3>Incidents over time (last 24h)</h3><canvas id="chart-timeline"></canvas></div>
  <div class="chart-box"><h3>Severity breakdown</h3><canvas id="chart-severity"></canvas></div>
</div>

<div class="chart-row">
  <div class="section" style="padding:0">
    <h2 style="margin-bottom:12px">🔒 Active Blocks</h2>
    <div class="table-wrap">
      <table><thead><tr><th>IP</th><th>Location</th><th>Blocked at</th><th>Expires</th><th></th></tr></thead>
      <tbody id="blocks-body"><tr><td colspan="5" style="color:var(--muted);text-align:center">No active blocks</td></tr></tbody></table>
    </div>
  </div>
  <div class="section" style="padding:0">
    <h2 style="margin-bottom:12px">🎯 Top Attackers</h2>
    <div class="table-wrap">
      <table><thead><tr><th>IP</th><th>Location</th><th>Incidents</th><th>Last seen</th></tr></thead>
      <tbody id="attackers-body"><tr><td colspan="4" style="color:var(--muted);text-align:center">No data yet</td></tr></tbody></table>
    </div>
  </div>
</div>

<div class="chart-row">
  <div class="section" style="padding:0">
    <h2 style="margin-bottom:12px">🚨 Recent Incidents</h2>
    <div class="table-wrap">
      <table><thead><tr><th>Time</th><th>IP</th><th>Location</th><th>Severity</th><th>Fails</th></tr></thead>
      <tbody id="incidents-body"><tr><td colspan="5" style="color:var(--muted);text-align:center">No incidents yet</td></tr></tbody></table>
    </div>
  </div>
  <div class="section" style="padding:0">
    <h2 style="margin-bottom:12px">📡 Live Feed</h2>
    <div class="live-feed" id="live-feed"></div>
  </div>
</div>

<script>
const $=id=>document.getElementById(id);
const fmt=ts=>ts?new Date(ts*1000).toLocaleTimeString():'';
const fmtDate=ts=>ts?new Date(ts*1000).toLocaleString():'';
const token=()=>localStorage.getItem('cnsl_token')||'';

function authHeaders(){return{'Content-Type':'application/json','Authorization':'Bearer '+token()};}

function addFeedLine(text,cls='info'){
  const feed=$('live-feed');
  const line=document.createElement('div');
  line.className='feed-line '+cls;
  line.textContent='['+new Date().toLocaleTimeString()+'] '+text;
  feed.prepend(line);
  while(feed.children.length>200)feed.removeChild(feed.lastChild);
}

async function doLogout(){
  await fetch('/api/logout',{method:'POST',headers:authHeaders()}).catch(()=>{});
  localStorage.removeItem('cnsl_token');
  location.href='/login';
}

// Charts
const tlCtx=$('chart-timeline').getContext('2d');
const tlChart=new Chart(tlCtx,{type:'line',
  data:{labels:[],datasets:[
    {label:'HIGH',data:[],borderColor:'#ef4444',backgroundColor:'rgba(239,68,68,.1)',tension:0.3,fill:true},
    {label:'MEDIUM',data:[],borderColor:'#f59e0b',backgroundColor:'rgba(245,158,11,.1)',tension:0.3,fill:true}
  ]},
  options:{responsive:true,maintainAspectRatio:true,
    plugins:{legend:{labels:{color:'#94a3b8',font:{size:11}}}},
    scales:{x:{ticks:{color:'#64748b',font:{size:10}},grid:{color:'#1e2130'}},
            y:{ticks:{color:'#64748b',font:{size:10}},grid:{color:'#1e2130'},beginAtZero:true}}}
});

const sevCtx=$('chart-severity').getContext('2d');
const sevChart=new Chart(sevCtx,{type:'doughnut',
  data:{labels:['HIGH','MEDIUM','LOW'],
        datasets:[{data:[0,0,0],backgroundColor:['#ef4444','#f59e0b','#3b82f6'],borderWidth:0}]},
  options:{responsive:true,maintainAspectRatio:true,
    plugins:{legend:{labels:{color:'#94a3b8',font:{size:11}}}}}
});

async function apiFetch(url,opts={}){
  opts.headers={...authHeaders(),...(opts.headers||{})};
  const r=await fetch(url,opts);
  if(r.status===401){location.href='/login';return null;}
  return r.json();
}

async function fetchStats(){
  const d=await apiFetch('/api/stats');
  if(!d)return;
  $('s-total').textContent=d.total??'0';
  $('s-high').textContent=d.high??'0';
  $('s-blocks').textContent=d.active_blocks??'0';
  $('s-unique').textContent=d.unique_ips??'0';
  sevChart.data.datasets[0].data=[d.high||0,d.medium||0,d.low||0];
  sevChart.update('none');
  if(d.dry_run)$('dry-run-banner').style.display='flex';
  if(d.default_password)$('default-pw-banner').style.display='block';
}

async function fetchIncidents(){
  const rows=await apiFetch('/api/incidents');
  if(!rows)return;
  const tb=$('incidents-body');
  if(!rows.length)return;
  tb.innerHTML=rows.slice(0,20).map(r=>`
    <tr>
      <td style="color:var(--muted);font-size:11px">${fmtDate(r.ts)}</td>
      <td class="ip">${r.src_ip}</td>
      <td><span style="font-size:16px">${r.flag||'🌐'}</span> ${r.country||''}</td>
      <td><span class="sev sev-${r.severity}">${r.severity}</span></td>
      <td>${r.fail_count}</td>
    </tr>`).join('');
}

async function fetchBlocks(){
  const rows=await apiFetch('/api/blocks');
  if(!rows)return;
  const tb=$('blocks-body');
  if(!rows.length){
    tb.innerHTML='<tr><td colspan="5" style="color:var(--muted);text-align:center">No active blocks</td></tr>';
    return;
  }
  tb.innerHTML=rows.map(r=>`
    <tr>
      <td class="ip">${r.ip}</td>
      <td>${r.flag||'🌐'} ${r.country||''}</td>
      <td style="font-size:11px;color:var(--muted)">${fmtDate(r.blocked_at)}</td>
      <td style="font-size:11px;color:var(--amber)">${fmtDate(r.unblock_at)}</td>
      <td><button class="unblock-btn" onclick="doUnblock('${r.ip}')">Unblock</button></td>
    </tr>`).join('');
}

async function fetchTopAttackers(){
  const rows=await apiFetch('/api/top-attackers');
  if(!rows)return;
  const tb=$('attackers-body');
  if(!rows.length)return;
  tb.innerHTML=rows.map(r=>`
    <tr>
      <td class="ip">${r.src_ip}</td>
      <td>${r.flag||'🌐'} ${r.country||''} ${r.city?'· '+r.city:''}</td>
      <td style="color:var(--red);font-weight:600">${r.incident_count}</td>
      <td style="font-size:11px;color:var(--muted)">${fmtDate(r.last_seen)}</td>
    </tr>`).join('');
}

async function doUnblock(ip){
  await apiFetch('/api/unblock',{method:'POST',body:JSON.stringify({ip})});
  addFeedLine('Manual unblock: '+ip,'ok');
  fetchBlocks();fetchStats();
}

function connectSSE(){
  const es=new EventSource('/stream?token='+encodeURIComponent(token()));
  es.onmessage=e=>{
    try{
      const d=JSON.parse(e.data);
      if(d.type==='incident'){
        const sev=d.payload?.severity;
        const ip=d.payload?.src_ip||d.payload?.ip;
        const cls=sev==='HIGH'?'alert':sev==='MEDIUM'?'warn':'info';
        addFeedLine(sev+' — '+ip+' — '+(d.payload?.reasons||[]).join('; '),cls);
        fetchStats();fetchIncidents();fetchBlocks();
      }else if(d.type==='action_block_scheduled'){
        addFeedLine('BLOCKED: '+d.payload?.ip,'alert');
        fetchBlocks();fetchStats();
      }else if(d.type==='event_auth'){
        const k=d.payload?.kind;
        if(k==='SSH_FAIL')addFeedLine('SSH FAIL from '+d.payload?.src_ip+' user='+(d.payload?.user||'?'),'warn');
        else if(k==='SSH_SUCCESS')addFeedLine('SSH OK from '+d.payload?.src_ip+' user='+(d.payload?.user||'?'),'ok');
      }
    }catch(err){}
  };
  es.onerror=()=>{
    addFeedLine('SSE disconnected, reconnecting...','info');
    es.close();
    setTimeout(connectSSE,3000);
  };
}

async function refresh(){
  await Promise.all([fetchStats(),fetchIncidents(),fetchBlocks(),fetchTopAttackers()]);
}

// Check auth before loading
if(!token()){location.href='/login';}
else{refresh();connectSSE();setInterval(refresh,10000);}
</script>
</body>
</html>"""



# Rate limiter for API endpoints


class _RateLimiter:
    def __init__(self, max_calls: int, window_sec: int):
        self._max    = max_calls
        self._window = window_sec
        self._calls: Dict[str, list] = {}

    def is_limited(self, key: str) -> bool:
        now    = time.time()
        cutoff = now - self._window
        calls  = [t for t in self._calls.get(key, []) if t > cutoff]
        self._calls[key] = calls
        if len(calls) >= self._max:
            return True
        calls.append(now)
        return False



# Dashboard server


async def start_dashboard(
    host:      str,
    port:      int,
    detector:  "Detector",
    blocker:   "Blocker",
    store:     "Store",
    metrics:   "Metrics",
    logger:    "JsonLogger",
    auth:      "AuthManager",
    dry_run:   bool = True,
    rbac:      Any = None,
    assets:    Any = None,
    honeypot:  Any = None,
) -> None:
    try:
        from aiohttp import web
    except ImportError:
        await logger.log("dashboard_error", {"error": "aiohttp not installed. Run: pip install aiohttp"})
        return

    _subscribers: list = []
    _api_limiter  = _RateLimiter(max_calls=60,  window_sec=60)
    _sse_limiter  = _RateLimiter(max_calls=10,  window_sec=60)

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

    logger.log = _patched_log

    router = web.RouteTableDef()

    # ── Auth helpers ──────────────────────────────────────────────────────────

    def _get_client_ip(req: web.Request) -> str:
        return req.headers.get("X-Forwarded-For", req.remote or "unknown").split(",")[0].strip()

    def _require_auth(req: web.Request):
        """Returns (payload, None) or (None, Response)."""
        if not auth.enabled:
            return {"sub": "anonymous", "role": "admin"}, None
        token = req.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            token = req.rel_url.query.get("token", "")
        payload, err = auth.verify_token(token)
        if err:
            return None, web.json_response({"error": err}, status=401)
        return payload, None

    def _require_perm(user_payload, perm: str):
        """Returns None if allowed, or a 403 Response if denied."""
        if rbac is None:
            return None
        role = user_payload.get("role", "viewer")
        err  = rbac.require(role, perm)
        if err:
            return web.json_response(err, status=403)
        return None

    def _rate_check(req: web.Request):
        ip = _get_client_ip(req)
        if _api_limiter.is_limited(ip):
            return web.json_response({"error": "Rate limit exceeded"}, status=429)
        return None

    # ── Pages ─────────────────────────────────────────────────────────────────

    @router.get("/login")
    async def login_page(_: web.Request) -> web.Response:
        return web.Response(text=_LOGIN_HTML, content_type="text/html")

    @router.get("/")
    async def index(req: web.Request) -> web.Response:
        if auth.enabled:
            token = req.cookies.get("cnsl_token") or req.rel_url.query.get("token", "")
            payload, err = auth.verify_token(token)
            if err:
                raise web.HTTPFound("/login")
        return web.Response(text=_HTML, content_type="text/html")

    # ── Auth endpoints ────────────────────────────────────────────────────────

    @router.post("/api/login")
    async def api_login(req: web.Request) -> web.Response:
        ip = _get_client_ip(req)
        body = await req.json()
        username = body.get("username", "")
        password = body.get("password", "")
        token, err = auth.login(username, password, client_ip=ip)
        if err:
            await logger.log("auth_login_fail", {"ip": ip, "username": username})
            return web.json_response({"error": err}, status=401)
        payload, _ = auth.verify_token(token)
        await logger.log("auth_login_ok", {"ip": ip, "username": username})
        return web.json_response({
            "token": token,
            "must_change_password": payload.get("mcp", False),
        })

    @router.post("/api/logout")
    async def api_logout(req: web.Request) -> web.Response:
        token_str = req.headers.get("Authorization", "").replace("Bearer ", "")
        auth.logout(token_str)
        return web.json_response({"ok": True})

    @router.get("/api/auth-info")
    async def api_auth_info(_: web.Request) -> web.Response:
        return web.json_response({
            "enabled":         auth.enabled,
            "default_password": auth.is_default_password(),
        })

    # ── API endpoints ─────────────────────────────────────────────────────────

    @router.get("/api/stats")
    async def api_stats(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        db = await store.stats() if store.available else {}
        return web.json_response({
            "total":            db.get("total", 0),
            "high":             db.get("high", 0),
            "medium":           db.get("medium", 0),
            "low":              0,
            "unique_ips":       db.get("unique_ips", len(detector._state)),
            "active_blocks":    len(blocker.active_blocks),
            "dry_run":          dry_run,
            "default_password": auth.is_default_password(),
        })

    @router.get("/api/incidents")
    async def api_incidents(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        try:
            limit = int(req.rel_url.query.get("limit", 50))
            limit = max(1, min(limit, 500))  # clamp: 1–500
        except (ValueError, TypeError):
            limit = 50
        rows  = await store.recent_incidents(limit) if store.available else []
        return web.json_response(rows)

    @router.get("/api/top-attackers")
    async def api_top(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        rows = await store.top_attackers() if store.available else []
        return web.json_response(rows)

    @router.get("/api/blocks")
    async def api_blocks(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        rows = await store.active_blocks() if store.available else []
        if not rows:
            rows = [
                {"ip": ip, "unblock_at": exp,
                 "blocked_at": exp - blocker.block_duration_sec}
                for ip, exp in blocker.active_blocks.items()
            ]
        return web.json_response(rows)

    @router.get("/api/metrics")
    async def api_metrics(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        return web.Response(text=metrics.render(), content_type="text/plain")

    @router.post("/api/block")
    async def api_block(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        user_payload, err = _require_auth(req)
        if err: return err
        if (r := _require_perm(user_payload, "block:write")): return r
        body = await req.json()
        ip   = body.get("ip", "").strip()
        if not ip:
            return web.json_response({"error": "ip required"}, status=400)
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return web.json_response({"error": f"invalid IP address: {ip!r}"}, status=400)
        ok = await blocker.block_ip(ip, reason=f"manual:{user_payload.get('sub','?')}")
        await logger.log("dashboard_manual_block", {"ip": ip, "by": user_payload.get("sub"), "ok": ok})
        return web.json_response({"blocked": ok, "ip": ip})

    @router.post("/api/unblock")
    async def api_unblock(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        user_payload, err = _require_auth(req)
        if err: return err
        if (r := _require_perm(user_payload, "unblock:write")): return r
        body = await req.json()
        ip   = body.get("ip", "").strip()
        if not ip:
            return web.json_response({"error": "ip required"}, status=400)
        await blocker._unblock_ip(ip)
        await logger.log("dashboard_manual_unblock", {"ip": ip, "by": user_payload.get("sub")})
        return web.json_response({"unblocked": True, "ip": ip})

    # ── SSE ───────────────────────────────────────────────────────────────────

    @router.get("/stream")
    async def sse_stream(req: web.Request) -> web.Response:
        ip = _get_client_ip(req)
        if _sse_limiter.is_limited(ip):
            return web.json_response({"error": "Too many SSE connections"}, status=429)

        _, err = _require_auth(req)
        if err: return err

        resp = web.StreamResponse(headers={
            "Content-Type":      "text/event-stream",
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
        })
        await resp.prepare(req)

        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        _subscribers.append(q)

        try:
            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=15.0)
                    await resp.write(f"data: {msg}\n\n".encode())
                except asyncio.TimeoutError:
                    await resp.write(b": heartbeat\n\n")
        except Exception:
            pass
        finally:
            try:
                _subscribers.remove(q)
            except ValueError:
                pass

        return resp

    # ── Start ─────────────────────────────────────────────────────────────────

    app = web.Application()
    app.add_routes(router)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()

    auth_status = "enabled" if auth.enabled else "disabled (open access)"
    await logger.log("dashboard_started", {
        "url":  f"http://{host}:{port}",
        "auth": auth_status,
    })
    print(f"\n   Dashboard → http://{host}:{port}  (auth: {auth_status})\n", flush=True)

    await asyncio.Event().wait()