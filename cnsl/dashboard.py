"""
cnsl/dashboard.py — Live web dashboard with JWT auth, SSE, REST API.

Routes:
  GET  /                     HTML dashboard (requires auth if enabled)
  GET  /login                Login page
  POST /api/login            Get JWT token
  POST /api/logout           Revoke token
  GET  /api/stats            Engine summary + uptime + ssh_fails
  GET  /api/incidents        Recent incidents
  GET  /api/top-attackers    Top attacker IPs
  GET  /api/timeline         Incident counts per hour (last 24h)
  GET  /api/blocks           Active blocks
  GET  /api/metrics          Prometheus text metrics
  GET  /api/ml               ML detector status + training progress
  GET  /api/fim              FIM recent alerts
  GET  /api/honeypot         Honeypot status + recent sessions
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
    from .auth        import AuthManager
    from .blocker     import Blocker
    from .detector    import Detector
    from .fim         import FIMEngine
    from .logger      import JsonLogger
    from .metrics     import Metrics
    from .ml_detector import MLDetector
    from .store       import Store


# SVG icon helpers 


def _svg(path_d: str, w: int = 16, h: int = 16) -> str:
    return (f'<svg width="{w}" height="{h}" viewBox="0 0 24 24" fill="none" '
            f'stroke="currentColor" stroke-width="2" stroke-linecap="round" '
            f'stroke-linejoin="round">{path_d}</svg>')

_I = {
    "shield":   _svg('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>', 18, 18),
    "alert":    _svg('<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>', 16, 16),
    "lock":     _svg('<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>', 16, 16),
    "users":    _svg('<path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/>', 16, 16),
    "cpu":      _svg('<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>', 16, 16),
    "terminal": _svg('<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>', 16, 16),
    "file":     _svg('<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>', 16, 16),
    "activity": _svg('<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>', 16, 16),
    "target":   _svg('<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>', 16, 16),
    "radio":    _svg('<circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 010 8.49m-8.48-.01a6 6 0 010-8.49m11.31-2.82a10 10 0 010 14.14m-14.14 0a10 10 0 010-14.14"/>', 16, 16),
    "clock":    _svg('<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>', 16, 16),
    "download": _svg('<path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>', 14, 14),
    "logout":   _svg('<path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>', 14, 14),
}


# Login page HTML


_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CNSL Login</title>
<style>
  :root{--bg:#0f1117;--surface:#1a1d27;--border:#2a2d3a;--text:#e2e8f0;
        --muted:#64748b;--accent:#6366f1;--red:#ef4444;}
  *{box-sizing:border-box;margin:0;padding:0;}
  body{
    background:var(--bg);
    color:var(--text);
    font-family:system-ui,sans-serif;
    display:flex;
    align-items:center;
    justify-content:center;
    min-height:100vh;
  }
  .card{
    background:var(--surface);
    border:1px solid var(--border);
    border-radius:12px;
    padding:2rem;
    width:100%;
    max-width:360px;
  }
  h1{
    font-size:17px;
    font-weight:600;
    argin-bottom:6px;
    display:flex;
    align-items:center;
    gap:8px;
    color:var(--accent);
  }
  .sub{font-size:13px;color:var(--muted);margin-bottom:1.5rem;}
  label{font-size:12px;color:var(--muted);display:block;margin-bottom:4px;}
  input{
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
  input:focus{border-color:var(--accent);}
  button{
    width:100%;
    padding:11px;
    background:var(--accent);
    color:#fff;
    border:none;
    border-radius:8px;
    font-size:14px;
    font-weight:500;
    cursor:pointer;
  }
  button:hover{opacity:.9;}
  .err{color:var(--red);font-size:13px;margin-top:1rem;display:none;}
  .warn{
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
  <h1><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>CNSL</h1>
  <p class="sub">Correlated Network Security Layer</p>
  <div id="warn" class="warn" style="display:none">Default password active. Change after login.</div>
  <label>Username</label>
  <input type="text" id="user" value="admin" autocomplete="username">
  <label>Password</label>
  <input type="password" id="pass" autocomplete="current-password" onkeydown="if(event.key==='Enter')doLogin()">
  <button onclick="doLogin()">Sign in</button>
  <div class="err" id="err"></div>
</div>
<script>
async function doLogin(){
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:document.getElementById('user').value,password:document.getElementById('pass').value})});
  const d=await r.json();
  if(d.token){localStorage.setItem('cnsl_token',d.token);location.href='/?token='+d.token;}
  else{const e=document.getElementById('err');e.textContent=d.error||'Login failed';e.style.display='block';}
}
fetch('/api/auth-info').then(r=>r.json()).then(d=>{if(d.default_password)document.getElementById('warn').style.display='block';}).catch(()=>{});
</script>
</body>
</html>"""


# Main dashboard HTML


_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CNSL Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
:root{--bg:#0f1117;--surf:#1a1d27;--bord:#2a2d3a;--text:#e2e8f0;--muted:#64748b;
  --acc:#6366f1;--red:#ef4444;--amber:#f59e0b;--green:#22c55e;--blue:#3b82f6;--purple:#a855f7;}
*{box-sizing:border-box;margin:0;padding:0;}
body{
  background:var(--bg);
  color:var(--text);
  font-family:'Segoe UI',system-ui,sans-serif;
  font-size:14px;
}
/* header */
header{
  background:var(--surf);
  border-bottom:1px solid var(--bord);
  padding:12px 24px;
  display:flex;
  align-items:center;
  gap:10px;
  position:sticky;
  top:0;
  z-index:100;
}
.hdr-logo{display:flex;align-items:center;gap:8px;}
.hdr-title{font-size:15px;font-weight:600;}
.badge{
  font-size:10px;
  padding:2px 7px;
  border-radius:99px;
  background:var(--acc);
  color:#fff;
}
.live-dot{
  width:7px;
  height:7px;
  border-radius:50%;
  background:var(--green);
  margin-left:auto;
  animation:pulse 2s infinite;
}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.hdr-btn{
  font-size:12px;
  padding:4px 10px;
  border:1px solid var(--bord);
  border-radius:6px;
  background:transparent;
  color:var(--muted);
  cursor:pointer;
}
.hdr-btn:hover{color:var(--red);border-color:var(--red);}
/* nav tabs */
.nav{
  background:var(--surf);
  border-bottom:1px solid var(--bord);
  display:flex;
  padding:0 24px;
  gap:4px;
}
.tab{
  padding:10px 16px;
  font-size:13px;
  color:var(--muted);
  cursor:pointer;
  border-bottom:2px solid transparent;
  display:flex;
  align-items:center;
  gap:6px;
}
.tab:hover{color:var(--text);}
.tab.active{color:var(--text);border-bottom-color:var(--acc);}
/* page sections */
.page{display:none;padding:20px 24px;}
.page.active{display:block;}
/* banners */
.banner{
  border-radius:8px;
  padding:10px 14px;
  margin-bottom:16px;
  font-size:12px;
  display:flex;
  align-items:center;
  gap:8px;
}
.banner-warn{
  background:rgba(245,158,11,.1);
  border:1px solid var(--amber);
  color:var(--amber);
}
.banner-red{
  background:rgba(239,68,68,.1);
  border:1px solid var(--red);
  color:var(--red);
}
/* stat grid */
.stat-grid{
  display:grid;
  grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
  gap:12px;
  margin-bottom:20px;
}
.stat{
  background:var(--surf);
  border:1px solid var(--bord);
  border-radius:10px;
  padding:16px;
}
.stat-lbl{
  font-size:11px;
  color:var(--muted);
  text-transform:uppercase;
  letter-spacing:.05em;
  margin-bottom:6px;
  display:flex;
  align-items:center;
  gap:5px;
}
.stat-val{font-size:26px;font-weight:700;}
.c-red{color:var(--red);}.c-amber{color:var(--amber);}.c-green{color:var(--green);}.c-blue{color:var(--blue);}
.c-purple{color:var(--purple);}.c-muted{color:var(--muted);}
/* chart grid */
.chart-grid{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:14px;
  margin-bottom:20px;
}
.chart-box{
  background:var(--surf);
  border:1px solid var(--bord);
  border-radius:10px;
  padding:14px;
}
.chart-box h3{
  font-size:11px;
  color:var(--muted);
  text-transform:uppercase;
  letter-spacing:.05em;
  margin-bottom:10px;
}
canvas{max-height:180px;}
/* tables */
.tbl-wrap{
  background:var(--surf);
  border:1px solid var(--bord);
  border-radius:10px;
  overflow:hidden;
  margin-bottom:16px;
}
.tbl-head{
  padding:10px 14px;
  border-bottom:1px solid var(--bord);
  font-size:12px;
  color:var(--muted);
  display:flex;
  align-items:center;
  justify-content:space-between;
}
.tbl-head-title{
  display:flex;
  align-items:center;
  gap:6px;
  font-weight:500;
  color:var(--text);
}
table{width:100%;border-collapse:collapse;}
th{
  text-align:left;
  font-size:11px;
  color:var(--muted);
  text-transform:uppercase;
  padding:8px 14px;
  border-bottom:1px solid var(--bord);
}
td{
  padding:9px 14px;
  border-bottom:1px solid var(--bord);
  font-size:13px;
  vertical-align:middle;
}
tr:last-child td{border-bottom:none;}
tr:hover td{background:rgba(255,255,255,.02);}
.mono{font-family:monospace;font-size:12px;}
/* severity badges */
.sev{font-size:10px;font-weight:600;padding:2px 7px;border-radius:4px;}
.sev-CRITICAL{background:rgba(168,85,247,.2);color:var(--purple);}
.sev-HIGH{background:rgba(239,68,68,.15);color:var(--red);}
.sev-MEDIUM{background:rgba(245,158,11,.15);color:var(--amber);}
.sev-LOW{background:rgba(59,130,246,.15);color:var(--blue);}
/* change badges */
.chg{font-size:10px;font-weight:600;padding:2px 7px;border-radius:4px;}
.chg-modified{background:rgba(245,158,11,.15);color:var(--amber);}
.chg-created{background:rgba(34,197,94,.15);color:var(--green);}
.chg-deleted{background:rgba(239,68,68,.15);color:var(--red);}
.chg-permission{background:rgba(168,85,247,.15);color:var(--purple);}
/* buttons */
.btn{
  font-size:11px;
  padding:3px 10px;
  border-radius:5px;
  border:1px solid;
  cursor:pointer;
  background:transparent;
}
.btn-green{border-color:var(--green);color:var(--green);}.btn-green:hover{background:rgba(34,197,94,.1);}
.btn-red{border-color:var(--red);color:var(--red);}.btn-red:hover{background:rgba(239,68,68,.1);}
/* live feed */
.feed{background:var(--bg);border-radius:8px;height:220px;overflow-y:auto;
  padding:10px;font-family:monospace;font-size:11px;border:1px solid var(--bord);}
.feed-line{padding:2px 0;border-bottom:1px solid rgba(255,255,255,.03);}
.feed-alert{color:var(--red);}.feed-warn{color:var(--amber);}
.feed-ok{color:var(--green);}.feed-info{color:var(--muted);}
.feed-purple{color:var(--purple);}
/* ML progress */
.prog-bar{height:8px;background:var(--bord);border-radius:4px;overflow:hidden;margin-top:6px;}
.prog-fill{height:100%;background:var(--acc);border-radius:4px;transition:width .4s;}
/* status pill */
.pill{font-size:10px;padding:2px 8px;border-radius:99px;font-weight:500;}
.pill-on{background:rgba(34,197,94,.15);color:var(--green);}
.pill-off{background:rgba(100,116,139,.15);color:var(--muted);}
/* manual block form */
.block-form{display:flex;gap:8px;padding:10px 14px;border-top:1px solid var(--bord);}
.block-input{flex:1;padding:6px 10px;background:var(--bg);border:1px solid var(--bord);
  border-radius:6px;color:var(--text);font-size:13px;outline:none;}
.block-input:focus{border-color:var(--acc);}
/* uptime */
.sys-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px;}
/* section header */
.sec-hdr{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;
  letter-spacing:.06em;margin-bottom:10px;display:flex;align-items:center;gap:6px;}
/* pdf/print */
@media print{
  header,nav,.hdr-btn,.btn,#dry-run-banner,#default-pw-banner,.live-dot,#pdf-btn{display:none!important;}
  body{background:#fff!important;color:#000!important;}
  .page{display:block!important;padding:0;}
  .stat{border:1px solid #ddd!important;background:#fff!important;}
  .tbl-wrap{border:1px solid #ddd!important;}
  canvas{max-height:160px;}
}
</style>
</head>
<body>

<header>
  <div class="hdr-logo">
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
      <path d="M10 2L3 5.5V10c0 3.87 2.93 7.5 7 8.45C17.07 17.5 20 13.87 20 10V5.5L10 2z"
            fill="none" stroke="#6366f1" stroke-width="1.5" stroke-linejoin="round"/>
      <path d="M7 10l2 2 4-4" stroke="#6366f1" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <span class="hdr-title">CNSL</span>
    <span class="badge">v1.0</span>
  </div>
  <div class="live-dot" title="Live"></div>
  <button class="hdr-btn" id="pdf-btn" onclick="exportPDF()" title="Export PDF report">
    <svg width="12" height="12" viewBox="0 0 12 12" fill="none" style="margin-right:4px;vertical-align:middle">
      <path d="M2 1h5.5L10 3.5V11H2V1z" stroke="currentColor" stroke-width="1.1" stroke-linejoin="round"/>
      <path d="M7 1v3h3" stroke="currentColor" stroke-width="1.1" stroke-linejoin="round"/>
      <path d="M4 6.5h4M4 8.5h2.5" stroke="currentColor" stroke-width="1.1" stroke-linecap="round"/>
    </svg>Export PDF
  </button>
  <button class="hdr-btn" onclick="doLogout()">Logout</button>
</header>

<nav class="nav">
  <div class="tab active" onclick="showTab('overview')" id="tab-overview">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <rect x="1" y="1" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.2"/>
      <rect x="8" y="1" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.2"/>
      <rect x="1" y="8" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.2"/>
      <rect x="8" y="8" width="5" height="5" rx="1" stroke="currentColor" stroke-width="1.2"/>
    </svg>
    Overview
  </div>
  <div class="tab" onclick="showTab('incidents')" id="tab-incidents">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <path d="M7 2v4M7 9v1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
      <path d="M1.5 12L7 2l5.5 10H1.5z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
    </svg>
    Incidents
  </div>
  <div class="tab" onclick="showTab('blocks')" id="tab-blocks">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <circle cx="7" cy="7" r="5.5" stroke="currentColor" stroke-width="1.2"/>
      <path d="M3.5 3.5l7 7" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
    </svg>
    Blocks
  </div>
  <div class="tab" onclick="showTab('honeypot')" id="tab-honeypot">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <ellipse cx="7" cy="9" rx="5" ry="3" stroke="currentColor" stroke-width="1.2"/>
      <path d="M2 9V5.5C2 4 4.24 3 7 3s5 1 5 2.5V9" stroke="currentColor" stroke-width="1.2"/>
    </svg>
    Honeypot
  </div>
  <div class="tab" onclick="showTab('fim')" id="tab-fim">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <path d="M3 2h5.5L11 4.5V12H3V2z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
      <path d="M8.5 2v3H11" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
      <path d="M5 7h4M5 9.5h2.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
    </svg>
    FIM
  </div>
  <div class="tab" onclick="showTab('ml')" id="tab-ml">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <circle cx="7" cy="3" r="1.5" stroke="currentColor" stroke-width="1.2"/>
      <circle cx="2.5" cy="10" r="1.5" stroke="currentColor" stroke-width="1.2"/>
      <circle cx="11.5" cy="10" r="1.5" stroke="currentColor" stroke-width="1.2"/>
      <path d="M7 4.5L2.5 8.5M7 4.5l4.5 4" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
      <path d="M2.5 10h9" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
    </svg>
    ML
  </div>
  <div class="tab" onclick="showTab('feed')" id="tab-feed">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <path d="M2 4h10M2 7h7M2 10h5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
    </svg>
    Live Feed
  </div>
</nav>

<!-- banners -->
<div id="dry-run-banner" style="display:none;margin:12px 24px 0" class="banner banner-warn">
  <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
    <path d="M7 2v4M7 9v1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
    <path d="M1.5 12L7 2l5.5 10H1.5z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
  </svg>
  DRY-RUN MODE — No real iptables commands executed.
</div>
<div id="default-pw-banner" style="display:none;margin:12px 24px 0" class="banner banner-red">
  <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
    <rect x="3" y="6" width="8" height="6" rx="1" stroke="currentColor" stroke-width="1.2"/>
    <path d="M5 6V4a2 2 0 014 0v2" stroke="currentColor" stroke-width="1.2"/>
  </svg>
  Default password in use. Update config.json.
</div>

<!-- ─────────────────── OVERVIEW ─────────────────── -->
<div class="page active" id="page-overview">

  <div class="stat-grid">
    <div class="stat">
      <div class="stat-lbl">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
          <path d="M1 11L6 2l5 9H1z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
        </svg>
        Total Incidents
      </div>
      <div class="stat-val" id="s-total">—</div>
    </div>
    <div class="stat">
      <div class="stat-lbl">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
          <path d="M6 1v3M6 8v1" stroke="#ef4444" stroke-width="1.5" stroke-linecap="round"/>
          <path d="M1 11L6 1l5 10H1z" stroke="#ef4444" stroke-width="1.2" stroke-linejoin="round"/>
        </svg>
        HIGH Severity
      </div>
      <div class="stat-val c-red" id="s-high">—</div>
    </div>
    <div class="stat">
      <div class="stat-lbl">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
          <circle cx="6" cy="6" r="5" stroke="#f59e0b" stroke-width="1.2"/>
          <path d="M4 4l4 4M8 4L4 8" stroke="#f59e0b" stroke-width="1.2" stroke-linecap="round"/>
        </svg>
        Active Blocks
      </div>
      <div class="stat-val c-amber" id="s-blocks">—</div>
    </div>
    <div class="stat">
      <div class="stat-lbl">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
          <circle cx="6" cy="4" r="2.5" stroke="#3b82f6" stroke-width="1.2"/>
          <path d="M1 11c0-2.76 2.24-5 5-5s5 2.24 5 5" stroke="#3b82f6" stroke-width="1.2" stroke-linecap="round"/>
        </svg>
        Unique Attackers
      </div>
      <div class="stat-val c-blue" id="s-unique">—</div>
    </div>
    <div class="stat">
      <div class="stat-lbl">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
          <circle cx="6" cy="6" r="5" stroke="#64748b" stroke-width="1.2"/>
          <path d="M6 3v3l2 2" stroke="#64748b" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        Uptime
      </div>
      <div class="stat-val c-muted" id="s-uptime">—</div>
    </div>
    <div class="stat">
      <div class="stat-lbl">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
          <path d="M1 9L4 6l2.5 2.5L9 4l2 2" stroke="#22c55e" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        SSH Fails Total
      </div>
      <div class="stat-val c-green" id="s-ssh-fails">—</div>
    </div>
    <div class="stat">
      <div class="stat-lbl">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
          <path d="M2 6h8M7 3l3 3-3 3" stroke="#6366f1" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        Events Processed
      </div>
      <div class="stat-val c-purple" id="s-events">—</div>
    </div>
    <div class="stat">
      <div class="stat-lbl">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
          <rect x="1" y="3" width="10" height="7" rx="1" stroke="#64748b" stroke-width="1.2"/>
          <path d="M4 3V2M8 3V2" stroke="#64748b" stroke-width="1.2" stroke-linecap="round"/>
        </svg>
        All-time Blocks
      </div>
      <div class="stat-val c-muted" id="s-blocks-total">—</div>
    </div>
  </div>

  <div class="chart-grid">
    <div class="chart-box">
      <h3>Incidents — last 24h</h3>
      <canvas id="chart-timeline" role="img" aria-label="Incidents over last 24 hours">Incident timeline chart</canvas>
    </div>
    <div class="chart-box">
      <h3>Severity breakdown</h3>
      <canvas id="chart-severity" role="img" aria-label="Severity breakdown doughnut">Severity chart</canvas>
    </div>
  </div>

  <div class="sec-hdr">
    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
      <circle cx="6" cy="4" r="2.5" stroke="currentColor" stroke-width="1.2"/>
      <path d="M1 11c0-2.76 2.24-5 5-5s5 2.24 5 5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
    </svg>
    Top attackers
  </div>
  <div class="tbl-wrap">
    <table>
      <thead><tr><th>IP</th><th>Location</th><th>Incidents</th><th>Last seen</th></tr></thead>
      <tbody id="attackers-body"><tr><td colspan="4" style="color:var(--muted);text-align:center;padding:20px">No data</td></tr></tbody>
    </table>
  </div>

</div>

<!-- ─────────────────── INCIDENTS ─────────────────── -->
<div class="page" id="page-incidents">

  <div class="tbl-wrap">
    <div class="tbl-head">
      <span class="tbl-head-title">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
          <path d="M7 2v4M7 9v1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
          <path d="M1.5 12L7 2l5.5 10H1.5z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
        </svg>
        Recent Incidents
      </span>
      <span style="font-size:11px;color:var(--muted)" id="incidents-count"></span>
    </div>
    <table>
      <thead><tr><th>Time</th><th>IP</th><th>Location</th><th>Severity</th><th>Fails</th><th>Reason</th></tr></thead>
      <tbody id="incidents-body"><tr><td colspan="6" style="color:var(--muted);text-align:center;padding:20px">No incidents</td></tr></tbody>
    </table>
  </div>

</div>

<!-- ─────────────────── BLOCKS ─────────────────── -->
<div class="page" id="page-blocks">

  <div class="tbl-wrap">
    <div class="tbl-head">
      <span class="tbl-head-title">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
          <circle cx="7" cy="7" r="5.5" stroke="currentColor" stroke-width="1.2"/>
          <path d="M3.5 3.5l7 7" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
        </svg>
        Active Blocks
      </span>
    </div>
    <table>
      <thead><tr><th>IP</th><th>Location</th><th>Blocked at</th><th>Expires</th><th></th></tr></thead>
      <tbody id="blocks-body"><tr><td colspan="5" style="color:var(--muted);text-align:center;padding:20px">No active blocks</td></tr></tbody>
    </table>
    <div class="block-form">
      <input class="block-input" id="manual-block-ip" placeholder="Manual block: enter IP address (e.g. 1.2.3.4)">
      <button class="btn btn-red" onclick="doManualBlock()">Block IP</button>
    </div>
  </div>

</div>

<!-- ─────────────────── HONEYPOT ─────────────────── -->
<div class="page" id="page-honeypot">

  <div class="stat-grid" style="grid-template-columns:repeat(3,1fr)">
    <div class="stat">
      <div class="stat-lbl">Status</div>
      <div style="margin-top:6px" id="hp-status"><span class="pill pill-off">disabled</span></div>
    </div>
    <div class="stat">
      <div class="stat-lbl">Mode</div>
      <div class="stat-val c-muted" style="font-size:16px" id="hp-mode">—</div>
    </div>
    <div class="stat">
      <div class="stat-lbl">Active Redirects</div>
      <div class="stat-val c-amber" id="hp-redirects">—</div>
    </div>
  </div>

  <div class="tbl-wrap">
    <div class="tbl-head">
      <span class="tbl-head-title">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
          <ellipse cx="7" cy="9" rx="5" ry="3" stroke="currentColor" stroke-width="1.2"/>
          <path d="M2 9V5.5C2 4 4.24 3 7 3s5 1 5 2.5V9" stroke="currentColor" stroke-width="1.2"/>
        </svg>
        Honeypot Sessions
      </span>
    </div>
    <table>
      <thead><tr><th>IP</th><th>Time</th><th>Duration</th><th>Auth attempts</th><th>Commands</th></tr></thead>
      <tbody id="hp-body"><tr><td colspan="5" style="color:var(--muted);text-align:center;padding:20px">No sessions</td></tr></tbody>
    </table>
  </div>

</div>

<!-- ─────────────────── FIM ─────────────────── -->
<div class="page" id="page-fim">

  <div id="fim-disabled-msg" style="display:none" class="banner banner-warn">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <path d="M7 2v4M7 9v1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
      <path d="M1.5 12L7 2l5.5 10H1.5z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
    </svg>
    FIM is disabled. Enable in config.json under "fim.enabled": true
  </div>

  <div id="fim-watch-paths" style="margin-bottom:14px;display:none">
    <div class="sec-hdr">Watched paths</div>
    <div id="fim-paths-list" style="font-family:monospace;font-size:12px;color:var(--muted);
      background:var(--surf);border:1px solid var(--bord);border-radius:8px;padding:10px 14px;line-height:1.8">
    </div>
  </div>

  <div class="tbl-wrap">
    <div class="tbl-head">
      <span class="tbl-head-title">
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
          <path d="M3 2h5.5L11 4.5V12H3V2z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
          <path d="M8.5 2v3H11" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
        </svg>
        File Integrity Alerts
      </span>
    </div>
    <table>
      <thead><tr><th>Time</th><th>Path</th><th>Change</th><th>Severity</th></tr></thead>
      <tbody id="fim-body"><tr><td colspan="4" style="color:var(--muted);text-align:center;padding:20px">No alerts</td></tr></tbody>
    </table>
  </div>

</div>

<!-- ─────────────────── ML ─────────────────── -->
<div class="page" id="page-ml">

  <div class="stat-grid" style="grid-template-columns:repeat(3,1fr);margin-bottom:14px">
    <div class="stat">
      <div class="stat-lbl">ML Detector</div>
      <div style="margin-top:6px" id="ml-status-pill"><span class="pill pill-off">disabled</span></div>
    </div>
    <div class="stat">
      <div class="stat-lbl">Model trained</div>
      <div style="margin-top:6px" id="ml-trained-pill"><span class="pill pill-off">not trained</span></div>
    </div>
    <div class="stat">
      <div class="stat-lbl">Tracked IPs</div>
      <div class="stat-val c-blue" id="ml-tracked">—</div>
    </div>
  </div>

  <div class="tbl-wrap" style="margin-bottom:14px">
    <div class="tbl-head">
      <span class="tbl-head-title">Training progress</span>
      <span style="font-size:11px;color:var(--muted)" id="ml-sample-lbl"></span>
    </div>
    <div style="padding:14px 16px">
      <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--muted);margin-bottom:6px">
        <span>Samples collected</span>
        <span id="ml-sample-count">0 / 0</span>
      </div>
      <div class="prog-bar"><div class="prog-fill" id="ml-prog" style="width:0%"></div></div>
      <div style="margin-top:10px;font-size:12px;color:var(--muted)">
        Last trained: <span id="ml-last-trained" style="color:var(--text)">never</span>
      </div>
    </div>
  </div>

  <div id="ml-disabled-note" style="display:none" class="banner banner-warn">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <path d="M7 2v4M7 9v1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
      <path d="M1.5 12L7 2l5.5 10H1.5z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
    </svg>
    ML is disabled. Set "ml.enabled": true in config.json and install scikit-learn.
  </div>

</div>

<!-- ─────────────────── LIVE FEED ─────────────────── -->
<div class="page" id="page-feed">

  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
    <div class="sec-hdr" style="margin-bottom:0">
      <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
        <path d="M2 4h8M2 7h5M2 10h3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
      </svg>
      Real-time event stream
    </div>
    <button class="btn btn-green" onclick="clearFeed()">Clear</button>
  </div>
  <div class="feed" id="live-feed"></div>

</div>

<script>
const $=id=>document.getElementById(id);
const fmtDate=ts=>ts?new Date(ts*1000).toLocaleString():'—';
const fmtTime=ts=>ts?new Date(ts*1000).toLocaleTimeString():'—';
const token=()=>localStorage.getItem('cnsl_token')||'';
const authHdr=()=>({'Content-Type':'application/json','Authorization':'Bearer '+token()});

// ── Tab navigation ────────────────────────────────────────────────────────
function showTab(name){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  $('tab-'+name).classList.add('active');
  $('page-'+name).classList.add('active');
}

// ── Auth ──────────────────────────────────────────────────────────────────
async function doLogout(){
  await fetch('/api/logout',{method:'POST',headers:authHdr()}).catch(()=>{});
  localStorage.removeItem('cnsl_token');
  location.href='/login';
}

// ── API fetch helper ──────────────────────────────────────────────────────
async function apiFetch(url,opts={}){
  opts.headers={...authHdr(),...(opts.headers||{})};
  const r=await fetch(url,opts);
  if(r.status===401){location.href='/login';return null;}
  return r.json();
}

// ── Charts ────────────────────────────────────────────────────────────────
const tlChart=new Chart($('chart-timeline').getContext('2d'),{type:'line',
  data:{labels:[],datasets:[
    {label:'HIGH',data:[],borderColor:'#ef4444',backgroundColor:'rgba(239,68,68,.1)',tension:.3,fill:true,pointRadius:2},
    {label:'MEDIUM',data:[],borderColor:'#f59e0b',backgroundColor:'rgba(245,158,11,.07)',tension:.3,fill:true,pointRadius:2}
  ]},
  options:{responsive:true,maintainAspectRatio:true,
    plugins:{legend:{labels:{color:'#64748b',font:{size:10},boxWidth:10}}},
    scales:{x:{ticks:{color:'#64748b',font:{size:9},autoSkip:true,maxRotation:0},grid:{color:'#1e2130'}},
            y:{ticks:{color:'#64748b',font:{size:9}},grid:{color:'#1e2130'},beginAtZero:true}}}
});

const sevChart=new Chart($('chart-severity').getContext('2d'),{type:'doughnut',
  data:{labels:['HIGH','MEDIUM','LOW'],
        datasets:[{data:[0,0,0],backgroundColor:['#ef4444','#f59e0b','#3b82f6'],
          borderWidth:0,hoverOffset:4}]},
  options:{responsive:true,maintainAspectRatio:true,cutout:'65%',
    plugins:{legend:{labels:{color:'#64748b',font:{size:10},boxWidth:10}}}}
});

// ── Live Feed ─────────────────────────────────────────────────────────────
function addFeed(text,cls='feed-info'){
  const feed=$('live-feed');
  const line=document.createElement('div');
  line.className='feed-line '+cls;
  line.textContent='['+new Date().toLocaleTimeString()+'] '+text;
  feed.prepend(line);
  while(feed.children.length>300)feed.removeChild(feed.lastChild);
}
function clearFeed(){$('live-feed').innerHTML='';}

// ── Fetchers ──────────────────────────────────────────────────────────────
async function fetchSystem(){
  const d=await apiFetch('/api/system');
  if(!d)return;
  const u=d.uptime_sec||0;
  const h=Math.floor(u/3600),m=Math.floor((u%3600)/60),s=u%60;
  $('s-uptime').textContent=h>0?h+'h '+m+'m':m+'m '+s+'s';
  $('s-ssh-fails').textContent=(d.ssh_fails_total??0).toLocaleString();
  $('s-events').textContent=(d.events_processed??0).toLocaleString();
  $('s-blocks-total').textContent=(d.blocks_total??0).toLocaleString();
}

async function fetchStats(){
  const d=await apiFetch('/api/stats');
  if(!d)return;
  $('s-total').textContent=(d.total??0).toLocaleString();
  $('s-high').textContent=(d.high??0).toLocaleString();
  $('s-blocks').textContent=(d.active_blocks??0).toLocaleString();
  $('s-unique').textContent=(d.unique_ips??0).toLocaleString();
  sevChart.data.datasets[0].data=[d.high||0,d.medium||0,d.low||0];
  sevChart.update('none');
  if(d.dry_run)$('dry-run-banner').style.display='flex';
  if(d.default_password)$('default-pw-banner').style.display='flex';
}

async function fetchTimeline(){
  const rows=await apiFetch('/api/timeline');
  if(!rows||!rows.length)return;
  const labels=[],hMap={},mMap={};
  for(let i=0;i<24;i++){
    labels.push(new Date(Date.now()-(23-i)*3600000).getHours().toString().padStart(2,'0')+':00');
    hMap[i]=0;mMap[i]=0;
  }
  rows.forEach(r=>{
    const idx=Math.min(23,Math.max(0,r.hour_offset));
    if(r.severity==='HIGH')hMap[idx]+=r.count;
    else if(r.severity==='MEDIUM')mMap[idx]+=r.count;
  });
  tlChart.data.labels=labels;
  tlChart.data.datasets[0].data=Object.values(hMap);
  tlChart.data.datasets[1].data=Object.values(mMap);
  tlChart.update('none');
}

async function fetchIncidents(){
  const rows=await apiFetch('/api/incidents');
  if(!rows)return;
  const tb=$('incidents-body');
  $('incidents-count').textContent=rows.length+' records';
  if(!rows.length)return;
  tb.innerHTML=rows.slice(0,50).map(r=>`
    <tr>
      <td style="color:var(--muted);font-size:11px">${fmtDate(r.ts)}</td>
      <td class="mono">${r.src_ip||'—'}</td>
      <td style="font-size:12px">${r.flag||''} ${r.country||'—'}</td>
      <td><span class="sev sev-${r.severity}">${r.severity}</span></td>
      <td style="color:var(--muted)">${r.fail_count||0}</td>
      <td style="font-size:11px;color:var(--muted);max-width:200px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
        ${(r.reasons||[]).join(', ')||'—'}
      </td>
    </tr>`).join('');
}

async function fetchBlocks(){
  const rows=await apiFetch('/api/blocks');
  if(!rows)return;
  const tb=$('blocks-body');
  if(!rows.length){
    tb.innerHTML='<tr><td colspan="5" style="color:var(--muted);text-align:center;padding:20px">No active blocks</td></tr>';
    return;
  }
  tb.innerHTML=rows.map(r=>`
    <tr>
      <td class="mono">${r.ip}</td>
      <td style="font-size:12px">${r.flag||''} ${r.country||'—'}</td>
      <td style="font-size:11px;color:var(--muted)">${fmtDate(r.blocked_at)}</td>
      <td style="font-size:11px;color:var(--amber)">${fmtDate(r.unblock_at)}</td>
      <td><button class="btn btn-green" onclick="doUnblock('${r.ip}')">Unblock</button></td>
    </tr>`).join('');
}

async function fetchTopAttackers(){
  const rows=await apiFetch('/api/top-attackers');
  if(!rows||!rows.length)return;
  $('attackers-body').innerHTML=rows.map(r=>`
    <tr>
      <td class="mono">${r.src_ip}</td>
      <td style="font-size:12px">${r.flag||''} ${r.country||'—'} ${r.city?'· '+r.city:''}</td>
      <td class="c-red" style="font-weight:600">${r.incident_count}</td>
      <td style="font-size:11px;color:var(--muted)">${fmtDate(r.last_seen)}</td>
    </tr>`).join('');
}

async function fetchHoneypot(){
  const d=await apiFetch('/api/honeypot');
  if(!d)return;
  $('hp-status').innerHTML=d.enabled
    ?'<span class="pill pill-on">enabled</span>'
    :'<span class="pill pill-off">disabled</span>';
  $('hp-mode').textContent=d.mode||'—';
  $('hp-redirects').textContent=d.active_redirects??'0';
  const tb=$('hp-body');
  const sess=d.sessions||[];
  if(!sess.length){
    tb.innerHTML='<tr><td colspan="5" style="color:var(--muted);text-align:center;padding:20px">No sessions yet</td></tr>';
    return;
  }
  tb.innerHTML=sess.map(s=>`
    <tr>
      <td class="mono">${s.attacker_ip}</td>
      <td style="font-size:11px;color:var(--muted)">${s.time||fmtDate(s.start_time)}</td>
      <td style="color:var(--muted)">${Math.round(s.duration_sec||0)}s</td>
      <td style="color:var(--amber)">${(s.auth_attempts||[]).length}</td>
      <td class="cmds">${(s.commands||[]).join(' | ')||'—'}</td>
    </tr>`).join('');
}

async function fetchFIM(){
  const d=await apiFetch('/api/fim');
  console.log('[CNSL] /api/fim →', d);
  if(!d)return;
  const enabled = d.enabled === true;
  $('fim-disabled-msg').style.display=enabled?'none':'flex';
  $('fim-watch-paths').style.display=enabled?'block':'none';
  if(!enabled)return;
  $('fim-paths-list').innerHTML=(d.watch_paths||[]).map(p=>`<div>${p}</div>`).join('');
  const tb=$('fim-body');
  const alerts=d.alerts||[];
  if(!alerts.length){
    tb.innerHTML='<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:20px">No alerts</td></tr>';
    return;
  }
  tb.innerHTML=alerts.map(a=>`
    <tr>
      <td style="font-size:11px;color:var(--muted)">${a.time||fmtDate(a.ts)}</td>
      <td class="mono" style="font-size:11px;max-width:220px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${a.path}</td>
      <td><span class="chg chg-${a.change}">${a.change}</span></td>
      <td><span class="sev sev-${a.severity}">${a.severity}</span></td>
    </tr>`).join('');
}

async function fetchML(){
  const d=await apiFetch('/api/ml-status');
  console.log('[CNSL] /api/ml-status →', d);
  if(!d)return;
  const enabled = d.enabled === true;
  $('ml-status-pill').innerHTML=enabled
    ?'<span class="pill pill-on">enabled</span>'
    :'<span class="pill pill-off">disabled</span>';
  $('ml-disabled-note').style.display=enabled?'none':'flex';
  if(!enabled)return;
  const trained = d.trained === true;
  $('ml-trained-pill').innerHTML=trained
    ?'<span class="pill pill-on">trained</span>'
    :'<span class="pill pill-off">not trained</span>';
  $('ml-tracked').textContent=d.tracked_ips??'0';
  const cur=d.training_samples||0;
  const min=d.min_samples||100;
  const pct=Math.min(100,Math.round(cur/min*100));
  $('ml-sample-count').textContent=cur+' / '+min;
  $('ml-prog').style.width=pct+'%';
  $('ml-last-trained').textContent=d.last_trained||'never';
}

// ── Actions ───────────────────────────────────────────────────────────────
async function doUnblock(ip){
  await apiFetch('/api/unblock',{method:'POST',body:JSON.stringify({ip})});
  addFeed('Manual unblock: '+ip,'feed-ok');
  fetchBlocks();fetchStats();
}

async function doManualBlock(){
  const ip=$('manual-block-ip').value.trim();
  if(!ip)return;
  const r=await apiFetch('/api/block',{method:'POST',body:JSON.stringify({ip})});
  if(r&&r.blocked){
    addFeed('Manual block: '+ip,'feed-alert');
    $('manual-block-ip').value='';
    fetchBlocks();fetchStats();
  }
}
$('manual-block-ip').addEventListener('keydown',e=>{if(e.key==='Enter')doManualBlock();});

// ── PDF Export ────────────────────────────────────────────────────────────
async function exportPDF(){
  const btn=$('pdf-btn');
  btn.textContent='Preparing...';
  btn.disabled=true;

  // Collect all current data
  const [stats, sys, incidents, blocks, attackers, ml, hp, fim] = await Promise.all([
    apiFetch('/api/stats'),
    apiFetch('/api/system'),
    apiFetch('/api/incidents?limit=100'),
    apiFetch('/api/blocks'),
    apiFetch('/api/top-attackers'),
    apiFetch('/api/ml-status'),
    apiFetch('/api/honeypot'),
    apiFetch('/api/fim'),
  ]);

  const now = new Date().toLocaleString();
  const uptime = sys ? (() => {
    const u=sys.uptime_sec||0, h=Math.floor(u/3600), m=Math.floor((u%3600)/60);
    return h>0?h+'h '+m+'m':m+'m';
  })() : '—';

  const sevColor = s => s==='HIGH'?'#ef4444':s==='MEDIUM'?'#f59e0b':s==='LOW'?'#3b82f6':'#a855f7';

  const incRows = (incidents||[]).slice(0,50).map(r=>`
    <tr>
      <td>${new Date((r.ts||0)*1000).toLocaleString()}</td>
      <td style="font-family:monospace">${r.src_ip||'—'}</td>
      <td>${r.flag||''} ${r.country||'—'}</td>
      <td><span style="background:${sevColor(r.severity)}22;color:${sevColor(r.severity)};
        padding:2px 6px;border-radius:3px;font-size:11px;font-weight:600">${r.severity}</span></td>
      <td>${r.fail_count||0}</td>
      <td style="font-size:11px;max-width:200px">${(r.reasons||[]).join(', ')||'—'}</td>
    </tr>`).join('');

  const blkRows = (blocks||[]).map(r=>`
    <tr>
      <td style="font-family:monospace">${r.ip}</td>
      <td>${r.flag||''} ${r.country||'—'}</td>
      <td>${new Date((r.blocked_at||0)*1000).toLocaleString()}</td>
      <td>${new Date((r.unblock_at||0)*1000).toLocaleString()}</td>
    </tr>`).join('');

  const atkRows = (attackers||[]).map(r=>`
    <tr>
      <td style="font-family:monospace">${r.src_ip}</td>
      <td>${r.flag||''} ${r.country||'—'}</td>
      <td style="font-weight:600;color:#ef4444">${r.incident_count}</td>
      <td>${new Date((r.last_seen||0)*1000).toLocaleString()}</td>
    </tr>`).join('');

  const fimRows = (fim?.alerts||[]).slice(0,30).map(a=>`
    <tr>
      <td>${a.time||new Date((a.ts||0)*1000).toLocaleString()}</td>
      <td style="font-family:monospace;font-size:11px">${a.path}</td>
      <td>${a.change}</td>
      <td><span style="background:${sevColor(a.severity)}22;color:${sevColor(a.severity)};
        padding:2px 6px;border-radius:3px;font-size:11px;font-weight:600">${a.severity}</span></td>
    </tr>`).join('');

  const hpRows = (hp?.sessions||[]).slice(0,20).map(s=>`
    <tr>
      <td style="font-family:monospace">${s.attacker_ip}</td>
      <td>${s.time||'—'}</td>
      <td>${Math.round(s.duration_sec||0)}s</td>
      <td>${(s.auth_attempts||[]).length}</td>
      <td style="font-family:monospace;font-size:11px">${(s.commands||[]).slice(0,4).join(' | ')||'—'}</td>
    </tr>`).join('');

  const css = `
    *{box-sizing:border-box;margin:0;padding:0;}
    body{font-family:'Segoe UI',system-ui,sans-serif;font-size:12px;color:#1e293b;padding:24px;}
    h1{font-size:20px;font-weight:700;color:#1e293b;margin-bottom:4px;}
    .meta{font-size:11px;color:#64748b;margin-bottom:20px;}
    .section{margin-bottom:22px;}
    .section-title{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;
      color:#64748b;margin-bottom:8px;padding-bottom:4px;border-bottom:1px solid #e2e8f0;}
    .stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:18px;}
    .stat{border:1px solid #e2e8f0;border-radius:6px;padding:10px 12px;}
    .stat-lbl{font-size:10px;color:#94a3b8;text-transform:uppercase;margin-bottom:4px;}
    .stat-val{font-size:20px;font-weight:700;}
    table{width:100%;border-collapse:collapse;font-size:11px;}
    th{text-align:left;padding:6px 8px;background:#f8fafc;border:1px solid #e2e8f0;
      font-size:10px;text-transform:uppercase;color:#64748b;}
    td{padding:5px 8px;border:1px solid #e2e8f0;vertical-align:top;}
    tr:nth-child(even) td{background:#f8fafc;}
    .info-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px;}
    .info-box{border:1px solid #e2e8f0;border-radius:6px;padding:10px 12px;}
    .info-box .lbl{font-size:10px;color:#94a3b8;text-transform:uppercase;margin-bottom:3px;}
    .info-box .val{font-size:13px;font-weight:600;}
    .pill-on{background:#dcfce7;color:#15803d;padding:2px 7px;border-radius:99px;font-size:10px;}
    .pill-off{background:#f1f5f9;color:#64748b;padding:2px 7px;border-radius:99px;font-size:10px;}
    .prog{height:6px;background:#e2e8f0;border-radius:3px;overflow:hidden;margin-top:5px;}
    .prog-fill{height:100%;background:#6366f1;border-radius:3px;}
    @page{margin:15mm;}
  `;

  const mlPct = ml ? Math.min(100,Math.round((ml.training_samples||0)/(ml.min_samples||100)*100)) : 0;

  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8">
  <title>CNSL Security Report</title><style>${css}</style></head><body>
  <h1>
    <svg width="22" height="22" viewBox="0 0 20 20" fill="none" style="vertical-align:middle;margin-right:8px">
      <path d="M10 2L3 5.5V10c0 3.87 2.93 7.5 7 8.45C17.07 17.5 20 13.87 20 10V5.5L10 2z"
        stroke="#6366f1" stroke-width="1.5" stroke-linejoin="round" fill="none"/>
      <path d="M7 10l2 2 4-4" stroke="#6366f1" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>CNSL Security Report
  </h1>
  <div class="meta">Generated: ${now} &nbsp;|&nbsp; Uptime: ${uptime} &nbsp;|&nbsp;
    Events processed: ${(sys?.events_processed||0).toLocaleString()}</div>

  <div class="stat-grid">
    <div class="stat"><div class="stat-lbl">Total Incidents</div>
      <div class="stat-val">${stats?.total||0}</div></div>
    <div class="stat"><div class="stat-lbl">HIGH Severity</div>
      <div class="stat-val" style="color:#ef4444">${stats?.high||0}</div></div>
    <div class="stat"><div class="stat-lbl">Active Blocks</div>
      <div class="stat-val" style="color:#f59e0b">${stats?.active_blocks||0}</div></div>
    <div class="stat"><div class="stat-lbl">Unique Attackers</div>
      <div class="stat-val" style="color:#3b82f6">${stats?.unique_ips||0}</div></div>
    <div class="stat"><div class="stat-lbl">MEDIUM Severity</div>
      <div class="stat-val" style="color:#f59e0b">${stats?.medium||0}</div></div>
    <div class="stat"><div class="stat-lbl">LOW Severity</div>
      <div class="stat-val" style="color:#3b82f6">${stats?.low||0}</div></div>
    <div class="stat"><div class="stat-lbl">SSH Fails</div>
      <div class="stat-val">${(sys?.ssh_fails_total||0).toLocaleString()}</div></div>
    <div class="stat"><div class="stat-lbl">All-time Blocks</div>
      <div class="stat-val">${(sys?.blocks_total||0).toLocaleString()}</div></div>
  </div>

  ${(incidents||[]).length ? `
  <div class="section">
    <div class="section-title">Recent Incidents (last ${Math.min((incidents||[]).length,50)})</div>
    <table><thead><tr><th>Time</th><th>IP</th><th>Location</th><th>Severity</th><th>Fails</th><th>Reason</th></tr></thead>
    <tbody>${incRows}</tbody></table>
  </div>` : ''}

  ${(attackers||[]).length ? `
  <div class="section">
    <div class="section-title">Top Attackers</div>
    <table><thead><tr><th>IP</th><th>Location</th><th>Incidents</th><th>Last seen</th></tr></thead>
    <tbody>${atkRows}</tbody></table>
  </div>` : ''}

  ${(blocks||[]).length ? `
  <div class="section">
    <div class="section-title">Active Blocks (${(blocks||[]).length})</div>
    <table><thead><tr><th>IP</th><th>Location</th><th>Blocked at</th><th>Expires</th></tr></thead>
    <tbody>${blkRows}</tbody></table>
  </div>` : ''}

  ${fim?.enabled && (fim?.alerts||[]).length ? `
  <div class="section">
    <div class="section-title">FIM Alerts (${(fim.alerts||[]).length})</div>
    <table><thead><tr><th>Time</th><th>Path</th><th>Change</th><th>Severity</th></tr></thead>
    <tbody>${fimRows}</tbody></table>
  </div>` : ''}

  ${hp?.enabled && (hp?.sessions||[]).length ? `
  <div class="section">
    <div class="section-title">Honeypot Sessions (${(hp.sessions||[]).length})</div>
    <table><thead><tr><th>IP</th><th>Time</th><th>Duration</th><th>Auth attempts</th><th>Commands</th></tr></thead>
    <tbody>${hpRows}</tbody></table>
  </div>` : ''}

  <div class="section">
    <div class="section-title">Module Status</div>
    <div class="info-grid">
      <div class="info-box">
        <div class="lbl">ML Detector</div>
        <div class="val">${ml?.enabled
          ?'<span class="pill-on">enabled</span>'
          :'<span class="pill-off">disabled</span>'}
          ${ml?.enabled ? ` &nbsp; trained: ${ml.trained?'<span class="pill-on">yes</span>':'<span class="pill-off">no</span>'}` : ''}
        </div>
        ${ml?.enabled ? `<div class="prog"><div class="prog-fill" style="width:${mlPct}%"></div></div>
          <div style="font-size:10px;color:#94a3b8;margin-top:3px">${ml.training_samples||0} / ${ml.min_samples||100} samples</div>` : ''}
      </div>
      <div class="info-box">
        <div class="lbl">FIM</div>
        <div class="val">${fim?.enabled
          ?'<span class="pill-on">enabled</span>'
          :'<span class="pill-off">disabled</span>'}
        </div>
        ${fim?.enabled ? `<div style="font-size:10px;color:#94a3b8;margin-top:4px">
          Watching: ${(fim.watch_paths||[]).join(', ')||'—'}</div>` : ''}
      </div>
      <div class="info-box">
        <div class="lbl">Honeypot</div>
        <div class="val">${hp?.enabled
          ?'<span class="pill-on">'+hp.mode+'</span>'
          :'<span class="pill-off">disabled</span>'}
        </div>
        ${hp?.enabled ? `<div style="font-size:10px;color:#94a3b8;margin-top:4px">
          Active redirects: ${hp.active_redirects||0}</div>` : ''}
      </div>
      <div class="info-box">
        <div class="lbl">System</div>
        <div class="val" style="font-size:12px">Uptime ${uptime}</div>
        <div style="font-size:10px;color:#94a3b8;margin-top:4px">
          Events: ${(sys?.events_processed||0).toLocaleString()} &nbsp;|&nbsp;
          SSH fails: ${(sys?.ssh_fails_total||0).toLocaleString()}
        </div>
      </div>
    </div>
  </div>

  </body></html>`;

  const w = window.open('', '_blank', 'width=900,height=700');
  w.document.write(html);
  w.document.close();
  w.focus();
  setTimeout(()=>{
    w.print();
  }, 600);

  btn.innerHTML = `<svg width="12" height="12" viewBox="0 0 12 12" fill="none" style="margin-right:4px;vertical-align:middle">
    <path d="M2 1h5.5L10 3.5V11H2V1z" stroke="currentColor" stroke-width="1.1" stroke-linejoin="round"/>
    <path d="M7 1v3h3" stroke="currentColor" stroke-width="1.1" stroke-linejoin="round"/>
    <path d="M4 6.5h4M4 8.5h2.5" stroke="currentColor" stroke-width="1.1" stroke-linecap="round"/>
    </svg>Export PDF`;
  btn.disabled = false;
}

// ── SSE ───────────────────────────────────────────────────────────────────
function connectSSE(){
  const es=new EventSource('/stream?token='+encodeURIComponent(token()));
  es.onmessage=e=>{
    try{
      const d=JSON.parse(e.data);
      const t=d.type;
      const p=d.payload||{};
      if(t==='incident'){
        const cls=p.severity==='HIGH'?'feed-alert':p.severity==='MEDIUM'?'feed-warn':'feed-info';
        addFeed('[INCIDENT] '+p.severity+' — '+(p.src_ip||p.ip||'?')+' — '+(p.reasons||[]).join('; '),cls);
        fetchStats();fetchIncidents();fetchBlocks();
      }else if(t==='action_block_scheduled'){
        addFeed('[BLOCKED] '+(p.ip||'?')+' reason='+p.reason,'feed-alert');
        fetchBlocks();fetchStats();
      }else if(t==='event_auth'){
        const k=p.kind;
        if(k==='SSH_FAIL')addFeed('[SSH FAIL] '+(p.src_ip||'?')+' user='+(p.user||'?'),'feed-warn');
        else if(k==='SSH_SUCCESS')addFeed('[SSH OK] '+(p.src_ip||'?')+' user='+(p.user||'?'),'feed-ok');
      }else if(t==='ml_anomaly'||t==='ml_alert'){
        addFeed('[ML ANOMALY] '+(p.src_ip||p.ip||'?')+' score='+(p.score??'?'),'feed-purple');
        fetchStats();
      }else if(t==='fim_alert'){
        addFeed('[FIM] '+p.severity+' — '+p.change+': '+p.path,'feed-purple');
        fetchFIM();
      }else if(t==='honeypot_session_complete'){
        addFeed('[HONEYPOT] session from '+(p.attacker_ip||'?')+' cmds='+(p.commands||[]).length,'feed-warn');
        fetchHoneypot();
      }
    }catch(_){}
  };
  es.onerror=()=>{
    addFeed('SSE disconnected — reconnecting...','feed-info');
    es.close();setTimeout(connectSSE,3000);
  };
}

// ── Refresh loop ──────────────────────────────────────────────────────────
async function refresh(){
  await Promise.all([
    fetchStats(),fetchSystem(),fetchTimeline(),
    fetchIncidents(),fetchBlocks(),fetchTopAttackers(),
    fetchHoneypot(),fetchFIM(),fetchML()
  ]);
}

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
    host:         str,
    port:         int,
    detector:     "Detector",
    blocker:      "Blocker",
    store:        "Store",
    metrics:      "Metrics",
    logger:       "JsonLogger",
    auth:         "AuthManager",
    dry_run:      bool = True,
    rbac:         Any = None,
    assets:       Any = None,
    honeypot:     Any = None,
    ml_detector:  Any = None,
    fim:          Any = None,
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
            "low":              db.get("low", 0),
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

    @router.get("/api/timeline")
    async def api_timeline(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        rows = await store.timeline_24h() if store.available else []
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


    @router.get("/api/debug")
    async def api_debug(req: web.Request) -> web.Response:
        """Diagnostic endpoint — shows what modules are wired."""
        return web.json_response({
            "ml_detector_wired":   ml_detector is not None,
            "ml_detector_enabled": getattr(ml_detector, "enabled", None),
            "fim_wired":           fim is not None,
            "fim_enabled":         getattr(fim, "enabled", None),
            "honeypot_wired":      honeypot is not None,
            "honeypot_enabled":    getattr(honeypot, "enabled", None),
            "assets_wired":        assets is not None,
        })

    @router.get("/api/ml-status")
    async def api_ml_status(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if ml_detector is None:
            return web.json_response({"enabled": False})
        return web.json_response(ml_detector.status())

    @router.get("/api/honeypot")
    async def api_honeypot_status(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if honeypot is None:
            return web.json_response({"enabled": False, "sessions": []})
        try:
            limit = int(req.rel_url.query.get("limit", 20))
        except (ValueError, TypeError):
            limit = 20
        return web.json_response({
            **honeypot.status(),
            "sessions": honeypot.recent_sessions(limit),
        })

    @router.get("/api/fim")
    async def api_fim(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        if fim is None or not getattr(fim, "enabled", False):
            return web.json_response({"enabled": False, "alerts": []})
        try:
            limit = int(req.rel_url.query.get("limit", 30))
        except (ValueError, TypeError):
            limit = 30
        alerts = fim.recent_alerts(limit)
        return web.json_response({
            "enabled":     fim.enabled,
            "watch_paths": getattr(fim, "_watch_paths", []),
            "alerts":      alerts,
        })

    @router.get("/api/system")
    async def api_system(req: web.Request) -> web.Response:
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err
        import time as _t
        uptime = int(_t.time() - metrics._start)
        return web.json_response({
            "uptime_sec":       uptime,
            "ssh_fails_total":  metrics.ssh_fails_total,
            "events_processed": metrics.events_processed,
            "blocks_total":     metrics.blocks_total,
        })

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
    print(f"\n  Dashboard → http://{host}:{port}  (auth: {auth_status})\n", flush=True)

    await asyncio.Event().wait()