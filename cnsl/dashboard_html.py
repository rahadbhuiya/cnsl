"""
cnsl/dashboard_html.py -- HTML/JS page templates for the CNSL dashboard.

Split from dashboard.py to keep the main module under 2000 lines.
Imported by dashboard.py at the top of start_dashboard().
"""

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

  <!-- Step 1: username + password -->
  <div id="step-login">
    <label>Username</label>
    <input type="text" id="user" value="admin" autocomplete="username">
    <label>Password</label>
    <input type="password" id="pass" autocomplete="current-password" onkeydown="if(event.key==='Enter')doLogin()">
    <button onclick="doLogin()">Sign in</button>
  </div>

  <!-- Step 2: TOTP code (shown only when 2FA is required) -->
  <div id="step-2fa" style="display:none">
    <p style="color:#aaa;font-size:13px;margin:0 0 12px">Enter the 6-digit code from your authenticator app, or a backup code.</p>
    <label>Authentication Code</label>
    <input type="text" id="otp" maxlength="9" placeholder="000000" autocomplete="one-time-code"
           style="letter-spacing:4px;font-size:20px;text-align:center"
           onkeydown="if(event.key==='Enter')do2FA()">
    <button onclick="do2FA()">Verify</button>
    <button onclick="resetLogin()" style="background:#333;margin-top:6px">Back</button>
  </div>

  <div class="err" id="err"></div>
</div>
<script>
let _partialToken = null;

async function doLogin(){
  const err=document.getElementById('err');
  err.style.display='none';
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({username:document.getElementById('user').value,
                         password:document.getElementById('pass').value})});
  const d=await r.json();
  if(d.needs_2fa){
    _partialToken=d.partial_token;
    document.getElementById('step-login').style.display='none';
    document.getElementById('step-2fa').style.display='block';
    document.getElementById('otp').focus();
  } else if(d.token){
    localStorage.setItem('cnsl_token',d.token);
    location.href='/?token='+d.token;
  } else {
    err.textContent=d.error||'Login failed';
    err.style.display='block';
  }
}

async function do2FA(){
  const err=document.getElementById('err');
  err.style.display='none';
  const code=document.getElementById('otp').value.trim();
  const r=await fetch('/api/2fa/verify',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({partial_token:_partialToken,code:code})});
  const d=await r.json();
  if(d.token){
    localStorage.setItem('cnsl_token',d.token);
    location.href='/?token='+d.token;
  } else {
    err.textContent=d.error||'Invalid code';
    err.style.display='block';
    document.getElementById('otp').value='';
    document.getElementById('otp').focus();
  }
}

function resetLogin(){
  _partialToken=null;
  document.getElementById('step-2fa').style.display='none';
  document.getElementById('step-login').style.display='block';
  document.getElementById('err').style.display='none';
  document.getElementById('otp').value='';
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
  --acc:#6366f1;--red:#ef4444;--amber:#f59e0b;--green:#22c55e;--blue:#3b82f6;--purple:#a855f7;
  --surface2:#22263a;}
*{box-sizing:border-box;margin:0;padding:0;}
body{
  background:var(--bg);
  color:var(--text);
  font-family:'Segoe UI',system-ui,sans-serif;
  font-size:14px;
}
/* Force dark theme on ALL form elements */
input,select,textarea,button{
  color:var(--text);
  background:var(--surf);
  border:1px solid var(--bord);
  font-family:inherit;
  font-size:inherit;
}
input:focus,select:focus,textarea:focus{
  outline:none;
  border-color:var(--acc);
}
select option{
  background:var(--surf);
  color:var(--text);
}
/* Scrollbar */
::-webkit-scrollbar{width:6px;height:6px;}
::-webkit-scrollbar-track{background:var(--bg);}
::-webkit-scrollbar-thumb{background:var(--bord);border-radius:3px;}
::-webkit-scrollbar-thumb:hover{background:var(--muted);}
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
    <span class="badge">v3.4.6</span>
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
  <div class="tab" onclick="showTab('cases')" id="tab-cases">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <rect x="2" y="1.5" width="10" height="11" rx="1" stroke="currentColor" stroke-width="1.2"/>
      <path d="M4.5 5h5M4.5 7.5h5M4.5 10h3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
    </svg>
    Cases
  </div>
  <div class="tab" onclick="showTab('ueba')" id="tab-ueba">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <circle cx="7" cy="4.5" r="2.5" stroke="currentColor" stroke-width="1.2"/>
      <path d="M2 12c0-2.76 2.24-5 5-5s5 2.24 5 5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
    </svg>
    UEBA
  </div>
  <div class="tab" onclick="showTab('rules')" id="tab-rules">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <path d="M2 3.5h10M2 7h6M2 10.5h8" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
      <circle cx="11" cy="7" r="1.5" stroke="currentColor" stroke-width="1.2"/>
    </svg>
    Rules
  </div>
  <div class="tab" onclick="showTab('ratelimit')" id="tab-ratelimit">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <circle cx="7" cy="7" r="5.5" stroke="currentColor" stroke-width="1.2"/>
      <path d="M7 4v3l2 1.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
    </svg>
    Rate Limit
  </div>
  <div class="tab" onclick="showTab('settings')" id="tab-settings">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <circle cx="7" cy="7" r="2" stroke="currentColor" stroke-width="1.2"/>
      <path d="M7 1.5v1M7 11.5v1M1.5 7h1M11.5 7h1M3.2 3.2l.7.7M10.1 10.1l.7.7M10.8 3.2l-.7.7M3.9 10.1l-.7.7" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
    </svg>
    Settings
  </div>
  <div class="tab" onclick="showTab('killchain')" id="tab-killchain">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <circle cx="2" cy="7" r="1.2" stroke="currentColor" stroke-width="1.2"/>
      <circle cx="7" cy="3" r="1.2" stroke="currentColor" stroke-width="1.2"/>
      <circle cx="12" cy="7" r="1.2" stroke="currentColor" stroke-width="1.2"/>
      <circle cx="7" cy="11" r="1.2" stroke="currentColor" stroke-width="1.2"/>
      <path d="M3.2 7h2.6M7 4.2v1.6M8.2 7h2.6M7 8.2v1.6" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
    </svg>
    Kill Chain
  </div>
  <div class="tab" onclick="showTab('graph')" id="tab-graph">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <circle cx="2"  cy="7"  r="1.4" stroke="currentColor" stroke-width="1.2"/>
      <circle cx="7"  cy="2"  r="1.4" stroke="currentColor" stroke-width="1.2"/>
      <circle cx="12" cy="7"  r="1.4" stroke="currentColor" stroke-width="1.2"/>
      <circle cx="5"  cy="11" r="1.4" stroke="currentColor" stroke-width="1.2"/>
      <circle cx="10" cy="11" r="1.4" stroke="currentColor" stroke-width="1.2"/>
      <path d="M3.2 6.4L6.2 3M8 3L11 6.4M3.2 7.6L4.5 10M10.5 10L11 7.6M6.2 11h1.6" stroke="currentColor" stroke-width="1.1" stroke-linecap="round"/>
    </svg>
    Graph
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

<!--  OVERVIEW  -->
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

<!--  INCIDENTS  -->
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

<!--  BLOCKS  -->
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

<!--  HONEYPOT  -->
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

<!--  FIM  -->
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

<!--  ML  -->
<div class="page" id="page-ml">

  <div class="stat-grid" style="grid-template-columns:repeat(4,1fr);margin-bottom:14px">
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
      <div class="stat-val c-blue" id="ml-tracked">--</div>
    </div>
    <div class="stat">
      <div class="stat-lbl">ML Alerts (recent)</div>
      <div class="stat-val c-amber" id="ml-alert-count">--</div>
    </div>
  </div>

  <!-- Training progress -->
  <div class="tbl-wrap" style="margin-bottom:14px">
    <div class="tbl-head">
      <span class="tbl-head-title">Training Progress</span>
      <span style="font-size:11px;color:var(--muted)" id="ml-sample-lbl"></span>
      <button onclick="mlTriggerRetrain()" id="ml-retrain-btn" style="font-size:11px;padding:3px 10px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer">Retrain Now</button>
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

  <!-- Parameter tuning -->
  <div class="tbl-wrap" style="margin-bottom:14px">
    <div class="tbl-head">
      <span class="tbl-head-title">Parameter Tuning</span>
      <span style="font-size:11px;color:var(--muted)">Changes apply immediately -- no restart needed</span>
    </div>
    <div style="padding:16px;display:grid;grid-template-columns:1fr 1fr;gap:16px">
      <div>
        <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:4px">
          Contamination (0.001 - 0.5)
          <span style="font-size:10px;color:var(--muted)"> -- expected fraction of anomalies</span>
        </label>
        <input id="ml-param-contamination" type="number" step="0.01" min="0.001" max="0.5"
          style="width:100%;background:var(--surf);border:1px solid var(--bord);color:var(--text);padding:6px 10px;border-radius:4px;font-size:13px">
      </div>
      <div>
        <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:4px">
          Anomaly Score Threshold
          <span style="font-size:10px;color:var(--muted)"> -- lower = stricter</span>
        </label>
        <input id="ml-param-threshold" type="number" step="0.01" min="-1" max="0"
          style="width:100%;background:var(--surf);border:1px solid var(--bord);color:var(--text);padding:6px 10px;border-radius:4px;font-size:13px">
      </div>
      <div>
        <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:4px">
          Min Samples to Train
        </label>
        <input id="ml-param-min-samples" type="number" step="10" min="10"
          style="width:100%;background:var(--surf);border:1px solid var(--bord);color:var(--text);padding:6px 10px;border-radius:4px;font-size:13px">
      </div>
      <div>
        <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:4px">
          Retrain Interval (seconds)
        </label>
        <input id="ml-param-retrain" type="number" step="60" min="60"
          style="width:100%;background:var(--surf);border:1px solid var(--bord);color:var(--text);padding:6px 10px;border-radius:4px;font-size:13px">
      </div>
      <div style="grid-column:1/-1;display:flex;align-items:center;gap:10px">
        <button onclick="mlSaveParams()" style="padding:6px 18px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:12px">Save Parameters</button>
        <span id="ml-param-msg" style="font-size:11px;color:var(--muted)"></span>
      </div>
    </div>
  </div>

  <!-- Feature importance -->
  <div class="tbl-wrap" style="margin-bottom:14px">
    <div class="tbl-head"><span class="tbl-head-title">Feature Importance (from recent alerts)</span></div>
    <div id="ml-feature-bars" style="padding:14px 16px"></div>
  </div>

  <!-- Recent ML alerts -->
  <div class="tbl-wrap" style="margin-bottom:14px">
    <div class="tbl-head"><span class="tbl-head-title">Recent ML Anomalies</span></div>
    <table>
      <thead><tr><th>Time</th><th>IP</th><th>Score</th><th>Top Reasons</th></tr></thead>
      <tbody id="ml-alerts-tbody"><tr><td colspan="4" style="color:var(--muted);text-align:center;padding:20px">No ML anomalies detected yet</td></tr></tbody>
    </table>
  </div>

  <div id="ml-disabled-note" style="display:none" class="banner banner-warn">
    <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
      <path d="M7 2v4M7 9v1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
      <path d="M1.5 12L7 2l5.5 10H1.5z" stroke="currentColor" stroke-width="1.2" stroke-linejoin="round"/>
    </svg>
    ML is disabled. Set "ml.enabled": true in config.json and install scikit-learn.
  </div>

</div>

<!--  LIVE FEED  -->
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

<!-- CASES -->
<div class="page" id="page-cases">
  <div class="stat-row" id="cases-stats" style="margin-bottom:14px"></div>
  <div class="tbl-wrap">
    <div class="tbl-head">
      <span class="tbl-head-title">Cases</span>
      <div style="display:flex;gap:8px;align-items:center">
        <select id="cases-filter-status" onchange="loadCases()" style="background:var(--surface2);border:1px solid var(--bord);color:var(--text);padding:3px 8px;border-radius:4px;font-size:12px">
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="closed">Closed</option>
          <option value="false_positive">False Positive</option>
        </select>
        <select id="cases-filter-sev" onchange="loadCases()" style="background:var(--surface2);border:1px solid var(--bord);color:var(--text);padding:3px 8px;border-radius:4px;font-size:12px">
          <option value="">All severities</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>
      </div>
    </div>
    <table>
      <thead><tr><th>#</th><th>Title</th><th>Status</th><th>Severity</th><th>IP</th><th>Assigned</th><th>Updated</th></tr></thead>
      <tbody id="cases-tbody"><tr><td colspan="7" style="color:var(--muted);text-align:center;padding:20px">Loading...</td></tr></tbody>
    </table>
  </div>
</div>

<!-- UEBA -->
<div class="page" id="page-ueba">
  <div class="stat-row" id="ueba-stats" style="margin-bottom:14px"></div>
  <div class="tbl-wrap" style="margin-bottom:14px">
    <div class="tbl-head"><span class="tbl-head-title">Recent Anomalies</span></div>
    <table>
      <thead><tr><th>Time</th><th>User</th><th>Source IP</th><th>Types</th><th>Reason</th></tr></thead>
      <tbody id="ueba-anomalies-tbody"><tr><td colspan="5" style="color:var(--muted);text-align:center;padding:20px">Loading...</td></tr></tbody>
    </table>
  </div>
  <div class="tbl-wrap">
    <div class="tbl-head"><span class="tbl-head-title">User Profiles</span><span style="font-size:11px;color:var(--muted)" id="ueba-profile-count"></span></div>
    <table>
      <thead><tr><th>Username</th><th>Logins</th><th>Anomalies</th><th>Known IPs</th><th>Last Seen</th></tr></thead>
      <tbody id="ueba-profiles-tbody"><tr><td colspan="5" style="color:var(--muted);text-align:center;padding:20px">Loading...</td></tr></tbody>
    </table>
  </div>
</div>

<!-- RULES -->
<div class="page" id="page-rules">
  <div class="tbl-wrap" style="margin-bottom:14px">
    <div class="tbl-head"><span class="tbl-head-title">Alert Rules</span><span style="font-size:11px;color:var(--muted)">Click a rule to edit threshold and severity</span></div>
    <table>
      <thead><tr><th>Rule ID</th><th>Name</th><th>Status</th><th>Severity</th><th>Threshold</th><th>Window</th><th>Actions</th></tr></thead>
      <tbody id="rules-tbody"><tr><td colspan="7" style="color:var(--muted);text-align:center;padding:20px">Loading...</td></tr></tbody>
    </table>
  </div>
  <!-- Edit panel -->
  <div id="rule-edit-panel" style="display:none;margin-top:14px;padding:16px;background:var(--surface2);border:1px solid var(--bord);border-radius:6px">
    <div style="font-size:13px;font-weight:600;margin-bottom:12px;color:var(--text)" id="rule-edit-title">Edit Rule</div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:14px">
      <div>
        <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:4px">Threshold</label>
        <input id="rule-edit-threshold" type="number" min="1" style="width:100%;background:var(--surf);border:1px solid var(--bord);color:var(--text);padding:6px 10px;border-radius:4px;font-size:13px">
      </div>
      <div>
        <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:4px">Severity</label>
        <select id="rule-edit-severity" style="width:100%;background:var(--surf);border:1px solid var(--bord);color:var(--text);padding:6px 10px;border-radius:4px;font-size:13px">
          <option value="LOW">LOW</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="HIGH">HIGH</option>
        </select>
      </div>
      <div>
        <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:4px">Window (sec)</label>
        <input id="rule-edit-window" type="number" min="0" style="width:100%;background:var(--surf);border:1px solid var(--bord);color:var(--text);padding:6px 10px;border-radius:4px;font-size:13px">
      </div>
    </div>
    <div style="display:flex;gap:8px">
      <button class="btn btn-green" onclick="saveRule()">Save</button>
      <button class="btn" onclick="resetRule()" style="background:var(--surf);border:1px solid var(--bord)">Reset to Default</button>
      <button class="btn" onclick="$('rule-edit-panel').style.display='none'" style="background:var(--surf);border:1px solid var(--bord)">Cancel</button>
    </div>
  </div>
  <!-- Suggested Rules panel -->
  <div class="tbl-wrap" style="margin-top:14px" id="suggested-rules-wrap">
    <div class="tbl-head">
      <span class="tbl-head-title">Suggested Rules</span>
      <span style="font-size:11px;color:var(--muted)">Patterns discovered automatically from recurring attack sequences</span>
      <button onclick="loadSuggestedRules()" style="font-size:11px;padding:3px 10px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer">Refresh</button>
    </div>
    <div id="suggested-rules-stats" style="padding:8px 16px;font-size:11px;color:var(--muted);border-bottom:1px solid var(--border)"></div>
    <table>
      <thead><tr><th>Pattern</th><th>Confidence</th><th>Occurrences</th><th>Severity</th><th>Threshold</th><th>Window</th><th>Example IPs</th><th>Last Seen</th><th>Actions</th></tr></thead>
      <tbody id="suggested-rules-tbody"><tr><td colspan="9" style="color:var(--muted);text-align:center;padding:20px">Loading...</td></tr></tbody>
    </table>
  </div>
</div>

<!-- RATE LIMIT -->
<div class="page" id="page-ratelimit">
  <div class="stat-row" id="rl-stats" style="margin-bottom:14px"></div>
  <div class="tbl-wrap">
    <div class="tbl-head"><span class="tbl-head-title">Top Requesters</span><button class="btn btn-green" onclick="loadRateLimit()" style="font-size:11px;padding:3px 10px">Refresh</button></div>
    <table>
      <thead><tr><th>IP</th><th>Requests (window)</th><th>Actions</th></tr></thead>
      <tbody id="rl-top-tbody"><tr><td colspan="3" style="color:var(--muted);text-align:center;padding:20px">Loading...</td></tr></tbody>
    </table>
  </div>
  <div class="tbl-wrap" style="margin-top:14px">
    <div class="tbl-head"><span class="tbl-head-title">Active Rate-Limit Blocks</span></div>
    <table>
      <thead><tr><th>IP</th><th>Expires in</th><th>Actions</th></tr></thead>
      <tbody id="rl-blocks-tbody"><tr><td colspan="3" style="color:var(--muted);text-align:center;padding:20px">Loading...</td></tr></tbody>
    </table>
  </div>
</div>

<!-- SETTINGS -->
<div class="page" id="page-graph">
  <div class="tbl-wrap" style="margin-bottom:14px">
    <div class="tbl-head">
      <span class="tbl-head-title">Attack Behavior Graph</span>
      <span style="font-size:11px;color:var(--muted)">Nodes = attacker IPs, sized by kill chain progress, colored by trust</span>
      <div style="display:flex;gap:8px;align-items:center">
        <label style="font-size:11px;color:var(--muted)">
          Min incidents:
          <select id="graph-min-incidents" onchange="renderGraph()" style="font-size:11px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:2px 4px;margin-left:4px">
            <option value="1">1+</option>
            <option value="2">2+</option>
            <option value="5">5+</option>
          </select>
        </label>
        <label style="font-size:11px;color:var(--muted)">
          <input type="checkbox" id="graph-show-labels" checked onchange="renderGraph()"> Labels
        </label>
        <button onclick="loadGraph()" style="font-size:11px;padding:3px 10px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer">Refresh</button>
      </div>
    </div>
    <!-- Legend -->
    <div style="padding:8px 16px;display:flex;gap:16px;font-size:11px;color:var(--muted);border-bottom:1px solid var(--border);flex-wrap:wrap">
      <span>Node color:</span>
      <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#22c55e;margin-right:4px"></span>Trusted</span>
      <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#f59e0b;margin-right:4px"></span>Moderate</span>
      <span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#ef4444;margin-right:4px"></span>Suspicious/Untrusted</span>
      <span style="margin-left:8px">Node size: kill chain progress</span>
      <span>Edge: shared attack rule</span>
    </div>
    <!-- Canvas -->
    <div style="position:relative;height:480px;background:var(--bg);border-radius:0 0 6px 6px;overflow:hidden">
      <canvas id="graph-canvas" style="width:100%;height:100%"></canvas>
      <div id="graph-empty" style="display:none;position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:13px">
        No attack data yet -- incidents appear here as they are detected
      </div>
      <!-- Tooltip -->
      <div id="graph-tooltip" style="display:none;position:absolute;background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:10px 14px;font-size:11px;pointer-events:none;max-width:220px;z-index:10"></div>
    </div>
  </div>
  <!-- Node detail panel -->
  <div id="graph-detail" style="display:none">
    <div class="tbl-wrap">
      <div class="tbl-head">
        <span class="tbl-head-title" id="graph-detail-title">Node Detail</span>
        <button onclick="document.getElementById('graph-detail').style.display='none'" style="font-size:11px;padding:3px 10px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;cursor:pointer">Close</button>
      </div>
      <div id="graph-detail-body" style="padding:16px;display:grid;grid-template-columns:1fr 1fr;gap:12px;font-size:12px"></div>
    </div>
  </div>
</div>

<div class="page" id="page-killchain">
  <div class="tbl-wrap" style="margin-bottom:14px">
    <div class="tbl-head">
      <span class="tbl-head-title">Kill Chain Overview</span>
      <span style="font-size:11px;color:var(--muted)">Attack progression per source IP</span>
      <div style="display:flex;gap:8px;align-items:center">
        <label style="font-size:11px;color:var(--muted)">
          <input type="checkbox" id="kc-complete-only" onchange="loadKillChain()"> Complete only
        </label>
        <select id="kc-min-score" onchange="loadKillChain()" style="font-size:11px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:2px 6px">
          <option value="0">All scores</option>
          <option value="0.3">Score >= 0.3</option>
          <option value="0.5">Score >= 0.5</option>
          <option value="0.7">Score >= 0.7</option>
        </select>
        <button onclick="loadKillChain()" style="font-size:11px;padding:3px 10px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer">Refresh</button>
      </div>
    </div>
    <div id="kc-stats-bar" style="padding:10px 16px;display:flex;gap:24px;border-bottom:1px solid var(--border);font-size:12px"></div>
    <table id="kc-table">
      <thead><tr>
        <th>Source IP</th>
        <th>Max Stage</th>
        <th>Score</th>
        <th>Complete</th>
        <th>Events</th>
        <th>Last Seen</th>
        <th>Location</th>
        <th>Detail</th>
      </tr></thead>
      <tbody id="kc-tbody"></tbody>
    </table>
  </div>
  <div id="kc-detail-wrap" style="display:none">
    <div class="tbl-wrap">
      <div class="tbl-head">
        <span class="tbl-head-title" id="kc-detail-title">Kill Chain Detail</span>
        <button onclick="document.getElementById('kc-detail-wrap').style.display='none'" style="font-size:11px;padding:3px 10px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:4px;cursor:pointer">Close</button>
      </div>
      <div id="kc-detail-stages" style="padding:16px;display:flex;gap:0;flex-wrap:nowrap;overflow-x:auto"></div>
      <div id="kc-detail-meta" style="padding:0 16px 16px;font-size:12px;color:var(--muted)"></div>
    </div>
  </div>
</div>

<div class="page" id="page-settings">
  <div class="tbl-wrap" style="margin-bottom:14px">
    <div class="tbl-head">
      <span class="tbl-head-title">Zero-Trust Trust Scores</span>
      <span style="font-size:11px;color:var(--muted)">Per-entity trust scoring -- lower trust = lower alert threshold</span>
      <button onclick="loadZeroTrust()" style="font-size:11px;padding:3px 10px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer">Refresh</button>
    </div>
    <div id="zt-stats-bar" style="padding:8px 16px;display:flex;gap:20px;font-size:11px;border-bottom:1px solid var(--border)"></div>
    <table>
      <thead><tr><th>Entity</th><th>Type</th><th>Trust Label</th><th>Score</th><th>Signals</th><th>Last Signal</th><th>Actions</th></tr></thead>
      <tbody id="zt-tbody"><tr><td colspan="7" style="color:var(--muted);text-align:center;padding:20px">No scored entities yet</td></tr></tbody>
    </table>
  </div>
  <div class="tbl-wrap" style="margin-bottom:14px">
    <div class="tbl-head">
      <span class="tbl-head-title">Cloud Identity Connectors</span>
      <span style="font-size:11px;color:var(--muted)">AWS CloudTrail + Azure AD sign-in polling</span>
      <button onclick="loadCloudIdentityStatus()" style="font-size:11px;padding:3px 10px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer">Refresh</button>
    </div>
    <div id="cloud-identity-wrap" style="padding:16px">
      <div id="cloud-identity-cards" style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px"></div>
    </div>
  </div>
  <div class="tbl-wrap" style="margin-bottom:14px">
    <div class="tbl-head">
      <span class="tbl-head-title">SIEM / SOAR Connectors</span>
      <span style="font-size:11px;color:var(--muted)">Real-time push to external platforms</span>
      <button onclick="loadSIEMStatus()" style="font-size:11px;padding:3px 10px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer">Refresh</button>
    </div>
    <div id="siem-status-wrap" style="padding:16px">
      <div id="siem-status-cards" style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:14px"></div>
      <div id="siem-queue-line" style="font-size:11px;color:var(--muted)"></div>
    </div>
  </div>
  <div class="tbl-wrap" style="margin-bottom:14px">
    <div class="tbl-head">
      <span class="tbl-head-title">Federation -- Multi-Node Correlation</span>
      <span style="font-size:11px;color:var(--muted)">Cross-node detection sharing via Redis</span>
      <button onclick="loadFederationStatus()" style="font-size:11px;padding:3px 10px;background:var(--accent);color:#fff;border:none;border-radius:4px;cursor:pointer">Refresh</button>
    </div>
    <div id="federation-status-wrap" style="padding:16px">
      <div id="federation-summary" style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:14px"></div>
      <div style="font-size:12px;font-weight:600;margin-bottom:8px;color:var(--text)">Known Peer Nodes</div>
      <table>
        <thead><tr><th>Node ID</th><th>Last Seen</th></tr></thead>
        <tbody id="federation-nodes-tbody"><tr><td colspan="2" style="color:var(--muted);text-align:center;padding:12px">No peer nodes yet</td></tr></tbody>
      </table>
      <div style="font-size:12px;font-weight:600;margin:14px 0 8px;color:var(--text)">Cross-Node Attacks (IPs seen by 2+ nodes)</div>
      <table>
        <thead><tr><th>IP</th><th>Nodes</th><th>Kinds Observed</th><th>Last Seen</th></tr></thead>
        <tbody id="federation-crossnode-tbody"><tr><td colspan="4" style="color:var(--muted);text-align:center;padding:12px">No cross-node activity yet</td></tr></tbody>
      </table>
    </div>
  </div>
  <div class="tbl-wrap" style="margin-bottom:14px">
    <div class="tbl-head"><span class="tbl-head-title">Module Status</span><span style="font-size:11px;color:var(--muted)">Live status of optional modules</span></div>
    <div style="padding:16px;display:grid;grid-template-columns:1fr 1fr;gap:12px" id="settings-modules"></div>
  </div>
  <div class="tbl-wrap" style="margin-bottom:14px">
    <div class="tbl-head"><span class="tbl-head-title">Zeek Log Sources</span><span style="font-size:11px;color:var(--muted)" id="zeek-hint">Disable to stop "File not found" messages</span></div>
    <div style="padding:16px">
      <p style="font-size:12px;color:var(--muted);margin:0 0 12px">Zeek logs are enabled in config. If Zeek is not installed, disable them to prevent log spam.</p>
      <div style="display:flex;gap:8px;flex-wrap:wrap" id="zeek-toggle-btns"></div>
      <p style="font-size:11px;color:var(--muted);margin:12px 0 0">Note: Changes take effect on next restart. Edit <code>/etc/cnsl/config.json</code> to make permanent.</p>
    </div>
  </div>
  <div class="tbl-wrap" style="margin-bottom:14px">
    <div class="tbl-head"><span class="tbl-head-title">HuddleCluster — Load Balancing</span></div>
    <div style="padding:16px" id="settings-huddle">
      <p style="font-size:12px;color:var(--muted);margin:0 0 10px">
        Self-organizing load balancer across multiple CNSL nodes.<br>
        Temperature score = CNSL event load + queue fill + incident rate.
      </p>
      <div id="huddle-inner-list" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px"></div>
      <div style="font-size:11px;color:var(--muted)" id="huddle-status-line">Loading...</div>
    </div>
  </div>
    <div style="padding:16px">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;font-size:12px" id="settings-config-ref"></div>
    </div>
  </div>
</div>

<script>
const $=id=>document.getElementById(id);
function escHtml(s){
  return String(s==null?'':s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;')
    .replace(/'/g,'&#39;');
}
const fmtDate=ts=>ts?new Date(ts*1000).toLocaleString():'—';
const fmtTime=ts=>ts?new Date(ts*1000).toLocaleTimeString():'—';
const token=()=>localStorage.getItem('cnsl_token')||'';
const authHdr=()=>({'Content-Type':'application/json','Authorization':'Bearer '+token()});

//  Tab navigation 
function showTab(name){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  $('tab-'+name).classList.add('active');
  $('page-'+name).classList.add('active');
  if(name==='cases')     loadCases();
  if(name==='ueba')      loadUEBA();
  if(name==='rules')     { loadRules(); loadSuggestedRules(); }
  if(name==='ratelimit') loadRateLimit();
  if(name==='settings')  { loadSettings(); loadSIEMStatus(); loadFederationStatus(); loadCloudIdentityStatus(); loadZeroTrust(); }
  if(name==='killchain') loadKillChain();
  if(name==='graph')     loadGraph();
}

//  Cases 
let _editingRuleId = null;

async function loadCases(){
  const status = $('cases-filter-status').value;
  const sev    = $('cases-filter-sev').value;
  let url = `/api/cases?limit=100`;
  if(status) url += `&status=${status}`;
  if(sev)    url += `&severity=${sev}`;

  // stats
  const stats = await apiFetch('/api/cases/stats');
  if(stats){
    $('cases-stats').innerHTML = [
      {l:'Total',v:stats.total||0,c:''},
      {l:'Open',v:stats.open||0,c:'c-red'},
      {l:'Investigating',v:stats.investigating||0,c:'c-yellow'},
      {l:'Closed',v:stats.closed||0,c:'c-green'},
      {l:'False Positive',v:stats.false_positive||0,c:'c-blue'},
    ].map(s=>`<div class="stat"><div class="stat-lbl">${s.l}</div><div class="stat-val ${s.c}">${s.v}</div></div>`).join('');
  }

  const d = await apiFetch(url);
  if(!d) return;
  const STATUS_COLOR = {open:'c-red',investigating:'c-yellow',closed:'c-green',false_positive:'c-blue'};
  $('cases-tbody').innerHTML = d.cases.length ? d.cases.map(c=>`
    <tr>
      <td style="color:var(--muted);font-size:11px">#${c.id}</td>
      <td style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(c.title)}">${escHtml(c.title)}</td>
      <td><span class="${STATUS_COLOR[c.status]||''}">${escHtml(c.status)}</span></td>
      <td><span class="${c.severity==='HIGH'?'c-red':c.severity==='MEDIUM'?'c-yellow':'c-blue'}">${escHtml(c.severity)}</span></td>
      <td style="font-family:monospace;font-size:12px">${escHtml(c.src_ip||'—')}</td>
      <td>${c.assigned_to?escHtml(c.assigned_to):'<span style="color:var(--muted)">unassigned</span>'}</td>
      <td style="color:var(--muted);font-size:11px">${fmtDate(c.updated_at)}</td>
    </tr>`).join('') :
    '<tr><td colspan="7" style="color:var(--muted);text-align:center;padding:20px">No cases found</td></tr>';
}

//  UEBA 
async function loadUEBA(){
  const stats = await apiFetch('/api/ueba');
  if(stats && stats.enabled!==false){
    $('ueba-stats').innerHTML = [
      {l:'Total Profiles',v:stats.total_profiles||0,c:''},
      {l:'Anomalous Users',v:stats.anomalous_users||0,c:'c-red'},
      {l:'Total Logins',v:stats.total_logins_seen||0,c:'c-blue'},
    ].map(s=>`<div class="stat"><div class="stat-lbl">${s.l}</div><div class="stat-val ${s.c}">${s.v}</div></div>`).join('');
  } else {
    $('ueba-stats').innerHTML = '<div class="stat"><div class="stat-lbl">Status</div><div class="stat-val" style="color:var(--muted)">Disabled</div></div>';
  }

  const an = await apiFetch('/api/ueba/anomalies?limit=50');
  $('ueba-anomalies-tbody').innerHTML = an && an.anomalies && an.anomalies.length ?
    an.anomalies.map(a=>`<tr>
      <td style="color:var(--muted);font-size:11px">${fmtTime(a.ts)}</td>
      <td style="font-weight:500">${escHtml(a.username)}</td>
      <td style="font-family:monospace;font-size:12px">${escHtml(a.src_ip||'—')}</td>
      <td style="font-size:11px">${escHtml((a.anomaly_types||a.anomaly_type||'').toString()).replace(',','<br>')}</td>
      <td style="font-size:11px;color:var(--muted);max-width:280px;overflow:hidden;text-overflow:ellipsis" title="${escHtml(a.reason)}">${escHtml(a.reason||'—')}</td>
    </tr>`).join('') :
    '<tr><td colspan="5" style="color:var(--muted);text-align:center;padding:20px">No anomalies detected</td></tr>';

  const pr = await apiFetch('/api/ueba/profiles?sort_by=anomaly_count&limit=20');
  if(pr && pr.profiles){
    $('ueba-profile-count').textContent = `${pr.total} total`;
    $('ueba-profiles-tbody').innerHTML = pr.profiles.length ?
      pr.profiles.map(p=>`<tr>
        <td style="font-weight:500">${escHtml(p.username)}</td>
        <td>${p.total_logins}</td>
        <td class="${p.anomaly_count>0?'c-red':''}">${p.anomaly_count}</td>
        <td>${p.known_ip_count}</td>
        <td style="color:var(--muted);font-size:11px">${fmtDate(p.last_seen)}</td>
      </tr>`).join('') :
      '<tr><td colspan="5" style="color:var(--muted);text-align:center;padding:20px">No profiles yet — observes successful SSH logins</td></tr>';
  }
}

//  Rules 
async function loadRules(){
  const d = await apiFetch('/api/rules');
  if(!d) return;
  $('rules-tbody').innerHTML = d.rules.map(r=>`
    <tr>
      <td style="font-family:monospace;font-size:11px;color:var(--muted)">${r.id}</td>
      <td style="font-size:12px">${r.name}</td>
      <td><span class="${r.enabled?'c-green':'c-red'}">${r.enabled?'Enabled':'Disabled'}</span>${r.overridden?'<span style="font-size:10px;color:var(--muted);margin-left:6px">✎</span>':''}</td>
      <td><span class="${r.effective_severity==='HIGH'?'c-red':r.effective_severity==='MEDIUM'?'c-yellow':'c-blue'}">${r.effective_severity}</span></td>
      <td>${r.effective_threshold}</td>
      <td>${r.effective_window}s</td>
      <td style="display:flex;gap:6px">
        <button class="btn ${r.enabled?'':'btn-green'}" onclick="${r.enabled?`disableRule('${r.id}')`:`enableRule('${r.id}')`}" style="font-size:11px;padding:2px 8px">
          ${r.enabled?'Disable':'Enable'}
        </button>
        <button class="btn" onclick="openRuleEdit('${r.id}',${r.effective_threshold},'${r.effective_severity}',${r.effective_window})" style="font-size:11px;padding:2px 8px">Edit</button>
      </td>
    </tr>`).join('');
}

async function enableRule(id){
  await apiFetch(`/api/rules/${id}/enable`,{method:'POST'});
  loadRules();
}
async function disableRule(id){
  await apiFetch(`/api/rules/${id}/disable`,{method:'POST'});
  loadRules();
}
function openRuleEdit(id,threshold,severity,window_sec){
  _editingRuleId = id;
  $('rule-edit-title').textContent = `Edit: ${id}`;
  $('rule-edit-threshold').value = threshold;
  $('rule-edit-severity').value  = severity;
  $('rule-edit-window').value    = window_sec;
  $('rule-edit-panel').style.display = 'block';
}
async function saveRule(){
  if(!_editingRuleId) return;
  await apiFetch(`/api/rules/${_editingRuleId}`,{
    method:'PATCH',
    body:JSON.stringify({
      threshold: parseInt($('rule-edit-threshold').value),
      severity:  $('rule-edit-severity').value,
      window_sec: parseInt($('rule-edit-window').value),
    })
  });
  $('rule-edit-panel').style.display = 'none';
  loadRules();
}
async function resetRule(){
  if(!_editingRuleId) return;
  await apiFetch(`/api/rules/${_editingRuleId}/reset`,{method:'POST'});
  $('rule-edit-panel').style.display = 'none';
  loadRules();
}
async function loadSuggestedRules(){
  const [d, stats] = await Promise.all([
    apiFetch('/api/pattern-suggestions'),
    apiFetch('/api/pattern-suggestions/stats'),
  ]);
  if(stats){
    $('suggested-rules-stats').innerHTML =
      `Tracking <b>${stats.patterns_tracked}</b> patterns &nbsp;|&nbsp; ` +
      `<b>${stats.active_suggestions}</b> active suggestions &nbsp;|&nbsp; ` +
      `<b>${stats.promoted}</b> promoted &nbsp;|&nbsp; ` +
      `<b>${stats.dismissed}</b> dismissed &nbsp;|&nbsp; ` +
      `Min occurrences: <b>${stats.min_occurrences}</b>`;
  }
  if(!d || !d.length){
    $('suggested-rules-tbody').innerHTML =
      '<tr><td colspan="9" style="color:var(--muted);text-align:center;padding:20px">No suggestions yet -- patterns appear after recurring attack sequences are observed</td></tr>';
    return;
  }
  const SEV_COLOR = {HIGH:'#e74c3c',MEDIUM:'#fd7e14',LOW:'#6c757d'};
  $('suggested-rules-tbody').innerHTML = d.map(s => {
    const confPct  = Math.round(s.confidence * 100);
    const sevColor = SEV_COLOR[s.severity] || '#6c757d';
    const kinds    = (s.event_kinds || []).join(', ');
    const ips      = (s.example_ips || []).slice(0,3).join(', ');
    return `<tr>
      <td style="font-size:11px;font-family:monospace;max-width:180px;word-break:break-all" title="${escHtml(s.pattern_key)}">${escHtml(kinds)}</td>
      <td>
        <div style="display:flex;align-items:center;gap:6px">
          <div style="width:50px;height:6px;background:var(--surface-2,#2a2a2a);border-radius:3px">
            <div style="width:${confPct}%;height:6px;background:#3498db;border-radius:3px"></div>
          </div>
          <span style="font-size:11px">${confPct}%</span>
        </div>
      </td>
      <td>${s.occurrences}</td>
      <td><span style="color:${sevColor};font-weight:600;font-size:11px">${s.severity}</span></td>
      <td>${s.threshold}</td>
      <td>${s.window_sec}s</td>
      <td style="font-size:11px;color:var(--muted)">${escHtml(ips)}</td>
      <td style="font-size:11px">${escHtml(s.last_seen||'')}</td>
      <td style="white-space:nowrap">
        <button onclick="promoteSuggestion('${escHtml(s.id)}','${escHtml(s.suggested_rule_id)}',${s.threshold},'${s.severity}',${s.window_sec})"
          style="font-size:10px;padding:2px 7px;background:#27ae60;color:#fff;border:none;border-radius:3px;cursor:pointer;margin-right:4px">Promote</button>
        <button onclick="dismissSuggestion('${escHtml(s.id)}')"
          style="font-size:10px;padding:2px 7px;background:var(--surface);color:var(--muted);border:1px solid var(--border);border-radius:3px;cursor:pointer">Dismiss</button>
      </td>
    </tr>`;
  }).join('');
}
async function promoteSuggestion(id, ruleId, threshold, severity, window_sec){
  const err1 = await apiFetch(`/api/pattern-suggestions/${id}/promote`,{method:'POST'});
  if(!err1) return;
  // Also apply the suggested override to the rule engine if rule exists
  await apiFetch(`/api/rules/${encodeURIComponent(ruleId)}`,{
    method:'PATCH',
    body:JSON.stringify({threshold, severity, window_sec, enabled:true}),
  });
  loadRules();
  loadSuggestedRules();
}
async function dismissSuggestion(id){
  await apiFetch(`/api/pattern-suggestions/${id}/dismiss`,{method:'POST'});
  loadSuggestedRules();
}

//  Rate Limit 
async function loadRateLimit(){
  const d = await apiFetch('/api/rate-limit');
  if(!d){ $('rl-stats').innerHTML='<div class="stat"><div class="stat-lbl">Status</div><div class="stat-val" style="color:var(--muted)">Disabled</div></div>'; return; }
  $('rl-stats').innerHTML = [
    {l:'Enabled',v:d.enabled?'Yes':'No',c:d.enabled?'c-green':'c-red'},
    {l:'Limit',v:`${d.requests_per_min||0}/min`,c:''},
    {l:'DDoS Threshold',v:d.ddos_threshold||0,c:''},
    {l:'Total Requests',v:d.total_requests||0,c:''},
    {l:'Rate Limited',v:d.rate_limited||0,c:d.rate_limited>0?'c-yellow':''},
    {l:'DDoS Detections',v:d.ddos_detections||0,c:d.ddos_detections>0?'c-red':''},
    {l:'Active Blocks',v:d.active_blocks||0,c:d.active_blocks>0?'c-red':''},
  ].map(s=>`<div class="stat"><div class="stat-lbl">${s.l}</div><div class="stat-val ${s.c}">${s.v}</div></div>`).join('');

  const top = await apiFetch('/api/rate-limit/top?n=10');
  $('rl-top-tbody').innerHTML = top && top.top && top.top.length ?
    top.top.map(t=>`<tr>
      <td style="font-family:monospace">${t.ip}</td>
      <td>${t.requests}</td>
      <td><button class="btn" onclick="rlReset('${t.ip}')" style="font-size:11px;padding:2px 8px">Reset</button></td>
    </tr>`).join('') :
    '<tr><td colspan="3" style="color:var(--muted);text-align:center;padding:16px">No data</td></tr>';

  const blocks = d.active_block_ips||{};
  const blockKeys = Object.keys(blocks);
  $('rl-blocks-tbody').innerHTML = blockKeys.length ?
    blockKeys.map(ip=>`<tr>
      <td style="font-family:monospace">${ip}</td>
      <td>${Math.round(blocks[ip])}s</td>
      <td><button class="btn btn-green" onclick="rlReset('${ip}')" style="font-size:11px;padding:2px 8px">Reset</button></td>
    </tr>`).join('') :
    '<tr><td colspan="3" style="color:var(--muted);text-align:center;padding:16px">No active rate-limit blocks</td></tr>';
}
async function rlReset(ip){
  await apiFetch(`/api/rate-limit/reset/${ip}`,{method:'POST'});
  loadRateLimit();
}

//  Settings 
// ---- Graph Visualization (force-directed, canvas-based) ----

let _graphData = null;
let _graphAnim  = null;
let _graphNodes = [];
let _graphEdges = [];

async function loadGraph(){
  const [attackers, incidents, kcData, ztData] = await Promise.all([
    apiFetch('/api/attackers'),
    apiFetch('/api/incidents?limit=200'),
    apiFetch('/api/kill-chain?limit=200'),
    apiFetch('/api/zero-trust/scores?limit=500'),
  ]);
  _graphData = {attackers, incidents, kc: kcData, zt: ztData};
  renderGraph();
}

function renderGraph(){
  if(!_graphData) return;
  const {attackers, incidents, kc, zt} = _graphData;
  const minInc  = parseInt($('graph-min-incidents').value, 10);
  const showLbl = $('graph-show-labels').checked;
  const canvas  = $('graph-canvas');
  const empty   = $('graph-empty');
  const tooltip = $('graph-tooltip');

  // Build lookup maps
  const kcMap = {};
  (kc || []).forEach(c => { kcMap[c.ip] = c; });
  const ztMap = {};
  (zt || []).forEach(r => {
    if(r.entity_type === 'ip') ztMap[r.entity_id] = r;
  });

  // Filter attackers by min incidents
  const filtered = (attackers || []).filter(a => (a.incident_count || 1) >= minInc);
  if(!filtered.length){
    canvas.style.display = 'none';
    empty.style.display  = 'flex';
    return;
  }
  canvas.style.display = '';
  empty.style.display  = 'none';

  // Set canvas size
  const rect = canvas.parentElement.getBoundingClientRect();
  const W = rect.width  || 800;
  const H = rect.height || 480;
  canvas.width  = W;
  canvas.height = H;
  const ctx = canvas.getContext('2d');

  // Build nodes
  const ipSet = new Set(filtered.map(a => a.src_ip));
  _graphNodes = filtered.map(a => {
    const ip   = a.src_ip;
    const kci  = kcMap[ip];
    const zti  = ztMap[ip];
    const score    = zti  ? zti.score           : 0.8;
    const kcScore  = kci  ? (kci.score || 0)    : 0;
    const maxStage = kci  ? (kci.max_stage || 0) : 0;
    const radius   = 8 + Math.round(kcScore * 18);
    const color    = score >= 0.8 ? '#22c55e' :
                     score >= 0.5 ? '#f59e0b' : '#ef4444';
    return {
      ip, score, kcScore, maxStage, radius, color,
      incidentCount: a.incident_count || 1,
      country: a.country || '',
      maxSev:  a.max_severity || '',
      kcLabel: kci ? kci.max_stage_name : '',
      ztLabel: zti ? zti.label : 'unknown',
      // Random initial position, re-used across frames for continuity
      x: (existing => existing ? existing.x : W/2 + (Math.random()-.5)*200)
          (_graphNodes.find(n => n.ip === ip)),
      y: (existing => existing ? existing.y : H/2 + (Math.random()-.5)*150)
          (_graphNodes.find(n => n.ip === ip)),
      vx: 0, vy: 0,
    };
  });

  // Build edges from shared rule names in recent incidents
  const rulesByIp = {};
  (incidents || []).forEach(inc => {
    if(!ipSet.has(inc.src_ip)) return;
    const reasons = inc.reasons || [];
    reasons.forEach(r => {
      const rule = r.split(':')[0].trim();
      if(!rulesByIp[inc.src_ip]) rulesByIp[inc.src_ip] = new Set();
      rulesByIp[inc.src_ip].add(rule);
    });
  });

  _graphEdges = [];
  const ipList = _graphNodes.map(n => n.ip);
  for(let i = 0; i < ipList.length; i++){
    for(let j = i+1; j < ipList.length; j++){
      const a = rulesByIp[ipList[i]] || new Set();
      const b = rulesByIp[ipList[j]] || new Set();
      const shared = [...a].filter(r => b.has(r));
      if(shared.length){
        _graphEdges.push({i, j, label: shared[0], strength: shared.length});
      }
    }
  }

  // Force-directed layout simulation
  const STEPS = 80;
  const REPEL  = 3000;
  const ATTRACT = 0.025;
  const DAMP   = 0.88;
  const IDEAL  = 140;

  for(let step = 0; step < STEPS; step++){
    // Repulsion between all nodes
    for(let i = 0; i < _graphNodes.length; i++){
      for(let j = i+1; j < _graphNodes.length; j++){
        const ni = _graphNodes[i], nj = _graphNodes[j];
        const dx = ni.x - nj.x, dy = ni.y - nj.y;
        const d  = Math.sqrt(dx*dx + dy*dy) || 1;
        const f  = REPEL / (d*d);
        ni.vx += f*dx/d; ni.vy += f*dy/d;
        nj.vx -= f*dx/d; nj.vy -= f*dy/d;
      }
    }
    // Edge attraction
    _graphEdges.forEach(e => {
      const ni = _graphNodes[e.i], nj = _graphNodes[e.j];
      const dx = nj.x - ni.x, dy = nj.y - ni.y;
      const d  = Math.sqrt(dx*dx + dy*dy) || 1;
      const f  = ATTRACT * (d - IDEAL);
      ni.vx += f*dx/d; ni.vy += f*dy/d;
      nj.vx -= f*dx/d; nj.vy -= f*dy/d;
    });
    // Center gravity
    _graphNodes.forEach(n => {
      n.vx += (W/2 - n.x) * 0.005;
      n.vy += (H/2 - n.y) * 0.005;
      n.vx *= DAMP; n.vy *= DAMP;
      n.x  = Math.max(n.radius+10, Math.min(W-n.radius-10, n.x + n.vx));
      n.y  = Math.max(n.radius+10, Math.min(H-n.radius-10, n.y + n.vy));
    });
  }

  // Draw
  ctx.clearRect(0, 0, W, H);

  // Draw edges
  _graphEdges.forEach(e => {
    const ni = _graphNodes[e.i], nj = _graphNodes[e.j];
    ctx.save();
    ctx.strokeStyle = 'rgba(100,116,139,0.35)';
    ctx.lineWidth   = 1 + Math.min(e.strength-1, 2);
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(ni.x, ni.y);
    ctx.lineTo(nj.x, nj.y);
    ctx.stroke();
    ctx.restore();
  });

  // Draw nodes
  _graphNodes.forEach(n => {
    // Outer glow for high-severity nodes
    if(n.maxSev === 'HIGH'){
      const grad = ctx.createRadialGradient(n.x, n.y, n.radius, n.x, n.y, n.radius*2.5);
      grad.addColorStop(0, n.color + '40');
      grad.addColorStop(1, 'transparent');
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.radius*2.5, 0, Math.PI*2);
      ctx.fillStyle = grad;
      ctx.fill();
    }
    // Fill
    ctx.beginPath();
    ctx.arc(n.x, n.y, n.radius, 0, Math.PI*2);
    ctx.fillStyle = n.color;
    ctx.fill();
    // Kill chain progress ring
    if(n.kcScore > 0){
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.radius+2, -Math.PI/2, -Math.PI/2 + n.kcScore*Math.PI*2);
      ctx.strokeStyle = '#ffffff66';
      ctx.lineWidth   = 2;
      ctx.stroke();
    }
    // Label
    if(showLbl){
      ctx.font      = '9px monospace';
      ctx.fillStyle = '#94a3b8';
      ctx.textAlign = 'center';
      const short = n.ip.split('.').slice(-2).join('.');
      ctx.fillText(short, n.x, n.y + n.radius + 11);
    }
  });
}

// Click/hover on graph canvas
(function(){
  const canvas = document.getElementById('graph-canvas');
  if(!canvas) return;
  canvas.addEventListener('mousemove', e => {
    if(!_graphNodes.length) return;
    const rect = canvas.getBoundingClientRect();
    const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
    const my = (e.clientY - rect.top)  * (canvas.height / rect.height);
    const tip = $('graph-tooltip');
    const hit = _graphNodes.find(n => {
      const dx = n.x - mx, dy = n.y - my;
      return Math.sqrt(dx*dx + dy*dy) <= n.radius + 4;
    });
    if(hit){
      tip.style.display = 'block';
      tip.style.left = (e.clientX - rect.left + 12) + 'px';
      tip.style.top  = (e.clientY - rect.top  - 10) + 'px';
      tip.innerHTML = `<b>${escHtml(hit.ip)}</b><br>
        Trust: <b style="color:${hit.color}">${escHtml(hit.ztLabel)}</b> (${Math.round(hit.score*100)}%)<br>
        Kill chain: ${escHtml(hit.kcLabel||'none')} (${Math.round(hit.kcScore*100)}%)<br>
        Incidents: ${hit.incidentCount}
        ${hit.country ? `<br>Location: ${escHtml(hit.country)}` : ''}`;
    } else {
      tip.style.display = 'none';
    }
  });
  canvas.addEventListener('mouseleave', () => {
    $('graph-tooltip').style.display = 'none';
  });
  canvas.addEventListener('click', e => {
    if(!_graphNodes.length) return;
    const rect = canvas.getBoundingClientRect();
    const mx = (e.clientX - rect.left) * (canvas.width / rect.width);
    const my = (e.clientY - rect.top)  * (canvas.height / rect.height);
    const hit = _graphNodes.find(n => {
      const dx = n.x - mx, dy = n.y - my;
      return Math.sqrt(dx*dx + dy*dy) <= n.radius + 4;
    });
    if(!hit) return;
    $('graph-detail-title').textContent = `Node: ${hit.ip}`;
    $('graph-detail').style.display = 'block';
    $('graph-detail-body').innerHTML = [
      ['IP',           hit.ip],
      ['Trust Score',  `${Math.round(hit.score*100)}% (${hit.ztLabel})`],
      ['Kill Chain',   hit.kcLabel || 'None'],
      ['KC Progress',  `${Math.round(hit.kcScore*100)}%`],
      ['Max Severity', hit.maxSev || '-'],
      ['Incidents',    hit.incidentCount],
      ['Location',     hit.country || '-'],
    ].map(([k,v]) => `<div><span style="color:var(--muted);font-size:11px">${k}</span><div style="font-weight:600">${escHtml(String(v))}</div></div>`).join('');
  });
})();

async function loadKillChain(){
  const completeOnly = document.getElementById('kc-complete-only').checked;
  const minScore     = document.getElementById('kc-min-score').value;
  const url = `/api/kill-chain?limit=200&min_score=${minScore}&complete_only=${completeOnly}`;
  const [chains, stats] = await Promise.all([
    apiFetch(url),
    apiFetch('/api/kill-chain/stats'),
  ]);

  // Stats bar
  if(stats){
    const bar = document.getElementById('kc-stats-bar');
    const pct  = stats.total_chains ? Math.round(stats.complete_chains / stats.total_chains * 100) : 0;
    bar.innerHTML = [
      `<span><b>${stats.total_chains}</b> chains tracked</span>`,
      `<span><b>${stats.complete_chains}</b> complete (${pct}%)</span>`,
      `<span>Avg score <b>${stats.avg_score}</b></span>`,
      Object.entries(stats.stage_distribution || {}).map(([s,c])=>
        `<span>${s}: <b>${c}</b></span>`
      ).join(''),
    ].join('<span style="color:var(--border)">|</span>');
  }

  if(!chains || !chains.length){
    document.getElementById('kc-tbody').innerHTML =
      '<tr><td colspan="8" style="text-align:center;color:var(--muted);padding:20px">No kill chains recorded yet</td></tr>';
    return;
  }

  const STAGE_COLORS = ['#6c757d','#dc3545','#fd7e14','#e74c3c','#9b59b6','#3498db','#1abc9c'];
  const tbody = document.getElementById('kc-tbody');
  tbody.innerHTML = chains.map(c => {
    const maxColor = STAGE_COLORS[c.max_stage] || '#6c757d';
    const scorePct = Math.round(c.score * 100);
    const completeBadge = c.complete
      ? '<span style="background:#e74c3c;color:#fff;padding:2px 6px;border-radius:3px;font-size:10px">COMPLETE</span>'
      : '<span style="background:var(--surface-2,#2a2a2a);color:var(--muted);padding:2px 6px;border-radius:3px;font-size:10px">partial</span>';
    const geo = [c.geo_city, c.geo_country].filter(Boolean).join(', ') || '-';
    return `<tr>
      <td><code>${escHtml(c.ip)}</code></td>
      <td><span style="color:${maxColor};font-weight:600">${escHtml(c.max_stage_name)}</span></td>
      <td>
        <div style="display:flex;align-items:center;gap:6px">
          <div style="width:60px;height:6px;background:var(--surface-2,#2a2a2a);border-radius:3px">
            <div style="width:${scorePct}%;height:6px;background:${maxColor};border-radius:3px"></div>
          </div>
          <span style="font-size:11px">${scorePct}%</span>
        </div>
      </td>
      <td>${completeBadge}</td>
      <td>${c.event_count}</td>
      <td style="font-size:11px">${escHtml(c.last_seen)}</td>
      <td style="font-size:11px">${escHtml(geo)}</td>
      <td><button onclick="showKcDetail('${escHtml(c.ip)}')" style="font-size:11px;padding:2px 8px;background:var(--accent);color:#fff;border:none;border-radius:3px;cursor:pointer">View</button></td>
    </tr>`;
  }).join('');
}

async function showKcDetail(ip){
  const chain = await apiFetch(`/api/kill-chain/${encodeURIComponent(ip)}`);
  if(!chain) return;
  document.getElementById('kc-detail-wrap').style.display = 'block';
  document.getElementById('kc-detail-title').textContent = `Kill Chain: ${ip}`;

  const STAGE_COLORS  = ['#6c757d','#dc3545','#fd7e14','#e74c3c','#9b59b6','#3498db','#1abc9c'];
  const STAGE_NAMES   = ['Reconnaissance','Weaponization','Delivery','Exploitation','Installation','C2','Actions'];
  const stagesEl = document.getElementById('kc-detail-stages');

  stagesEl.innerHTML = STAGE_NAMES.map((name, i) => {
    const observed = chain.stages && chain.stages[String(i)];
    const color    = observed ? STAGE_COLORS[i] : 'var(--surface-2,#2a2a2a)';
    const textCol  = observed ? '#fff' : 'var(--muted)';
    const count    = observed ? observed.count : 0;
    const kinds    = observed ? (observed.event_kinds || []).slice(0,3).join(', ') : '';
    const arrow    = i < STAGE_NAMES.length - 1
      ? `<div style="display:flex;align-items:center;padding-top:24px;color:${observed ? STAGE_COLORS[i] : 'var(--border)'};font-size:18px">&#8594;</div>`
      : '';
    return `<div style="display:flex;align-items:flex-start">
      <div style="min-width:120px;max-width:140px;background:${color};color:${textCol};border-radius:6px;padding:10px 12px;font-size:11px">
        <div style="font-weight:700;margin-bottom:4px">${name}</div>
        ${observed
          ? `<div>Events: <b>${count}</b></div><div style="margin-top:4px;word-break:break-all;opacity:.85">${escHtml(kinds)}</div>`
          : '<div style="opacity:.6">Not observed</div>'
        }
      </div>${arrow}
    </div>`;
  }).join('');

  const geo = [chain.geo_city, chain.geo_country].filter(Boolean).join(', ');
  document.getElementById('kc-detail-meta').innerHTML =
    `First seen: ${escHtml(chain.first_seen)} &nbsp;|&nbsp; Last seen: ${escHtml(chain.last_seen)}` +
    (geo ? ` &nbsp;|&nbsp; Location: ${escHtml(geo)}` : '') +
    ` &nbsp;|&nbsp; Score: ${Math.round(chain.score * 100)}%`;
}

async function loadZeroTrust(){
  const [stats, scores] = await Promise.all([
    apiFetch('/api/zero-trust/stats'),
    apiFetch('/api/zero-trust/scores?limit=100'),
  ]);

  if(!stats){
    $('zt-stats-bar').innerHTML = '<span style="color:var(--muted)">Zero-trust not available</span>';
    return;
  }

  $('zt-stats-bar').innerHTML = [
    {label:'Total entities', value: stats.total_entities ?? 0},
    {label:'Trusted',    value: stats.trusted    ?? 0, color:'#22c55e'},
    {label:'Moderate',   value: stats.moderate   ?? 0, color:'#f59e0b'},
    {label:'Suspicious', value: stats.suspicious ?? 0, color:'#ef4444'},
    {label:'Untrusted',  value: stats.untrusted  ?? 0, color:'#dc2626'},
    {label:'Avg score',  value: stats.avg_score  ?? ''},
  ].map(s => `<span${s.color ? ` style="color:${s.color}"` : ''}><b>${s.value}</b> ${escHtml(s.label)}</span>`).join(
    '<span style="color:var(--border)">|</span>'
  );

  if(!scores || !scores.length){
    $('zt-tbody').innerHTML = '<tr><td colspan="7" style="color:var(--muted);text-align:center;padding:20px">No scored entities yet -- signals appear after login events</td></tr>';
    return;
  }

  const LABEL_COLOR = {trusted:'#22c55e', moderate:'#f59e0b', suspicious:'#ef4444', untrusted:'#dc2626'};
  $('zt-tbody').innerHTML = scores.map(r => {
    const pct   = Math.round(r.score * 100);
    const color = LABEL_COLOR[r.label] || '#64748b';
    const lastSig = (r.recent_signals || []).slice(-1)[0];
    const lastSigText = lastSig
      ? `${escHtml(lastSig.signal)} (${lastSig.delta > 0 ? '+' : ''}${lastSig.delta})`
      : '-';
    return `<tr>
      <td><code>${escHtml(r.entity_id)}</code></td>
      <td style="font-size:11px">${escHtml(r.entity_type)}</td>
      <td><span style="color:${color};font-weight:600">${escHtml(r.label)}</span></td>
      <td>
        <div style="display:flex;align-items:center;gap:6px">
          <div style="width:50px;height:6px;background:var(--surface-2,#2a2a2a);border-radius:3px">
            <div style="width:${pct}%;height:6px;background:${color};border-radius:3px"></div>
          </div>
          <span style="font-size:11px">${pct}%</span>
        </div>
      </td>
      <td>${r.signal_count}</td>
      <td style="font-size:11px;color:var(--muted)">${escHtml(lastSigText)}</td>
      <td>
        <button onclick="ztReset('${escHtml(r.entity_id)}','${escHtml(r.entity_type)}')"
          style="font-size:10px;padding:2px 7px;background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:3px;cursor:pointer">Reset</button>
      </td>
    </tr>`;
  }).join('');
}
async function ztReset(entityId, entityType){
  await apiFetch(`/api/zero-trust/scores/${encodeURIComponent(entityId)}/reset?type=${entityType}`,{method:'POST'});
  loadZeroTrust();
}

async function loadCloudIdentityStatus(){
  const d = await apiFetch('/api/cloud-identity/status');
  const wrap = $('cloud-identity-cards');
  if(!d){
    wrap.innerHTML = '<span style="font-size:12px;color:var(--muted)">Cloud identity not available</span>';
    return;
  }
  const connectors = d.connectors || {};
  const labels = {aws_cloudtrail:'AWS CloudTrail', azure_ad:'Azure AD'};
  wrap.innerHTML = Object.entries(labels).map(([name, label]) => {
    const c       = connectors[name] || {};
    const enabled = c.enabled !== false;
    const healthy = c.healthy !== false;
    const status  = !enabled ? 'Disabled' : healthy ? 'Healthy' : 'Error';
    const color   = !enabled ? '#64748b'  : healthy ? '#22c55e' : '#ef4444';
    const err     = c.last_error ? `<div style="font-size:10px;color:#ef4444;margin-top:4px;word-break:break-all">${escHtml(c.last_error)}</div>` : '';
    const polls   = c.poll_count != null ? `<div style="font-size:11px;color:var(--muted);margin-top:2px">Polls: ${c.poll_count} | Errors: ${c.error_count||0}</div>` : '';
    const token   = c.token_valid != null ? `<div style="font-size:10px;color:var(--muted)">Token: ${c.token_valid ? 'valid' : 'expired'}</div>` : '';
    return `<div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:12px">
      <div style="font-weight:600;font-size:12px;margin-bottom:6px">${label}</div>
      <div style="color:${color};font-size:11px;font-weight:600">${status}</div>
      ${polls}${token}${err}
    </div>`;
  }).join('');
  if(d.events_fed != null){
    wrap.innerHTML += `<div style="grid-column:1/-1;font-size:11px;color:var(--muted);padding-top:4px">Events fed into detection pipeline: <b>${d.events_fed}</b> &nbsp;|&nbsp; Poll interval: <b>${d.poll_interval_sec}s</b></div>`;
  }
}

async function loadFederationStatus(){
  const [status, nodesRes, crossNode] = await Promise.all([
    apiFetch('/api/federation/status'),
    apiFetch('/api/federation/nodes'),
    apiFetch('/api/federation/cross-node?limit=20'),
  ]);

  if(!status){
    $('federation-summary').innerHTML = '<span style="font-size:12px;color:var(--muted)">Federation not available</span>';
    return;
  }

  const connColor = status.connected ? '#22c55e' : '#64748b';
  const connText  = status.connected ? 'Connected' : (status.enabled ? 'Disconnected' : 'Disabled');
  $('federation-summary').innerHTML = [
    {label:'Status',           value: connText, color: connColor},
    {label:'Signals Sent',     value: status.signals_sent ?? 0},
    {label:'Signals Received', value: status.signals_received ?? 0},
    {label:'Cross-Node IPs',   value: status.cross_node_ips ?? 0, color: status.cross_node_ips > 0 ? '#ef4444' : null},
  ].map(c => `<div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:10px 12px">
    <div style="font-size:10px;color:var(--muted);margin-bottom:4px">${c.label}</div>
    <div style="font-size:15px;font-weight:700;${c.color ? `color:${c.color}` : ''}">${c.value}</div>
  </div>`).join('');

  const nodes = (nodesRes && nodesRes.nodes) || [];
  $('federation-nodes-tbody').innerHTML = nodes.length
    ? nodes.map(n => `<tr>
        <td><code>${escHtml(n.node_id)}</code></td>
        <td style="font-size:11px;color:var(--muted)">${escHtml(n.last_seen)}</td>
      </tr>`).join('')
    : '<tr><td colspan="2" style="color:var(--muted);text-align:center;padding:12px">No peer nodes yet -- check redis.enabled and federation.enabled in config</td></tr>';

  $('federation-crossnode-tbody').innerHTML = (crossNode && crossNode.length)
    ? crossNode.map(r => {
        const nodeNames = Object.keys(r.nodes || {});
        const allKinds  = [...new Set(Object.values(r.nodes || {}).flatMap(n => n.kinds))];
        return `<tr>
          <td><code>${escHtml(r.ip)}</code></td>
          <td style="font-size:11px">${nodeNames.map(escHtml).join(', ')}</td>
          <td style="font-size:11px;color:var(--muted)">${allKinds.map(escHtml).join(', ')}</td>
          <td style="font-size:11px">${escHtml(r.last_seen)}</td>
        </tr>`;
      }).join('')
    : '<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:12px">No cross-node activity yet</td></tr>';
}

async function loadSIEMStatus(){
  const d = await apiFetch('/api/siem/status');
  if(!d){
    $('siem-status-cards').innerHTML = '<span style="font-size:12px;color:var(--muted)">SIEM router not available</span>';
    return;
  }
  const connectors = d.connectors || {};
  const names      = ['splunk','sentinel','webhook'];
  const labels     = {splunk:'Splunk HEC', sentinel:'Microsoft Sentinel', webhook:'Webhook'};
  $('siem-status-cards').innerHTML = names.map(name => {
    const c       = connectors[name] || {};
    const enabled = c.enabled !== false;
    const healthy = c.healthy !== false;
    const status  = !enabled ? 'Disabled' : healthy ? 'Healthy' : 'Error';
    const color   = !enabled ? '#64748b'  : healthy  ? '#22c55e' : '#ef4444';
    const err     = c.last_error ? `<div style="font-size:10px;color:#ef4444;margin-top:4px;word-break:break-all">${escHtml(c.last_error)}</div>` : '';
    const pushed  = c.push_count  != null ? `<div style="font-size:11px;color:var(--muted);margin-top:2px">Pushed: ${c.push_count} | Errors: ${c.error_count||0}</div>` : '';
    return `<div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:12px">
      <div style="font-weight:600;font-size:12px;margin-bottom:6px">${labels[name]}</div>
      <div style="color:${color};font-size:11px;font-weight:600">${status}</div>
      ${pushed}${err}
      ${enabled ? `<div style="display:flex;gap:6px;margin-top:8px">
        <button onclick="siemTest('${name}')" style="font-size:10px;padding:2px 8px;background:var(--accent);color:#fff;border:none;border-radius:3px;cursor:pointer">Send Test</button>
      </div>` : ''}
    </div>`;
  }).join('');
  const qd = d.queue_depth || 0;
  $('siem-queue-line').innerHTML = qd > 0
    ? `Retry queue: <b style="color:#f59e0b">${qd}</b> events pending &nbsp;
       <button onclick="siemFlush()" style="font-size:10px;padding:2px 8px;background:#f59e0b;color:#fff;border:none;border-radius:3px;cursor:pointer">Flush Now</button>`
    : 'Retry queue: empty';
}
async function siemTest(name){
  const d = await apiFetch(`/api/siem/test/${name}`,{method:'POST'});
  if(d) alert(d.ok ? `Test event sent to ${name}` : `Test failed: ${d.error || 'unknown error'}`);
  loadSIEMStatus();
}
async function siemFlush(){
  const d = await apiFetch('/api/siem/flush',{method:'POST'});
  if(d) alert(`Flushed: ${JSON.stringify(d.flushed)}`);
  loadSIEMStatus();
}

async function loadSettings(){
  // Module status
  const debug = await apiFetch('/api/debug');
  if(debug){
    const modules = [
      {k:'geoip',       label:'GeoIP'},
      {k:'abuseipdb',   label:'AbuseIPDB'},
      {k:'redis',       label:'Redis Sync'},
      {k:'fim',         label:'File Integrity Monitoring'},
      {k:'ml',          label:'ML Detection'},
      {k:'honeypot',    label:'Honeypot'},
      {k:'ueba',        label:'UEBA'},
      {k:'threat_feed', label:'Threat Feed'},
      {k:'kafka',       label:'Kafka'},
      {k:'rate_limit',  label:'Rate Limiting'},
      {k:'huddle',      label:'HuddleCluster'},
    ];
    $('settings-modules').innerHTML = modules.map(m=>{
      const on = debug[m.k]===true || debug[m.k]==='enabled';
      return `<div style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--surf);border:1px solid var(--bord);border-radius:5px">
        <span style="width:8px;height:8px;border-radius:50%;background:${on?'#22c55e':'#475569'};flex-shrink:0"></span>
        <span style="font-size:12px;color:${on?'var(--text)':'var(--muted)'}">${m.label}</span>
      </div>`;
    }).join('');
  }

  // Zeek toggle helper
  const zeekLogs = ['conn','ssh','http','dns','notice','weird'];
  $('zeek-toggle-btns').innerHTML = zeekLogs.map(l=>`
    <button class="btn" onclick="alert('Edit zeek.logs.${l} in /etc/cnsl/config.json and restart CNSL')"
      style="font-size:11px;padding:4px 12px">
      ${l}.log
    </button>`).join('');

  // HuddleCluster status
  const hd = await apiFetch('/api/huddle');
  if(hd){
    if(!hd.enabled){
      $('huddle-status-line').textContent = 'Disabled — enable in config.json: "huddle": {"enabled": true, "nodes": [...]}';
    } else {
      const inner = hd.inner_servers||[];
      const outer = hd.outer_servers||[];
      $('huddle-inner-list').innerHTML = inner.map(s=>`
        <div style="padding:8px 14px;background:var(--surf);border:1px solid var(--bord);border-radius:5px;min-width:120px">
          <div style="font-size:11px;color:var(--muted)">INNER (active)</div>
          <div style="font-size:12px;font-weight:600;margin:2px 0">${escHtml(s.id)}</div>
          <div style="font-size:11px;color:var(--acc)">${escHtml(s.host)}:${escHtml(String(s.port))}</div>
          <div style="font-size:11px;margin-top:4px">
            temp: <span class="${s.temp>0.7?'c-red':s.temp>0.4?'c-yellow':'c-green'}">${(s.temp*100).toFixed(0)}%</span>
            &nbsp;p95: ${s.p95}ms
          </div>
        </div>`).join('') +
        outer.map(s=>`
        <div style="padding:8px 14px;background:var(--surf);border:1px solid var(--bord);border-radius:5px;min-width:120px;opacity:0.6">
          <div style="font-size:11px;color:var(--muted)">OUTER (resting)</div>
          <div style="font-size:12px;font-weight:600;margin:2px 0">${escHtml(s.id)}</div>
          <div style="font-size:11px;color:var(--muted)">${escHtml(s.host)}:${escHtml(String(s.port))}</div>
          <div style="font-size:11px;margin-top:4px">temp: ${(s.temp*100).toFixed(0)}%</div>
        </div>`).join('');
      $('huddle-status-line').textContent =
        `Rotations: ${hd.rotations||0}  |  Fairness: ${((hd.fairness||1)*100).toFixed(0)}%  |  Local: ${hd.local_id||'—'}  temp: ${((hd.local_temp||0)*100).toFixed(0)}%`;
    }
  }

  // Config reference
  $('settings-config-ref').innerHTML = [
    {k:'zeek.enabled',     v:'Disable to stop Zeek "waiting" messages'},
    {k:'ueba.enabled',     v:'Per-user behavioral profiling'},
    {k:'threat_feed.enabled', v:'Community blocklist (Emerging Threats etc.)'},
    {k:'rate_limiting.enabled',v:'Per-IP rate limiting + DDoS protection'},
    {k:'kafka.enabled',    v:'Kafka log ingestion'},
    {k:'country_block.enabled',v:'Block entire countries by ISO code'},
    {k:'fim.enabled',      v:'File integrity monitoring'},
    {k:'ml.enabled',       v:'ML anomaly detection (IsolationForest)'},
  ].map(r=>`<div style="padding:8px 0;border-bottom:1px solid var(--bord)">
    <code style="font-size:11px;color:var(--acc)">${r.k}</code>
    <div style="font-size:11px;color:var(--muted);margin-top:2px">${r.v}</div>
  </div>`).join('');
}

//  Auth 
async function doLogout(){
  await fetch('/api/logout',{method:'POST',headers:authHdr()}).catch(()=>{});
  localStorage.removeItem('cnsl_token');
  location.href='/login';
}

//  API fetch helper 
async function apiFetch(url,opts={}){
  opts.headers={...authHdr(),...(opts.headers||{})};
  const r=await fetch(url,opts);
  if(r.status===401){location.href='/login';return null;}
  return r.json();
}

//  Charts 
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

//  Live Feed 
function addFeed(text,cls='feed-info'){
  const feed=$('live-feed');
  const line=document.createElement('div');
  line.className='feed-line '+cls;
  line.textContent='['+new Date().toLocaleTimeString()+'] '+text;
  feed.prepend(line);
  while(feed.children.length>300)feed.removeChild(feed.lastChild);
}
function clearFeed(){$('live-feed').innerHTML='';}

//  Fetchers 
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
      <td class="mono">${escHtml(r.src_ip||'—')}</td>
      <td style="font-size:12px">${escHtml(r.flag||'')} ${escHtml(r.country||'—')}</td>
      <td><span class="sev sev-${escHtml(r.severity)}">${escHtml(r.severity)}</span></td>
      <td style="color:var(--muted)">${r.fail_count||0}</td>
      <td style="font-size:11px;color:var(--muted);max-width:200px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">
        ${(r.reasons||[]).map(escHtml).join(', ')||'—'}
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
      <td class="mono">${escHtml(r.ip)}</td>
      <td style="font-size:12px">${escHtml(r.flag||'')} ${escHtml(r.country||'—')}</td>
      <td style="font-size:11px;color:var(--muted)">${fmtDate(r.blocked_at)}</td>
      <td style="font-size:11px;color:var(--amber)">${fmtDate(r.unblock_at)}</td>
      <td><button class="btn btn-green" onclick="doUnblock('${escHtml(r.ip)}')">Unblock</button></td>
    </tr>`).join('');
}

async function fetchTopAttackers(){
  const rows=await apiFetch('/api/top-attackers');
  if(!rows||!rows.length)return;
  $('attackers-body').innerHTML=rows.map(r=>`
    <tr>
      <td class="mono">${escHtml(r.src_ip)}</td>
      <td style="font-size:12px">${escHtml(r.flag||'')} ${escHtml(r.country||'—')} ${r.city?'· '+escHtml(r.city):''}</td>
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
      <td class="mono">${escHtml(s.attacker_ip)}</td>
      <td style="font-size:11px;color:var(--muted)">${s.time||fmtDate(s.start_time)}</td>
      <td style="color:var(--muted)">${Math.round(s.duration_sec||0)}s</td>
      <td style="color:var(--amber)">${(s.auth_attempts||[]).length}</td>
      <td class="cmds">${(s.commands||[]).map(escHtml).join(' | ')||'—'}</td>
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
  $('fim-paths-list').innerHTML=(d.watch_paths||[]).map(p=>`<div>${escHtml(p)}</div>`).join('');
  const tb=$('fim-body');
  const alerts=d.alerts||[];
  if(!alerts.length){
    tb.innerHTML='<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:20px">No alerts</td></tr>';
    return;
  }
  tb.innerHTML=alerts.map(a=>`
    <tr>
      <td style="font-size:11px;color:var(--muted)">${a.time||fmtDate(a.ts)}</td>
      <td class="mono" style="font-size:11px;max-width:220px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escHtml(a.path)}</td>
      <td><span class="chg chg-${escHtml(a.change)}">${escHtml(a.change)}</span></td>
      <td><span class="sev sev-${escHtml(a.severity)}">${escHtml(a.severity)}</span></td>
    </tr>`).join('');
}

async function fetchML(){
  const [d, alerts, feats] = await Promise.all([
    apiFetch('/api/ml-status'),
    apiFetch('/api/ml/alerts?limit=30'),
    apiFetch('/api/ml/feature-stats'),
  ]);
  if(!d) return;
  const enabled = d.enabled === true;
  $('ml-status-pill').innerHTML = enabled
    ? '<span class="pill pill-on">enabled</span>'
    : '<span class="pill pill-off">disabled</span>';
  $('ml-disabled-note').style.display = enabled ? 'none' : 'flex';
  if(!enabled) return;
  const trained = d.trained === true;
  $('ml-trained-pill').innerHTML = trained
    ? '<span class="pill pill-on">trained</span>'
    : '<span class="pill pill-off">not trained</span>';
  $('ml-tracked').textContent     = d.tracked_ips     ?? '0';
  $('ml-alert-count').textContent = d.recent_alert_count ?? '0';
  const cur = d.training_samples || 0;
  const min = d.min_samples || 100;
  const pct = Math.min(100, Math.round(cur / min * 100));
  $('ml-sample-count').textContent = cur + ' / ' + min;
  $('ml-prog').style.width         = pct + '%';
  $('ml-last-trained').textContent = d.last_trained || 'never';

  // Populate param inputs with current values
  if(document.getElementById('ml-param-contamination').value === ''){
    $('ml-param-contamination').value = d.contamination ?? 0.05;
    $('ml-param-threshold').value     = d.threshold     ?? -0.1;
    $('ml-param-min-samples').value   = d.min_samples   ?? 100;
    $('ml-param-retrain').value       = d.retrain_interval_sec ?? 3600;
  }

  // Feature importance bars
  const featWrap = $('ml-feature-bars');
  if(feats && Object.keys(feats).length){
    const maxV = Math.max(...Object.values(feats));
    featWrap.innerHTML = Object.entries(feats).slice(0, 10).map(([k, v]) => `
      <div style="margin-bottom:8px">
        <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--muted);margin-bottom:3px">
          <span>${escHtml(k)}</span><span>${v}</span>
        </div>
        <div style="height:6px;background:var(--surface-2,#2a2a2a);border-radius:3px">
          <div style="height:6px;width:${Math.round(v/maxV*100)}%;background:var(--accent);border-radius:3px"></div>
        </div>
      </div>`).join('');
  } else {
    featWrap.innerHTML = '<span style="font-size:12px;color:var(--muted)">No anomalies detected yet</span>';
  }

  // Recent alerts table
  if(alerts && alerts.length){
    $('ml-alerts-tbody').innerHTML = alerts.slice().reverse().map(a => {
      const scorePct = Math.round(Math.abs(a.anomaly_score || 0) * 100);
      const reasons  = (a.top_reasons || []).slice(0, 2).map(escHtml).join('; ');
      return `<tr>
        <td style="font-size:11px">${escHtml(a.ts || '')}</td>
        <td><code>${escHtml(a.ip || '')}</code></td>
        <td><span style="color:#f59e0b;font-weight:600">${scorePct}</span></td>
        <td style="font-size:11px;color:var(--muted)">${reasons}</td>
      </tr>`;
    }).join('');
  } else {
    $('ml-alerts-tbody').innerHTML = '<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:20px">No ML anomalies detected yet</td></tr>';
  }
}

async function mlSaveParams(){
  const msg = $('ml-param-msg');
  const body = {
    contamination:        parseFloat($('ml-param-contamination').value),
    threshold:            parseFloat($('ml-param-threshold').value),
    min_samples:          parseInt($('ml-param-min-samples').value, 10),
    retrain_interval_sec: parseInt($('ml-param-retrain').value, 10),
  };
  const d = await apiFetch('/api/ml/params', {method:'PATCH', body: JSON.stringify(body)});
  if(d && d.updated){
    msg.textContent = 'Saved: ' + Object.keys(d.updated).join(', ');
    msg.style.color = '#22c55e';
  } else {
    msg.textContent = 'Failed to save';
    msg.style.color = '#ef4444';
  }
  setTimeout(() => { msg.textContent = ''; }, 3000);
  fetchML();
}

async function mlTriggerRetrain(){
  const btn = $('ml-retrain-btn');
  btn.textContent = 'Retraining...';
  btn.disabled    = true;
  const d = await apiFetch('/api/ml/retrain', {method:'POST'});
  if(d && d.ok){
    btn.textContent = 'Started';
    setTimeout(() => { btn.textContent = 'Retrain Now'; btn.disabled = false; fetchML(); }, 2000);
  } else {
    btn.textContent = d ? d.reason : 'Failed';
    setTimeout(() => { btn.textContent = 'Retrain Now'; btn.disabled = false; }, 3000);
  }
}

//  Actions 
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

//  PDF Export 
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

//  SSE 
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

//  Refresh loop 
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