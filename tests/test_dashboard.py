"""
tests/test_dashboard.py -- split from test_cnsl.py (v3.4.3 test suite reorg).

Run:
    pytest tests/test_dashboard.py -v
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from unittest.mock import AsyncMock, MagicMock

import pytest

from cnsl.config import DEFAULT_CONFIG, load_config, safe_int
from cnsl.models import Event, EventKind, Severity, iso_time, now
from cnsl.parsers import parse_auth_event, parse_tcpdump_hint
from cnsl.detector import Detector, IPState, _prune, _unique_users

from helpers import make_cfg, make_detector, _run, _det, _make_cm, _SKLEARN_AVAILABLE


class TestDashboardSignature:
    """start_dashboard must accept ml_detector and fim kwargs
    — if it doesn't, engine.py silently passes None and both tabs show disabled."""

    def test_start_dashboard_accepts_ml_and_fim(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        params = list(sig.parameters.keys())
        assert "ml_detector" in params, \
            "start_dashboard missing ml_detector param — ML tab will always show disabled"
        assert "fim" in params, \
            "start_dashboard missing fim param — FIM tab will always show disabled"

    def test_start_dashboard_ml_fim_default_none(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        assert sig.parameters["ml_detector"].default is None
        assert sig.parameters["fim"].default is None

# v1.2.0 — country blocking + email notification

class TestDashboardSignatureWithWS:
    """Dashboard start_dashboard accepts new ws/agent parameters."""

    def test_start_dashboard_accepts_ueba(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        assert "ueba"        in sig.parameters
        assert "threat_feed" in sig.parameters
        assert "case_manager" in sig.parameters

    def test_start_dashboard_all_new_params_optional(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        for name in ("ueba", "threat_feed", "case_manager"):
            p = sig.parameters[name]
            assert p.default is not inspect.Parameter.empty, \
                f"{name} should have a default value"

class TestDashboardSignatureV2:
    """start_dashboard must accept kill_chain, pattern_learner, siem_router
    -- if it doesn't, engine.py silently passes None and the new dashboard
    tabs/sections always show as unavailable."""

    def test_start_dashboard_accepts_new_v2_params(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        params = list(sig.parameters.keys())
        assert "kill_chain" in params, \
            "start_dashboard missing kill_chain param -- Kill Chain tab will always show disabled"
        assert "pattern_learner" in params, \
            "start_dashboard missing pattern_learner param -- Suggested Rules panel will always be empty"
        assert "siem_router" in params, \
            "start_dashboard missing siem_router param -- SIEM status will always show unavailable"

    def test_start_dashboard_new_v2_params_default_none(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        for name in ("kill_chain", "pattern_learner", "siem_router"):
            assert sig.parameters[name].default is None

class TestDashboardSignatureV3:
    """start_dashboard must accept federation -- if it doesn't, engine.py
    silently passes None and the Federation panel always shows unavailable."""

    def test_start_dashboard_accepts_federation_param(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        assert "federation" in sig.parameters.keys(), \
            "start_dashboard missing federation param -- Federation panel will always show unavailable"
        assert sig.parameters["federation"].default is None


# v2.6.0 -- cloud identity connectors

class TestGraphTabPresence:
    """Graph tab button and page exist in the dashboard HTML."""

    def _get_html(self):
        from pathlib import Path
        root = Path(__file__).parent.parent / "cnsl"
        # HTML is now in dashboard_html.py; routes remain in dashboard.py
        return (
            (root / "dashboard.py").read_text(encoding="utf-8") +
            (root / "dashboard_html.py").read_text(encoding="utf-8")
        )

    def test_graph_tab_button_present(self):
        html = self._get_html()
        assert "showTab('graph')" in html, "Graph tab button missing from nav"

    def test_graph_page_div_present(self):
        html = self._get_html()
        assert 'id="page-graph"' in html, "Graph page div missing"

    def test_graph_canvas_present(self):
        html = self._get_html()
        assert 'id="graph-canvas"' in html, "Graph canvas element missing"

    def test_load_graph_js_function_present(self):
        html = self._get_html()
        assert "async function loadGraph()" in html, "loadGraph() JS function missing"

    def test_render_graph_js_function_present(self):
        html = self._get_html()
        assert "function renderGraph()" in html, "renderGraph() JS function missing"

    def test_graph_tooltip_present(self):
        html = self._get_html()
        assert 'id="graph-tooltip"' in html, "Graph tooltip element missing"

    def test_graph_detail_panel_present(self):
        html = self._get_html()
        assert 'id="graph-detail"' in html, "Graph node detail panel missing"

class TestGraphAPIRoute:
    """GET /api/graph route registered in start_dashboard."""

    def test_graph_api_route_registered(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "dashboard.py").read_text(encoding="utf-8")
        assert '"/api/graph"' in src, "/api/graph route missing from dashboard.py"

class TestDashboardSignatureV4:
    """start_dashboard must still accept all module params including zero_trust."""

    def test_start_dashboard_has_zero_trust(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        assert "zero_trust" in sig.parameters
        assert sig.parameters["zero_trust"].default is None

    def test_start_dashboard_has_cloud_identity(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        assert "cloud_identity" in sig.parameters

# v2.9.0 -- ML tuning UI

class TestTailLogFileRotation:
    """tail_log_file has inode-tracking fallback when tail binary unavailable."""

    def test_inode_tracking_present_in_source(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "log_sources.py"
               ).read_text(encoding="utf-8")
        assert "st_ino" in src, \
            "inode tracking missing from tail_log_file fallback"

    def test_shutil_which_check_present(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "log_sources.py"
               ).read_text(encoding="utf-8")
        assert "shutil.which" in src, \
            "shutil.which check missing -- no fallback detection"

class TestStartupParallelism:
    """engine.py uses asyncio.gather for kill_chain + pattern_learner load."""

    def test_gather_used_for_parallel_load(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "engine.py"
               ).read_text(encoding="utf-8")
        assert "asyncio.gather(" in src, \
            "asyncio.gather missing from engine.py startup -- loads are sequential"
        assert "kill_chain_tracker.load_all" in src
        assert "pattern_learner.load_all" in src

class TestSIGHUPHotReload:
    """engine.py registers SIGHUP handler for config hot-reload."""

    def test_sighup_handler_registered(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "engine.py"
               ).read_text(encoding="utf-8")
        assert "SIGHUP" in src, \
            "SIGHUP handler missing from engine.py -- no config hot-reload"
        assert "_handle_sighup" in src
        assert "_apply_config" in src

# v3.2.0 -- Batch 4: dashboard split + PostgreSQL backend

class TestDashboardSplit:
    """dashboard_html.py must exist and contain _LOGIN_HTML and _HTML."""

    def test_dashboard_html_module_exists(self):
        from pathlib import Path
        assert (Path(__file__).parent.parent / "cnsl" / "dashboard_html.py").exists(), \
            "cnsl/dashboard_html.py missing -- HTML not split from dashboard.py"

    def test_login_html_in_html_module(self):
        from cnsl.dashboard_html import _LOGIN_HTML
        assert "<!DOCTYPE html>" in _LOGIN_HTML
        assert "login" in _LOGIN_HTML.lower()

    def test_main_html_in_html_module(self):
        from cnsl.dashboard_html import _HTML
        assert "<!DOCTYPE html>" in _HTML
        assert len(_HTML) > 10000  # must be the full template

    def test_dashboard_imports_from_html_module(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "dashboard.py"
               ).read_text(encoding="utf-8")
        assert "from .dashboard_html import" in src, \
            "dashboard.py does not import from dashboard_html.py"

    def test_dashboard_py_under_2000_lines(self):
        from pathlib import Path
        lines = len((Path(__file__).parent.parent / "cnsl" / "dashboard.py"
                     ).read_text(encoding="utf-8").splitlines())
        assert lines < 2000, \
            f"dashboard.py has {lines} lines -- split did not reduce size enough"

    def test_html_module_has_no_route_handlers(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "dashboard_html.py"
               ).read_text(encoding="utf-8")
        assert "@router." not in src, \
            "dashboard_html.py contains route handlers -- should only have HTML"

class TestMetricsLastEventTs:
    """Metrics tracks _last_event_ts on inc_event()."""

    def test_last_event_ts_zero_initially(self):
        from cnsl.metrics import Metrics
        m = Metrics()
        assert m._last_event_ts == 0.0

    def test_last_event_ts_updated_on_inc_event(self):
        import time
        from cnsl.metrics import Metrics
        m = Metrics()
        before = time.time()
        m.inc_event()
        assert m._last_event_ts >= before

    def test_start_attribute_exists(self):
        from cnsl.metrics import Metrics
        m = Metrics()
        assert hasattr(m, "_start")
        assert m._start > 0

class TestHealthEndpointRoute:
    """GET /api/health route is registered in dashboard.py."""

    def _src(self):
        from pathlib import Path
        return (Path(__file__).parent.parent / "cnsl" / "dashboard.py"
                ).read_text(encoding="utf-8")

    def test_health_route_registered(self):
        assert '"/api/health"' in self._src(), \
            "/api/health route missing from dashboard.py"

    def test_health_no_auth_required(self):
        src = self._src()
        # Find the health endpoint and verify no _require_auth before it
        health_idx = src.find('"/api/health"')
        system_idx = src.find('"/api/system"')
        health_block = src[health_idx:system_idx]
        assert "_require_auth" not in health_block, \
            "/api/health must not require auth (used by load balancer probes)"

    def test_health_returns_version(self):
        src = self._src()
        health_idx = src.find('"/api/health"')
        system_idx = src.find('"/api/system"')
        health_block = src[health_idx:system_idx]
        assert "__version__" in health_block

    def test_health_checks_database(self):
        src = self._src()
        health_idx = src.find('"/api/health"')
        system_idx = src.find('"/api/system"')
        health_block = src[health_idx:system_idx]
        assert "database" in health_block

    def test_health_checks_redis(self):
        src = self._src()
        health_idx = src.find('"/api/health"')
        system_idx = src.find('"/api/system"')
        health_block = src[health_idx:system_idx]
        assert "redis" in health_block

    def test_health_checks_event_queue(self):
        src = self._src()
        health_idx = src.find('"/api/health"')
        system_idx = src.find('"/api/system"')
        health_block = src[health_idx:system_idx]
        assert "event_queue" in health_block

    def test_health_returns_503_on_unhealthy(self):
        src = self._src()
        health_idx = src.find('"/api/health"')
        system_idx = src.find('"/api/system"')
        health_block = src[health_idx:system_idx]
        assert "503" in health_block

    def test_health_has_status_levels(self):
        src = self._src()
        health_idx = src.find('"/api/health"')
        system_idx = src.find('"/api/system"')
        health_block = src[health_idx:system_idx]
        assert "healthy" in health_block
        assert "degraded" in health_block
        assert "unhealthy" in health_block

class TestStartDashboardHealthParams:
    """start_dashboard now accepts queue and redis_sync params."""

    def test_queue_param_in_signature(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        assert "queue" in sig.parameters, \
            "start_dashboard missing queue param needed by /api/health"
        assert sig.parameters["queue"].default is None

    def test_redis_sync_param_in_signature(self):
        import inspect
        from cnsl.dashboard import start_dashboard
        sig = inspect.signature(start_dashboard)
        assert "redis_sync" in sig.parameters, \
            "start_dashboard missing redis_sync param needed by /api/health"
        assert sig.parameters["redis_sync"].default is None


# IPv6-aware blocking (iptables/ipset backend picks ip6tables / *_v6 set)

class TestTelegramEscape:
    """_tg_escape must neutralise Markdown v1 special chars in dynamic content."""

    def test_escape_underscore(self):
        from cnsl.notify import _tg_escape
        assert _tg_escape("Verizon_Business") == "Verizon\\_Business"

    def test_escape_asterisk(self):
        from cnsl.notify import _tg_escape
        assert _tg_escape("score*98") == "score\\*98"

    def test_escape_backtick(self):
        from cnsl.notify import _tg_escape
        assert _tg_escape("cmd`exec`") == "cmd\\`exec\\`"

    def test_escape_bracket(self):
        from cnsl.notify import _tg_escape
        assert _tg_escape("[link]") == "\\[link]"

    def test_no_change_plain(self):
        from cnsl.notify import _tg_escape
        assert _tg_escape("Hello World 123") == "Hello World 123"

    def test_escape_combined(self):
        from cnsl.notify import _tg_escape
        result = _tg_escape("AS12345_ISP*provider")
        assert "\\_" in result
        assert "\\*" in result


# v1.0.2 — LOW severity count fix
