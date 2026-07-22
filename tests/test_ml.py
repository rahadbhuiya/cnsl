"""
tests/test_ml.py -- split from test_cnsl.py (v3.4.3 test suite reorg).

Run:
    pytest tests/test_ml.py -v
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


class TestMLRetrain:
    """_retrain must not update _last_train when data is insufficient."""

    def test_last_train_not_updated_below_min_samples(self):
        """Does not import sklearn — tests pure timer logic only."""
        import asyncio
        from cnsl.ml_detector import MLDetector
        logger = AsyncMock()
        cfg = {"ml": {"enabled": True, "min_samples": 100, "retrain_interval_sec": 1}}
        ml = MLDetector(cfg, logger)
        assert ml._last_train == 0.0

        async def _go():
            await ml._retrain()   # 0 samples — must be a no-op

        asyncio.run(_go())
        assert ml._last_train == 0.0, (
            "_last_train was updated even though there was no training data"
        )

    def test_last_train_updated_after_successful_train(self):
        """Train with enough samples — _trained becomes True, _last_train > 0."""
        import asyncio
        if not _SKLEARN_AVAILABLE:
            pytest.skip("scikit-learn not installed")

        try:
            from cnsl.ml_detector import MLDetector, FeatureWindow
        except Exception as e:
            pytest.skip(f"ml_detector import failed: {e}")

        logger = AsyncMock()
        cfg = {"ml": {"enabled": True, "min_samples": 3, "retrain_interval_sec": 1}}
        ml = MLDetector(cfg, logger)

        fw = FeatureWindow(ip="1.2.3.4", ts=time.time())
        fw.ssh_fail_count = 5
        for _ in range(5):
            ml._training_data.append(fw.to_vector())

        async def _go():
            await ml._retrain()

        asyncio.run(_go())
        assert ml._trained is True
        assert ml._last_train > 0.0


# v1.0.2 — dashboard signature fix

class TestMLDetectorRecentAlerts:
    """_recent_alerts deque is populated and bounded."""

    def _make_detector(self):
        from cnsl.ml_detector import MLDetector
        from cnsl.logger import JsonLogger
        cfg = {"ml": {"enabled": True, "min_samples": 1,
                      "contamination": 0.5, "anomaly_score_threshold": 0.0}}
        return MLDetector(cfg, JsonLogger("/dev/null", verbose=False))

    def test_recent_alerts_starts_empty(self):
        det = self._make_detector()
        assert len(det._recent_alerts) == 0

    def test_recent_alerts_list_returns_empty(self):
        det = self._make_detector()
        assert det.recent_alerts_list() == []

    def test_feature_stats_empty_when_no_alerts(self):
        det = self._make_detector()
        assert det.feature_stats() == {}

class TestMLDetectorUpdateParams:
    """update_params() applies valid changes and clamps values."""

    def _make_detector(self):
        from cnsl.ml_detector import MLDetector
        from cnsl.logger import JsonLogger
        cfg = {"ml": {"enabled": True, "min_samples": 100,
                      "contamination": 0.05, "anomaly_score_threshold": -0.1,
                      "retrain_interval_sec": 3600}}
        return MLDetector(cfg, JsonLogger("/dev/null", verbose=False))

    def test_update_contamination(self):
        det = self._make_detector()
        result = det.update_params(contamination=0.1)
        assert det.contamination == 0.1
        assert result["updated"]["contamination"] == 0.1

    def test_update_threshold(self):
        det = self._make_detector()
        det.update_params(threshold=-0.2)
        assert det.threshold == -0.2

    def test_update_min_samples(self):
        det = self._make_detector()
        det.update_params(min_samples=200)
        assert det.min_samples == 200

    def test_update_retrain_interval(self):
        det = self._make_detector()
        det.update_params(retrain_interval_sec=7200)
        assert det.retrain_sec == 7200

    def test_contamination_clamped_to_min(self):
        det = self._make_detector()
        det.update_params(contamination=-5.0)
        assert det.contamination == 0.001

    def test_contamination_clamped_to_max(self):
        det = self._make_detector()
        det.update_params(contamination=0.99)
        assert det.contamination == 0.5

    def test_min_samples_clamped_to_min(self):
        det = self._make_detector()
        det.update_params(min_samples=0)
        assert det.min_samples == 10

    def test_retrain_sec_clamped_to_min(self):
        det = self._make_detector()
        det.update_params(retrain_interval_sec=0)
        assert det.retrain_sec == 60

    def test_none_values_not_applied(self):
        det = self._make_detector()
        original = det.contamination
        det.update_params(contamination=None)
        assert det.contamination == original

    def test_status_reflects_updated_params(self):
        det = self._make_detector()
        det.update_params(contamination=0.15, threshold=-0.2)
        status = det.status()
        assert status["contamination"] == 0.15
        assert status["threshold"] == -0.2

class TestMLDetectorTriggerRetrain:
    """trigger_retrain() returns correct ok/fail status."""

    def _make_detector(self, min_samples=100):
        from cnsl.ml_detector import MLDetector
        from cnsl.logger import JsonLogger
        cfg = {"ml": {"enabled": True, "min_samples": min_samples,
                      "contamination": 0.05, "anomaly_score_threshold": -0.1}}
        return MLDetector(cfg, JsonLogger("/dev/null", verbose=False))

    def test_trigger_retrain_disabled_returns_false(self):
        from cnsl.ml_detector import MLDetector
        from cnsl.logger import JsonLogger
        det = MLDetector({"ml": {"enabled": False}}, JsonLogger("/dev/null", verbose=False))
        result = _run(det.trigger_retrain())
        assert result["ok"] is False
        assert "enabled" in result["reason"]

    def test_trigger_retrain_insufficient_samples_returns_false(self):
        det = self._make_detector(min_samples=100)
        # No training data accumulated
        result = _run(det.trigger_retrain())
        assert result["ok"] is False
        assert "samples" in result["reason"].lower()

class TestMLStatusIncludesNewFields:
    """status() returns the new fields added for the tuning UI."""

    def test_status_has_contamination(self):
        from cnsl.ml_detector import MLDetector
        from cnsl.logger import JsonLogger
        cfg = {"ml": {"enabled": True, "contamination": 0.07}}
        det = MLDetector(cfg, JsonLogger("/dev/null", verbose=False))
        s   = det.status()
        assert "contamination" in s
        assert s["contamination"] == 0.07

    def test_status_has_threshold(self):
        from cnsl.ml_detector import MLDetector
        from cnsl.logger import JsonLogger
        cfg = {"ml": {"enabled": True, "anomaly_score_threshold": -0.15}}
        det = MLDetector(cfg, JsonLogger("/dev/null", verbose=False))
        assert det.status()["threshold"] == -0.15

    def test_status_has_recent_alert_count(self):
        from cnsl.ml_detector import MLDetector
        from cnsl.logger import JsonLogger
        det = MLDetector({"ml": {"enabled": True}}, JsonLogger("/dev/null", verbose=False))
        assert "recent_alert_count" in det.status()
        assert det.status()["recent_alert_count"] == 0

    def test_status_has_retrain_interval_sec(self):
        from cnsl.ml_detector import MLDetector
        from cnsl.logger import JsonLogger
        cfg = {"ml": {"enabled": True, "retrain_interval_sec": 7200}}
        det = MLDetector(cfg, JsonLogger("/dev/null", verbose=False))
        assert det.status()["retrain_interval_sec"] == 7200

class TestMLAPIRoutes:
    """New ML API routes present in dashboard source."""

    def _src(self):
        from pathlib import Path
        root = Path(__file__).parent.parent / "cnsl"
        # Routes are in dashboard.py; JS functions moved with HTML to dashboard_html.py
        return (
            (root / "dashboard.py").read_text(encoding="utf-8") +
            (root / "dashboard_html.py").read_text(encoding="utf-8")
        )

    def test_params_patch_route(self):
        assert '"/api/ml/params"' in self._src()

    def test_retrain_post_route(self):
        assert '"/api/ml/retrain"' in self._src()

    def test_alerts_get_route(self):
        assert '"/api/ml/alerts"' in self._src()

    def test_feature_stats_route(self):
        assert '"/api/ml/feature-stats"' in self._src()

    def test_ml_save_params_js(self):
        assert "async function mlSaveParams()" in self._src()

    def test_ml_trigger_retrain_js(self):
        assert "async function mlTriggerRetrain()" in self._src()

# v3.0.0 -- OT/IoT protocol support

class TestPatternFingerprint:
    """Pattern fingerprinting and ID generation."""

    def test_fingerprint_sorted_and_deduped(self):
        from cnsl.pattern_learner import _fingerprint
        key, kinds = _fingerprint([("SSH_FAIL", "auth"), ("WEB_SCAN", "nginx"),
                                    ("SSH_FAIL", "auth")])
        assert kinds == ["SSH_FAIL", "WEB_SCAN"]
        assert key == "SSH_FAIL+WEB_SCAN"

    def test_empty_pairs_returns_empty(self):
        from cnsl.pattern_learner import _fingerprint
        key, kinds = _fingerprint([])
        assert key == ""
        assert kinds == []

    def test_same_kinds_different_order_same_fingerprint(self):
        from cnsl.pattern_learner import _fingerprint
        key1, _ = _fingerprint([("A", "x"), ("B", "y")])
        key2, _ = _fingerprint([("B", "y"), ("A", "x")])
        assert key1 == key2

    def test_make_id_deterministic(self):
        from cnsl.pattern_learner import _make_id
        assert _make_id("SSH_FAIL+WEB_SCAN") == _make_id("SSH_FAIL+WEB_SCAN")

    def test_make_id_differs_for_different_patterns(self):
        from cnsl.pattern_learner import _make_id
        assert _make_id("A+B") != _make_id("C+D")

class TestPatternLearnerObservation:
    """Event observation and buffer management."""

    def _make_learner(self, cfg=None):
        from cnsl.pattern_learner import PatternLearner
        return PatternLearner(cfg or {"pattern_learning": {
            "enabled": True, "lookback_sec": 300, "min_occurrences": 3,
        }})

    def _make_event(self, ip, kind, source="auth"):
        from cnsl.models import Event, now
        return Event(ts=now(), source=source, kind=kind, src_ip=ip, user=None,
                     raw=f"test event {kind} from {ip}")

    def test_observe_event_populates_buffer(self):
        pl = self._make_learner()
        pl.observe_event(self._make_event("1.2.3.4", "SSH_FAIL"))
        buf = pl._buffers.get("1.2.3.4")
        assert buf is not None
        assert len(buf.snapshot()) == 1

    def test_disabled_learner_ignores_events(self):
        pl = self._make_learner({"pattern_learning": {"enabled": False}})
        pl.observe_event(self._make_event("1.2.3.4", "SSH_FAIL"))
        assert "1.2.3.4" not in pl._buffers

    def test_event_without_ip_ignored(self):
        from cnsl.models import Event, now
        pl = self._make_learner()
        ev = Event(ts=now(), source="auth", kind="SSH_FAIL", src_ip=None,
                   user=None, raw="no ip")
        pl.observe_event(ev)
        assert len(pl._buffers) == 0

class TestPatternLearnerSuggestions:
    """Suggestion generation, promote, and dismiss."""

    def _make_learner(self, min_occurrences=3):
        from cnsl.pattern_learner import PatternLearner
        return PatternLearner({"pattern_learning": {
            "enabled": True, "lookback_sec": 300,
            "min_occurrences": min_occurrences,
        }})

    def _observe_and_alert(self, pl, ip, kinds):
        from cnsl.models import Event, now
        for kind in kinds:
            pl.observe_event(Event(ts=now(), source="test", kind=kind,
                                    src_ip=ip, user=None, raw=f"{kind} from {ip}"))
        return pl.on_alert(ip, "test_rule")

    def test_no_suggestion_below_min_occurrences(self):
        pl = self._make_learner(min_occurrences=5)
        for i in range(3):
            self._observe_and_alert(pl, f"1.2.3.{i}", ["SSH_FAIL", "WEB_SCAN"])
        assert len(pl.get_suggestions()) == 0

    def test_suggestion_created_at_min_occurrences(self):
        pl = self._make_learner(min_occurrences=3)
        result = None
        for i in range(3):
            result = self._observe_and_alert(pl, f"1.2.3.{i}", ["SSH_FAIL", "WEB_SCAN"])
        assert len(pl.get_suggestions()) == 1
        assert result is not None
        assert "SSH_FAIL" in result.event_kinds

    def test_suggestion_tracks_example_ips(self):
        pl = self._make_learner(min_occurrences=2)
        self._observe_and_alert(pl, "1.1.1.1", ["SSH_FAIL", "WEB_SCAN"])
        self._observe_and_alert(pl, "2.2.2.2", ["SSH_FAIL", "WEB_SCAN"])
        # Suggestion is born on the 2nd occurrence, so only the IP that
        # triggered creation is recorded at this point.
        suggestions = pl.get_suggestions()
        assert len(suggestions) == 1
        assert "2.2.2.2" in suggestions[0].example_ips
        # A subsequent occurrence of the same pattern adds its IP too.
        self._observe_and_alert(pl, "3.3.3.3", ["SSH_FAIL", "WEB_SCAN"])
        updated = pl.get_suggestion(suggestions[0].id)
        assert "3.3.3.3" in updated.example_ips

    def test_dismiss_suppresses_future_suggestions(self):
        pl = self._make_learner(min_occurrences=2)
        self._observe_and_alert(pl, "1.1.1.1", ["SSH_FAIL", "WEB_SCAN"])
        self._observe_and_alert(pl, "2.2.2.2", ["SSH_FAIL", "WEB_SCAN"])
        sugg = pl.get_suggestions()[0]
        assert pl.dismiss(sugg.id) is True
        assert sugg.pattern_key in pl._dismissed
        # New occurrences of the same pattern should not resurrect it
        self._observe_and_alert(pl, "3.3.3.3", ["SSH_FAIL", "WEB_SCAN"])
        active = pl.get_suggestions()
        assert len(active) == 0

    def test_mark_promoted_sets_flag(self):
        pl = self._make_learner(min_occurrences=2)
        self._observe_and_alert(pl, "1.1.1.1", ["SSH_FAIL", "WEB_SCAN"])
        self._observe_and_alert(pl, "2.2.2.2", ["SSH_FAIL", "WEB_SCAN"])
        sugg = pl.get_suggestions()[0]
        assert pl.mark_promoted(sugg.id) is True
        assert sugg.promoted is True
        # Promoted suggestions excluded from default get_suggestions()
        assert len(pl.get_suggestions()) == 0

    def test_dismiss_unknown_id_returns_false(self):
        pl = self._make_learner()
        assert pl.dismiss("nonexistent") is False

    def test_stats_reports_counts(self):
        pl = self._make_learner(min_occurrences=2)
        self._observe_and_alert(pl, "1.1.1.1", ["SSH_FAIL", "WEB_SCAN"])
        self._observe_and_alert(pl, "2.2.2.2", ["SSH_FAIL", "WEB_SCAN"])
        stats = pl.stats()
        assert stats["active_suggestions"] == 1
        assert stats["patterns_tracked"] >= 1


# v2.4.0 -- SIEM/SOAR connectors
