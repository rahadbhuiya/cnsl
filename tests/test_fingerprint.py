"""
tests/test_fingerprint.py -- tests for attacker fingerprinting and
cross-IP actor clustering (cnsl/fingerprint.py) and its dashboard
wiring (cnsl/dashboard_fingerprint.py).
"""

from __future__ import annotations

import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock

from cnsl.fingerprint import (
    build_fingerprint,
    build_fingerprints,
    similarity,
    find_similar,
    cluster_attackers,
    AttackerFingerprint,
    MIN_INCIDENTS_FOR_FINGERPRINT,
)


def _run(coro):
    return asyncio.run(coro)


def _bot_incidents(ip, base_ts=1700000000.0, count=6, interval=30,
                     kind="SSH_FAIL", severity="MEDIUM",
                     reason="brute_force: 5 fails in 60s", uniq_users=1):
    return [
        {"src_ip": ip, "ts": base_ts + i * interval, "kind": kind,
         "severity": severity, "reasons": [reason], "uniq_users": uniq_users}
        for i in range(count)
    ]


class TestBuildFingerprint:
    def test_returns_none_below_minimum_incidents(self):
        incidents = _bot_incidents("1.1.1.1", count=MIN_INCIDENTS_FOR_FINGERPRINT - 1)
        assert build_fingerprint("1.1.1.1", incidents) is None

    def test_returns_fingerprint_at_minimum_incidents(self):
        incidents = _bot_incidents("1.1.1.1", count=MIN_INCIDENTS_FOR_FINGERPRINT)
        fp = build_fingerprint("1.1.1.1", incidents)
        assert fp is not None
        assert fp.incident_count == MIN_INCIDENTS_FOR_FINGERPRINT

    def test_kind_ratios_sum_to_approximately_one(self):
        incidents = _bot_incidents("1.1.1.1")
        fp = build_fingerprint("1.1.1.1", incidents)
        assert abs(sum(fp.kind_ratios) - 1.0) < 1e-9

    def test_pure_ssh_fail_ratio_is_one(self):
        incidents = _bot_incidents("1.1.1.1", kind="SSH_FAIL")
        fp = build_fingerprint("1.1.1.1", incidents)
        d = fp.to_dict()
        assert d["kind_ratios"]["SSH_FAIL"] == 1.0

    def test_unknown_kind_folds_into_other(self):
        incidents = _bot_incidents("1.1.1.1", kind="SOME_FUTURE_KIND")
        fp = build_fingerprint("1.1.1.1", incidents)
        d = fp.to_dict()
        assert d["kind_ratios"]["other"] == 1.0

    def test_regular_interval_gives_low_cv(self):
        incidents = _bot_incidents("1.1.1.1", interval=30)
        fp = build_fingerprint("1.1.1.1", incidents)
        assert fp.mean_interval_sec == pytest.approx(30.0)
        assert fp.interval_cv == pytest.approx(0.0, abs=1e-9)

    def test_irregular_interval_gives_higher_cv(self):
        incidents = [
            {"src_ip": "1.1.1.1", "ts": ts, "kind": "SSH_FAIL", "severity": "MEDIUM",
             "reasons": ["brute_force: x"], "uniq_users": 1}
            for ts in [1000.0, 1005.0, 1400.0, 1401.0, 3000.0]
        ]
        fp = build_fingerprint("1.1.1.1", incidents)
        assert fp.interval_cv > 0.3

    def test_single_incident_after_dedupe_has_zero_interval_stats(self):
        """All incidents at the same timestamp -> no positive intervals."""
        incidents = [
            {"src_ip": "1.1.1.1", "ts": 1000.0, "kind": "SSH_FAIL", "severity": "LOW",
             "reasons": ["x"], "uniq_users": 0}
            for _ in range(3)
        ]
        fp = build_fingerprint("1.1.1.1", incidents)
        assert fp.mean_interval_sec == 0.0
        assert fp.interval_cv == 0.0

    def test_severity_weight_averaging(self):
        incidents = _bot_incidents("1.1.1.1", severity="HIGH")
        fp = build_fingerprint("1.1.1.1", incidents)
        assert fp.avg_severity == pytest.approx(1.0)

    def test_reason_keywords_extracted(self):
        incidents = _bot_incidents("1.1.1.1", reason="credential_stuffing: many users")
        fp = build_fingerprint("1.1.1.1", incidents)
        assert "credential_stuffing" in fp.reason_keywords

    def test_reason_keywords_deduplicated_across_incidents(self):
        incidents = _bot_incidents("1.1.1.1", reason="brute_force: attempt")
        fp = build_fingerprint("1.1.1.1", incidents)
        assert fp.reason_keywords == frozenset({"brute_force"})

    def test_multiple_distinct_reasons_all_captured(self):
        incidents = _bot_incidents("1.1.1.1", count=3, reason="brute_force: x")
        incidents += _bot_incidents("1.1.1.1", count=3, base_ts=2000.0, reason="scanner: y")
        fp = build_fingerprint("1.1.1.1", incidents)
        assert fp.reason_keywords == frozenset({"brute_force", "scanner"})

    def test_avg_uniq_users(self):
        incidents = _bot_incidents("1.1.1.1", uniq_users=4)
        fp = build_fingerprint("1.1.1.1", incidents)
        assert fp.avg_uniq_users == pytest.approx(4.0)

    def test_first_and_last_seen(self):
        incidents = _bot_incidents("1.1.1.1", base_ts=1000.0, count=4, interval=100)
        fp = build_fingerprint("1.1.1.1", incidents)
        assert fp.first_seen == 1000.0
        assert fp.last_seen == 1300.0

    def test_to_dict_shape(self):
        incidents = _bot_incidents("1.1.1.1")
        fp = build_fingerprint("1.1.1.1", incidents)
        d = fp.to_dict()
        assert set(d.keys()) == {
            "ip", "incident_count", "first_seen", "last_seen", "kind_ratios",
            "mean_interval_sec", "interval_cv", "avg_severity",
            "reason_keywords", "avg_uniq_users",
        }


class TestBuildFingerprints:
    def test_groups_by_ip(self):
        incidents = _bot_incidents("1.1.1.1") + _bot_incidents("2.2.2.2")
        fps = build_fingerprints(incidents)
        assert set(fps.keys()) == {"1.1.1.1", "2.2.2.2"}

    def test_omits_ips_below_minimum(self):
        incidents = _bot_incidents("1.1.1.1", count=1)
        fps = build_fingerprints(incidents)
        assert "1.1.1.1" not in fps

    def test_ignores_rows_without_src_ip(self):
        incidents = _bot_incidents("1.1.1.1")
        incidents.append({"ts": 5000.0, "kind": "SSH_FAIL", "severity": "LOW",
                            "reasons": [], "uniq_users": 0})  # no src_ip
        fps = build_fingerprints(incidents)
        assert set(fps.keys()) == {"1.1.1.1"}

    def test_empty_input_gives_empty_result(self):
        assert build_fingerprints([]) == {}


class TestSimilarity:
    def test_identical_behavior_scores_near_one(self):
        fp1 = build_fingerprint("1.1.1.1", _bot_incidents("1.1.1.1", base_ts=1000.0))
        fp2 = build_fingerprint("2.2.2.2", _bot_incidents("2.2.2.2", base_ts=999999.0))
        assert similarity(fp1, fp2) == pytest.approx(1.0, abs=1e-6)

    def test_different_kind_and_reason_scores_low(self):
        fp1 = build_fingerprint("1.1.1.1", _bot_incidents(
            "1.1.1.1", kind="SSH_FAIL", reason="brute_force: x", interval=30))
        fp2 = build_fingerprint("2.2.2.2", _bot_incidents(
            "2.2.2.2", kind="WEB_SCAN", reason="scanner: y", interval=3600, severity="LOW"))
        assert similarity(fp1, fp2) < 0.4

    def test_similarity_is_symmetric(self):
        fp1 = build_fingerprint("1.1.1.1", _bot_incidents("1.1.1.1"))
        fp2 = build_fingerprint("2.2.2.2", _bot_incidents(
            "2.2.2.2", kind="WEB_SCAN", reason="scanner: y"))
        assert similarity(fp1, fp2) == pytest.approx(similarity(fp2, fp1))

    def test_self_similarity_is_one(self):
        fp1 = build_fingerprint("1.1.1.1", _bot_incidents("1.1.1.1"))
        assert similarity(fp1, fp1) == pytest.approx(1.0)

    def test_no_keywords_both_sides_treated_as_matching(self):
        incidents_a = [{"src_ip": "1.1.1.1", "ts": 1000.0 + i * 30, "kind": "SSH_FAIL",
                         "severity": "LOW", "reasons": [], "uniq_users": 0} for i in range(4)]
        incidents_b = [{"src_ip": "2.2.2.2", "ts": 2000.0 + i * 30, "kind": "SSH_FAIL",
                         "severity": "LOW", "reasons": [], "uniq_users": 0} for i in range(4)]
        fp1 = build_fingerprint("1.1.1.1", incidents_a)
        fp2 = build_fingerprint("2.2.2.2", incidents_b)
        assert similarity(fp1, fp2) == pytest.approx(1.0)


class TestFindSimilar:
    def test_finds_matching_ip_above_threshold(self):
        fps = build_fingerprints(
            _bot_incidents("1.1.1.1", base_ts=1000.0) +
            _bot_incidents("2.2.2.2", base_ts=999999.0)
        )
        result = find_similar("1.1.1.1", fps, threshold=0.9)
        assert len(result) == 1
        assert result[0][0] == "2.2.2.2"
        assert result[0][1] == pytest.approx(1.0)

    def test_excludes_dissimilar_ip(self):
        fps = build_fingerprints(
            _bot_incidents("1.1.1.1", kind="SSH_FAIL", reason="brute_force: x") +
            _bot_incidents("2.2.2.2", kind="WEB_SCAN", reason="scanner: y",
                            interval=3600, severity="LOW")
        )
        result = find_similar("1.1.1.1", fps, threshold=0.75)
        assert result == []

    def test_unknown_ip_returns_empty(self):
        fps = build_fingerprints(_bot_incidents("1.1.1.1"))
        assert find_similar("9.9.9.9", fps) == []

    def test_excludes_self(self):
        fps = build_fingerprints(_bot_incidents("1.1.1.1"))
        result = find_similar("1.1.1.1", fps, threshold=0.0)
        assert all(ip != "1.1.1.1" for ip, _ in result)

    def test_sorted_descending_by_score(self):
        fps = build_fingerprints(
            _bot_incidents("1.1.1.1", base_ts=1000.0) +
            _bot_incidents("2.2.2.2", base_ts=50000.0) +
            _bot_incidents("3.3.3.3", base_ts=100000.0, interval=45)  # slightly less similar
        )
        result = find_similar("1.1.1.1", fps, threshold=0.0)
        scores = [s for _, s in result]
        assert scores == sorted(scores, reverse=True)

    def test_limit_respected(self):
        incidents = []
        for i in range(10):
            incidents += _bot_incidents(f"10.0.0.{i}", base_ts=1000.0 + i)
        fps = build_fingerprints(incidents)
        result = find_similar("10.0.0.0", fps, threshold=0.0, limit=3)
        assert len(result) <= 3


class TestClusterAttackers:
    def test_two_similar_ips_form_one_cluster(self):
        fps = build_fingerprints(
            _bot_incidents("1.1.1.1", base_ts=1000.0) +
            _bot_incidents("2.2.2.2", base_ts=999999.0)
        )
        clusters = cluster_attackers(fps, threshold=0.9)
        assert len(clusters) == 1
        assert set(clusters[0]) == {"1.1.1.1", "2.2.2.2"}

    def test_dissimilar_ips_form_no_cluster(self):
        fps = build_fingerprints(
            _bot_incidents("1.1.1.1", kind="SSH_FAIL", reason="brute_force: x") +
            _bot_incidents("2.2.2.2", kind="WEB_SCAN", reason="scanner: y",
                            interval=3600, severity="LOW")
        )
        clusters = cluster_attackers(fps, threshold=0.9)
        assert clusters == []

    def test_single_fingerprint_never_forms_a_cluster(self):
        fps = build_fingerprints(_bot_incidents("1.1.1.1"))
        assert cluster_attackers(fps, threshold=0.5) == []

    def test_transitive_clustering_via_union_find(self):
        """A similar to B, B similar to C (even if A-C alone might be
        borderline) should still land in one cluster via transitivity."""
        fps = build_fingerprints(
            _bot_incidents("1.1.1.1", base_ts=1000.0) +
            _bot_incidents("2.2.2.2", base_ts=50000.0) +
            _bot_incidents("3.3.3.3", base_ts=100000.0)
        )
        clusters = cluster_attackers(fps, threshold=0.9)
        assert len(clusters) == 1
        assert set(clusters[0]) == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}

    def test_two_separate_clusters(self):
        fps = build_fingerprints(
            _bot_incidents("1.1.1.1", kind="SSH_FAIL", reason="brute_force: x", base_ts=1000.0) +
            _bot_incidents("2.2.2.2", kind="SSH_FAIL", reason="brute_force: x", base_ts=50000.0) +
            _bot_incidents("3.3.3.3", kind="WEB_SCAN", reason="scanner: y",
                            interval=3600, severity="LOW", base_ts=1000.0) +
            _bot_incidents("4.4.4.4", kind="WEB_SCAN", reason="scanner: y",
                            interval=3600, severity="LOW", base_ts=50000.0)
        )
        clusters = cluster_attackers(fps, threshold=0.85)
        assert len(clusters) == 2
        cluster_sets = [set(c) for c in clusters]
        assert {"1.1.1.1", "2.2.2.2"} in cluster_sets
        assert {"3.3.3.3", "4.4.4.4"} in cluster_sets

    def test_clusters_sorted_by_size_descending(self):
        incidents = []
        for i in range(4):
            incidents += _bot_incidents(f"10.0.0.{i}", base_ts=1000.0 + i * 10)
        incidents += _bot_incidents("2.2.2.2", kind="WEB_SCAN", reason="scanner: y",
                                     interval=3600, severity="LOW", base_ts=1000.0)
        incidents += _bot_incidents("3.3.3.3", kind="WEB_SCAN", reason="scanner: y",
                                     interval=3600, severity="LOW", base_ts=50000.0)
        fps = build_fingerprints(incidents)
        clusters = cluster_attackers(fps, threshold=0.85)
        sizes = [len(c) for c in clusters]
        assert sizes == sorted(sizes, reverse=True)

    def test_empty_fingerprints_gives_no_clusters(self):
        assert cluster_attackers({}, threshold=0.8) == []


class TestFingerprintDashboardWiring:
    def _make_store(self, incidents=None):
        store = MagicMock()
        store.available = True
        store.recent_incidents = AsyncMock(return_value=incidents or [])
        return store

    async def _client(self, store):
        from aiohttp import web
        from aiohttp.test_utils import TestClient, TestServer
        from cnsl.dashboard_fingerprint import register_fingerprint_routes

        def _require_auth(req):
            return {"sub": "admin", "role": "admin"}, None
        def _rate_check(req):
            return None

        router = web.RouteTableDef()
        register_fingerprint_routes(router, store, _require_auth, _rate_check)
        app = web.Application()
        app.add_routes(router)
        client = TestClient(TestServer(app))
        await client.start_server()
        return client

    def test_clusters_endpoint_returns_matching_cluster(self):
        async def go():
            incidents = (_bot_incidents("1.1.1.1", base_ts=1000.0) +
                         _bot_incidents("2.2.2.2", base_ts=999999.0))
            client = await self._client(self._make_store(incidents))
            r = await client.get("/api/fingerprint/clusters")
            data = await r.json()
            assert r.status == 200
            assert data["total_clusters"] == 1
            assert set(data["clusters"][0]["ips"]) == {"1.1.1.1", "2.2.2.2"}
            await client.close()
        _run(go())

    def test_clusters_endpoint_empty_store(self):
        async def go():
            store = MagicMock()
            store.available = False
            client = await self._client(store)
            r = await client.get("/api/fingerprint/clusters")
            data = await r.json()
            assert r.status == 200
            assert data["total_clusters"] == 0
            await client.close()
        _run(go())

    def test_clusters_endpoint_threshold_param(self):
        async def go():
            incidents = (_bot_incidents("1.1.1.1", base_ts=1000.0) +
                         _bot_incidents("2.2.2.2", base_ts=999999.0))
            client = await self._client(self._make_store(incidents))
            r = await client.get("/api/fingerprint/clusters?threshold=1.5")
            data = await r.json()
            assert data["threshold"] == 1.0  # clamped
            await client.close()
        _run(go())

    def test_similar_endpoint_returns_matches(self):
        async def go():
            incidents = (_bot_incidents("1.1.1.1", base_ts=1000.0) +
                         _bot_incidents("2.2.2.2", base_ts=999999.0))
            client = await self._client(self._make_store(incidents))
            r = await client.get("/api/fingerprint/similar/1.1.1.1")
            data = await r.json()
            assert r.status == 200
            assert data["similar"][0]["ip"] == "2.2.2.2"
            await client.close()
        _run(go())

    def test_similar_endpoint_404_for_unfingerprinted_ip(self):
        async def go():
            client = await self._client(self._make_store([]))
            r = await client.get("/api/fingerprint/similar/9.9.9.9")
            assert r.status == 404
            data = await r.json()
            assert "error" in data
            await client.close()
        _run(go())

    def test_incident_limit_param_passed_to_store(self):
        async def go():
            store = self._make_store([])
            client = await self._client(store)
            await client.get("/api/fingerprint/clusters?incident_limit=500")
            store.recent_incidents.assert_called_with(limit=500)
            await client.close()
        _run(go())


class TestDashboardFingerprintModuleWiring:
    def test_register_fingerprint_routes_importable(self):
        from cnsl.dashboard_fingerprint import register_fingerprint_routes
        assert callable(register_fingerprint_routes)

    def test_routes_present_in_source(self):
        from pathlib import Path
        root = Path(__file__).parent.parent / "cnsl"
        src = (root / "dashboard.py").read_text(encoding="utf-8") + \
              (root / "dashboard_fingerprint.py").read_text(encoding="utf-8")
        assert "/api/fingerprint/clusters" in src
        assert "/api/fingerprint/similar/{ip}" in src

    def test_dashboard_py_stays_under_line_budget(self):
        from pathlib import Path
        lines = len((Path(__file__).parent.parent / "cnsl" / "dashboard.py"
                     ).read_text(encoding="utf-8").splitlines())
        assert lines < 2000