"""
tests/test_attack.py -- MITRE ATT&CK technique reference and coverage
mapping (cnsl/attack.py), plus drift guards ensuring every technique
ID referenced elsewhere (rules.py, correlator.py) actually exists in
attack.py's TECHNIQUES table.

Run:
    pytest tests/test_attack.py -v
"""

from __future__ import annotations

from cnsl.attack import (
    TECHNIQUES,
    KC_STAGE_TO_TACTIC,
    Tactic,
    build_coverage_report,
    sigma_tags_to_technique_ids,
    tactic_name,
    technique_info,
    technique_url,
)


class TestTechniqueInfo:
    def test_known_technique_returns_full_info(self):
        info = technique_info("T1110.001")
        assert info["id"] == "T1110.001"
        assert info["name"] == "Brute Force: Password Guessing"
        assert info["tactic_id"] == Tactic.CREDENTIAL_ACCESS
        assert info["tactic_name"] == "Credential Access"
        assert info["url"] == "https://attack.mitre.org/techniques/T1110/001/"

    def test_unknown_technique_returns_none(self):
        assert technique_info("T9999.999") is None

    def test_sub_technique_url_uses_slash_not_dot(self):
        assert technique_url("T1078.004") == "https://attack.mitre.org/techniques/T1078/004/"

    def test_top_level_technique_url(self):
        assert technique_url("T1190") == "https://attack.mitre.org/techniques/T1190/"


class TestTacticName:
    def test_known_tactic(self):
        assert tactic_name(Tactic.CREDENTIAL_ACCESS) == "Credential Access"

    def test_unknown_tactic_falls_back_to_id(self):
        assert tactic_name("TA9999") == "TA9999"


class TestSigmaTagExtraction:
    def test_extracts_attack_tags(self):
        tags = ["attack.t1110", "attack.t1078.003", "attack.initial_access"]
        # "attack.initial_access" is a tactic-name tag (no digits) --
        # not a technique id, must not be extracted as one.
        ids = sigma_tags_to_technique_ids(tags)
        assert ids == ["T1110", "T1078.003"]

    def test_case_insensitive(self):
        assert sigma_tags_to_technique_ids(["ATTACK.T1110"]) == ["T1110"]

    def test_ignores_unrelated_tags(self):
        assert sigma_tags_to_technique_ids(["car.2020.exploit", "cve.2021.1234"]) == []

    def test_empty_list(self):
        assert sigma_tags_to_technique_ids([]) == []


class TestCoverageReport:
    def test_empty_report(self):
        report = build_coverage_report()
        assert report["technique_count"] == 0
        assert report["techniques"] == []
        assert report["by_tactic"] == {}

    def test_builtin_rule_contributes(self):
        report = build_coverage_report(builtin_rules=[
            {"id": "ssh.brute_force", "enabled": True, "attack_techniques": ["T1110.001"]},
        ])
        assert report["technique_count"] == 1
        t = report["techniques"][0]
        assert t["id"] == "T1110.001"
        assert t["sources"] == [{"kind": "rule", "id": "ssh.brute_force"}]

    def test_disabled_rule_does_not_contribute(self):
        report = build_coverage_report(builtin_rules=[
            {"id": "ssh.brute_force", "enabled": False, "attack_techniques": ["T1110.001"]},
        ])
        assert report["technique_count"] == 0

    def test_correlation_rule_contributes(self):
        report = build_coverage_report(correlation_rules=[
            {"name": "web_recon_then_ssh", "enabled": True, "attack_techniques": ["T1595"]},
        ])
        assert report["technique_count"] == 1
        assert report["techniques"][0]["sources"] == [{"kind": "correlation", "id": "web_recon_then_ssh"}]

    def test_sigma_rule_contributes_via_tags(self):
        report = build_coverage_report(sigma_rules=[
            {"id": "sig1", "enabled": True, "tags": ["attack.t1190"]},
        ])
        assert report["technique_count"] == 1
        assert report["techniques"][0]["sources"] == [{"kind": "sigma", "id": "sig1"}]

    def test_disabled_sigma_rule_does_not_contribute(self):
        report = build_coverage_report(sigma_rules=[
            {"id": "sig1", "enabled": False, "tags": ["attack.t1190"]},
        ])
        assert report["technique_count"] == 0

    def test_same_technique_from_multiple_sources_merges_with_both_listed(self):
        report = build_coverage_report(
            builtin_rules=[{"id": "ssh.brute_force", "enabled": True, "attack_techniques": ["T1110"]}],
            sigma_rules=[{"id": "sig1", "enabled": True, "tags": ["attack.t1110"]}],
        )
        assert report["technique_count"] == 1
        sources = report["techniques"][0]["sources"]
        assert {"kind": "rule", "id": "ssh.brute_force"} in sources
        assert {"kind": "sigma", "id": "sig1"} in sources

    def test_by_tactic_groups_correctly(self):
        report = build_coverage_report(builtin_rules=[
            {"id": "a", "enabled": True, "attack_techniques": ["T1595"]},   # Reconnaissance
            {"id": "b", "enabled": True, "attack_techniques": ["T1110"]},   # Credential Access
        ])
        assert report["by_tactic"]["Reconnaissance"] == ["T1595"]
        assert report["by_tactic"]["Credential Access"] == ["T1110"]

    def test_unrecognized_technique_id_still_recorded_with_null_metadata(self):
        # A rule could reference an id not in the curated TECHNIQUES
        # table (e.g. a Sigma rule tagging a technique CNSL hasn't
        # curated yet) -- coverage should still count it, just without
        # a name/tactic, rather than silently dropping it.
        report = build_coverage_report(sigma_rules=[
            {"id": "sig1", "enabled": True, "tags": ["attack.t9999.999"]},
        ])
        assert report["technique_count"] == 1
        t = report["techniques"][0]
        assert t["id"] == "T9999.999"
        assert t["name"] is None
        assert t["tactic_id"] is None


class TestDriftGuards:
    """
    Every technique ID referenced by a built-in rule (rules.py) or a
    correlation rule (correlator.py) must exist in attack.py's
    TECHNIQUES table -- otherwise the coverage report would silently
    show it with null name/tactic (see
    test_unrecognized_technique_id_still_recorded_with_null_metadata
    above, which is the correct behavior for genuinely-external ids,
    but not for CNSL's own rules referencing a typo'd id).
    """

    def test_every_builtin_rule_technique_id_is_known(self):
        from cnsl.rules import RuleEngine
        engine = RuleEngine({})
        unknown = [
            (r["id"], tid)
            for r in engine.all_rules()
            for tid in r.get("attack_techniques", [])
            if tid not in TECHNIQUES
        ]
        assert unknown == [], f"Unknown ATT&CK technique id(s) referenced: {unknown}"

    def test_every_correlation_rule_technique_id_is_known(self):
        from cnsl.correlator import _DEFAULT_RULE_CLASSES
        unknown = [
            (cls().name, tid)
            for cls in _DEFAULT_RULE_CLASSES
            for tid in cls().attack_techniques
            if tid not in TECHNIQUES
        ]
        assert unknown == [], f"Unknown ATT&CK technique id(s) referenced: {unknown}"

    def test_every_kc_stage_tactic_is_known(self):
        from cnsl.kill_chain import STAGE_NAMES
        for stage in STAGE_NAMES:
            # Not every stage needs a tactic mapping (KC_STAGE_TO_TACTIC
            # covers all 7 today, but this guards against a future stage
            # being added without a corresponding tactic entry going
            # unnoticed) -- if present, it must resolve to a real tactic name.
            tid = KC_STAGE_TO_TACTIC.get(stage)
            if tid is not None:
                assert tactic_name(tid) != tid, f"Stage {stage}'s tactic id {tid} has no name mapping"


class TestKillChainIntegration:
    def test_stage_record_to_dict_includes_tactic(self):
        from cnsl.kill_chain import StageRecord, KCStage
        sr = StageRecord(stage=KCStage.RECONNAISSANCE, first_seen=100.0, last_seen=100.0, count=1, event_kinds=["WEB_SCAN"])
        d = sr.to_dict()
        assert d["attack_tactic_id"] == Tactic.RECONNAISSANCE
        assert d["attack_tactic_name"] == "Reconnaissance"

    def test_sigma_match_stage_maps_to_exploitation_tactic(self):
        from cnsl.kill_chain import StageRecord, KCStage
        sr = StageRecord(stage=KCStage.EXPLOITATION, first_seen=100.0, last_seen=100.0, count=1, event_kinds=["SIGMA_MATCH"])
        d = sr.to_dict()
        assert d["attack_tactic_name"] == "Execution"


class TestAttackDashboardWiring:
    async def _client(self, detector=None, correlator=None, sigma=None):
        from aiohttp import web
        from aiohttp.test_utils import TestClient, TestServer
        from cnsl.dashboard_attack import register_attack_routes

        def _require_auth(req):
            return {"sub": "admin", "role": "admin"}, None
        def _rate_check(req):
            return None

        router = web.RouteTableDef()
        register_attack_routes(router, detector, correlator, sigma, _require_auth, _rate_check)
        app = web.Application()
        app.add_routes(router)
        client = TestClient(TestServer(app))
        await client.start_server()
        return client

    def test_coverage_endpoint_aggregates_all_sources(self):
        import asyncio
        from unittest.mock import MagicMock

        async def go():
            detector = MagicMock()
            detector.rules.all_rules.return_value = [
                {"id": "ssh.brute_force", "enabled": True, "attack_techniques": ["T1110.001"]},
            ]
            correlator = MagicMock()
            correlator.all_rules.return_value = [
                {"name": "web_recon_then_ssh", "enabled": True, "attack_techniques": ["T1595"]},
            ]
            sigma = MagicMock()
            sigma.all_rules.return_value = [
                {"id": "sig1", "enabled": True, "tags": ["attack.t1190"]},
            ]
            client = await self._client(detector, correlator, sigma)
            r = await client.get("/api/attack/coverage")
            data = await r.json()
            assert r.status == 200
            assert data["technique_count"] == 3
            ids = {t["id"] for t in data["techniques"]}
            assert ids == {"T1110.001", "T1595", "T1190"}
            await client.close()
        asyncio.run(go())

    def test_coverage_endpoint_handles_missing_sources_gracefully(self):
        import asyncio

        async def go():
            client = await self._client(detector=None, correlator=None, sigma=None)
            r = await client.get("/api/attack/coverage")
            data = await r.json()
            assert r.status == 200
            assert data["technique_count"] == 0
            await client.close()
        asyncio.run(go())