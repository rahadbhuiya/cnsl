"""
tests/test_graph_correlation.py -- tests for graph-structured attack
correlation (cnsl/graph_correlation.py) and its dashboard wiring
(cnsl/dashboard_graph_correlation.py).
"""

from __future__ import annotations

import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock

from cnsl.graph_correlation import (
    build_attack_graph,
    find_campaigns,
    explain_connection,
)


def _run(coro):
    return asyncio.run(coro)


class _FakeChain:
    def __init__(self, ip, stages):
        self.ip = ip
        self.stages = stages  # dict stage_num -> anything


def _incident(ip, reasons=None):
    return {"src_ip": ip, "reasons": reasons or []}


class TestBuildAttackGraph:
    def test_creates_ip_and_rule_nodes(self):
        incidents = [_incident("1.1.1.1", ["brute_force: x"])]
        graph = build_attack_graph(incidents)
        node_types = {n["type"] for n in graph["nodes"]}
        assert node_types == {"ip", "rule"}

    def test_ip_node_id_and_label(self):
        incidents = [_incident("1.1.1.1", ["brute_force: x"])]
        graph = build_attack_graph(incidents)
        ip_node = next(n for n in graph["nodes"] if n["type"] == "ip")
        assert ip_node["id"] == "ip:1.1.1.1"
        assert ip_node["label"] == "1.1.1.1"

    def test_rule_node_extracts_keyword(self):
        incidents = [_incident("1.1.1.1", ["sql_injection: attempted payload"])]
        graph = build_attack_graph(incidents)
        rule_node = next(n for n in graph["nodes"] if n["type"] == "rule")
        assert rule_node["label"] == "sql_injection"

    def test_edge_connects_ip_to_rule(self):
        incidents = [_incident("1.1.1.1", ["brute_force: x"])]
        graph = build_attack_graph(incidents)
        assert len(graph["edges"]) == 1
        e = graph["edges"][0]
        assert e["source"] == "ip:1.1.1.1"
        assert e["target"] == "rule:brute_force"
        assert e["type"] == "triggered"

    def test_no_duplicate_edges_for_repeated_reason(self):
        incidents = [_incident("1.1.1.1", ["brute_force: x"]),
                     _incident("1.1.1.1", ["brute_force: y"])]
        graph = build_attack_graph(incidents)
        assert len(graph["edges"]) == 1  # deduped

    def test_ignores_incidents_without_src_ip(self):
        incidents = [{"reasons": ["brute_force: x"]}]
        graph = build_attack_graph(incidents)
        assert graph["nodes"] == []
        assert graph["edges"] == []

    def test_multiple_reasons_create_multiple_rule_edges(self):
        incidents = [_incident("1.1.1.1", ["brute_force: x", "scanner: y"])]
        graph = build_attack_graph(incidents)
        rule_labels = {n["label"] for n in graph["nodes"] if n["type"] == "rule"}
        assert rule_labels == {"brute_force", "scanner"}

    def test_kill_chain_stages_add_stage_nodes(self):
        incidents = [_incident("1.1.1.1")]
        chains = [_FakeChain("1.1.1.1", {0: None, 2: None})]
        graph = build_attack_graph(incidents, kill_chains=chains)
        stage_nodes = [n for n in graph["nodes"] if n["type"] == "stage"]
        assert len(stage_nodes) == 2

    def test_kill_chain_for_ip_not_in_incidents_is_ignored(self):
        incidents = [_incident("1.1.1.1")]
        chains = [_FakeChain("9.9.9.9", {0: None})]  # different IP, not in incidents
        graph = build_attack_graph(incidents, kill_chains=chains)
        stage_nodes = [n for n in graph["nodes"] if n["type"] == "stage"]
        assert stage_nodes == []

    def test_empty_incidents_gives_empty_graph(self):
        graph = build_attack_graph([])
        assert graph == {"nodes": [], "edges": []}

    def test_stage_node_uses_stage_name_label(self):
        incidents = [_incident("1.1.1.1")]
        chains = [_FakeChain("1.1.1.1", {2: None})]
        graph = build_attack_graph(incidents, kill_chains=chains)
        stage_node = next(n for n in graph["nodes"] if n["type"] == "stage")
        assert stage_node["label"] != "2"  # resolved to a real stage name


class TestFindCampaigns:
    def test_three_ips_sharing_a_rule_form_one_campaign(self):
        incidents = [_incident(ip, ["sql_injection: x"]) for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]]
        graph = build_attack_graph(incidents)
        campaigns = find_campaigns(graph, min_ips=3)
        assert len(campaigns) == 1
        assert campaigns[0]["ips"] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        assert campaigns[0]["size"] == 3

    def test_below_min_ips_excluded(self):
        incidents = [_incident(ip, ["sql_injection: x"]) for ip in ["1.1.1.1", "2.2.2.2"]]
        graph = build_attack_graph(incidents)
        assert find_campaigns(graph, min_ips=3) == []

    def test_exactly_min_ips_included(self):
        incidents = [_incident(ip, ["sql_injection: x"]) for ip in ["1.1.1.1", "2.2.2.2"]]
        graph = build_attack_graph(incidents)
        campaigns = find_campaigns(graph, min_ips=2)
        assert len(campaigns) == 1

    def test_all_unique_rules_form_no_campaign(self):
        """Each IP has its own never-shared rule -- no real correlation."""
        incidents = [
            _incident("1.1.1.1", ["rule_a: only mine"]),
            _incident("2.2.2.2", ["rule_b: only mine"]),
            _incident("3.3.3.3", ["rule_c: only mine"]),
        ]
        graph = build_attack_graph(incidents)
        assert find_campaigns(graph, min_ips=2) == []

    def test_transitive_correlation_through_intermediate_ip(self):
        """A-B share rule X, B-C share rule Y. A and C share nothing
        directly but must still land in the same campaign via B."""
        incidents = [
            _incident("A", ["rule_x: x"]),
            _incident("B", ["rule_x: x", "rule_y: y"]),
            _incident("C", ["rule_y: y"]),
        ]
        graph = build_attack_graph(incidents)
        campaigns = find_campaigns(graph, min_ips=3)
        assert len(campaigns) == 1
        assert set(campaigns[0]["ips"]) == {"A", "B", "C"}

    def test_two_separate_campaigns(self):
        incidents = (
            [_incident(ip, ["rule_a: x"]) for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]] +
            [_incident(ip, ["rule_b: y"]) for ip in ["4.4.4.4", "5.5.5.5", "6.6.6.6"]]
        )
        graph = build_attack_graph(incidents)
        campaigns = find_campaigns(graph, min_ips=3)
        assert len(campaigns) == 2

    def test_min_shared_degree_filters_weak_bridges(self):
        """A rule shared by only 1 IP shouldn't bridge anything --
        min_shared_degree=2 (default) already enforces this; explicitly
        setting a higher bar should filter out weaker campaigns too."""
        incidents = [_incident(ip, ["rule_a: x"]) for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]]
        graph = build_attack_graph(incidents)
        # min_shared_degree=4 -> the rule node only has 3 IP neighbors, below threshold
        assert find_campaigns(graph, min_ips=2, min_shared_degree=4) == []

    def test_campaigns_sorted_by_size_descending(self):
        incidents = (
            [_incident(ip, ["rule_a: x"]) for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]] +
            [_incident(ip, ["rule_b: y"]) for ip in ["5.5.5.5", "6.6.6.6", "7.7.7.7"]]
        )
        graph = build_attack_graph(incidents)
        campaigns = find_campaigns(graph, min_ips=3)
        sizes = [c["size"] for c in campaigns]
        assert sizes == sorted(sizes, reverse=True)

    def test_campaign_includes_shared_nodes(self):
        incidents = [_incident(ip, ["sql_injection: x"]) for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]]
        graph = build_attack_graph(incidents)
        campaigns = find_campaigns(graph, min_ips=3)
        assert any(n["label"] == "sql_injection" for n in campaigns[0]["shared_nodes"])

    def test_kill_chain_stage_forms_campaign(self):
        incidents = [_incident(ip) for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]]
        chains = [_FakeChain(ip, {2: None}) for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]]
        graph = build_attack_graph(incidents, kill_chains=chains)
        campaigns = find_campaigns(graph, min_ips=3)
        assert len(campaigns) == 1

    def test_empty_graph_gives_no_campaigns(self):
        assert find_campaigns({"nodes": [], "edges": []}, min_ips=2) == []

    def test_single_ip_never_forms_a_campaign(self):
        incidents = [_incident("1.1.1.1", ["sql_injection: x"])]
        graph = build_attack_graph(incidents)
        assert find_campaigns(graph, min_ips=2) == []


class TestExplainConnection:
    def test_returns_shared_rule_node(self):
        incidents = [_incident(ip, ["sql_injection: x"]) for ip in ["1.1.1.1", "2.2.2.2"]]
        graph = build_attack_graph(incidents)
        shared = explain_connection("1.1.1.1", "2.2.2.2", graph)
        assert len(shared) == 1
        assert shared[0]["label"] == "sql_injection"

    def test_empty_when_no_direct_connection(self):
        incidents = [
            _incident("1.1.1.1", ["rule_a: x"]),
            _incident("2.2.2.2", ["rule_b: y"]),
        ]
        graph = build_attack_graph(incidents)
        assert explain_connection("1.1.1.1", "2.2.2.2", graph) == []

    def test_transitive_pair_has_no_direct_shared_nodes(self):
        """A and C are in the same campaign via B, but share nothing
        DIRECTLY -- explain_connection only reports direct sharing."""
        incidents = [
            _incident("A", ["rule_x: x"]),
            _incident("B", ["rule_x: x", "rule_y: y"]),
            _incident("C", ["rule_y: y"]),
        ]
        graph = build_attack_graph(incidents)
        assert explain_connection("A", "C", graph) == []
        assert len(explain_connection("A", "B", graph)) == 1

    def test_unknown_ip_returns_empty(self):
        incidents = [_incident("1.1.1.1", ["rule_a: x"])]
        graph = build_attack_graph(incidents)
        assert explain_connection("1.1.1.1", "9.9.9.9", graph) == []

    def test_multiple_shared_nodes_all_returned(self):
        incidents = [
            _incident("1.1.1.1", ["rule_a: x", "rule_b: y"]),
            _incident("2.2.2.2", ["rule_a: x", "rule_b: y"]),
        ]
        graph = build_attack_graph(incidents)
        shared = explain_connection("1.1.1.1", "2.2.2.2", graph)
        assert len(shared) == 2


class TestGraphCorrelationDashboardWiring:
    def _make_store(self, incidents=None):
        store = MagicMock()
        store.available = True
        store.recent_incidents = AsyncMock(return_value=incidents or [])
        return store

    async def _client(self, store, kill_chain_tracker=None):
        from aiohttp import web
        from aiohttp.test_utils import TestClient, TestServer
        from cnsl.dashboard_graph_correlation import register_graph_correlation_routes

        def _require_auth(req):
            return {"sub": "admin", "role": "admin"}, None
        def _rate_check(req):
            return None

        router = web.RouteTableDef()
        register_graph_correlation_routes(router, store, kill_chain_tracker,
                                           _require_auth, _rate_check)
        app = web.Application()
        app.add_routes(router)
        client = TestClient(TestServer(app))
        await client.start_server()
        return client

    def test_campaigns_endpoint_returns_matching_campaign(self):
        async def go():
            incidents = [_incident(ip, ["sql_injection: x"]) for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]]
            client = await self._client(self._make_store(incidents))
            r = await client.get("/api/graph/campaigns")
            data = await r.json()
            assert r.status == 200
            assert data["total_campaigns"] == 1
            assert set(data["campaigns"][0]["ips"]) == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}
            await client.close()
        _run(go())

    def test_campaigns_endpoint_empty_store(self):
        async def go():
            store = MagicMock()
            store.available = False
            client = await self._client(store)
            r = await client.get("/api/graph/campaigns")
            data = await r.json()
            assert r.status == 200
            assert data["total_campaigns"] == 0
            await client.close()
        _run(go())

    def test_campaigns_endpoint_min_ips_param(self):
        async def go():
            incidents = [_incident(ip, ["sql_injection: x"]) for ip in ["1.1.1.1", "2.2.2.2"]]
            client = await self._client(self._make_store(incidents))
            r = await client.get("/api/graph/campaigns?min_ips=2")
            data = await r.json()
            assert data["total_campaigns"] == 1
            await client.close()
        _run(go())

    def test_explain_endpoint_returns_shared_nodes(self):
        async def go():
            incidents = [_incident(ip, ["sql_injection: x"]) for ip in ["1.1.1.1", "2.2.2.2"]]
            client = await self._client(self._make_store(incidents))
            r = await client.get("/api/graph/explain/1.1.1.1/2.2.2.2")
            data = await r.json()
            assert r.status == 200
            assert data["directly_connected"] is True
            assert len(data["shared_nodes"]) == 1
            await client.close()
        _run(go())

    def test_explain_endpoint_not_connected(self):
        async def go():
            incidents = [
                _incident("1.1.1.1", ["rule_a: x"]),
                _incident("2.2.2.2", ["rule_b: y"]),
            ]
            client = await self._client(self._make_store(incidents))
            r = await client.get("/api/graph/explain/1.1.1.1/2.2.2.2")
            data = await r.json()
            assert data["directly_connected"] is False
            await client.close()
        _run(go())

    def test_incident_limit_param_passed_to_store(self):
        async def go():
            store = self._make_store([])
            client = await self._client(store)
            await client.get("/api/graph/campaigns?incident_limit=500")
            store.recent_incidents.assert_called_with(limit=500)
            await client.close()
        _run(go())

    def test_kill_chain_tracker_used_when_provided(self):
        async def go():
            incidents = [_incident(ip) for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]]
            kc = MagicMock()
            kc.get_all.return_value = [_FakeChain(ip, {2: None}) for ip in
                                        ["1.1.1.1", "2.2.2.2", "3.3.3.3"]]
            client = await self._client(self._make_store(incidents), kill_chain_tracker=kc)
            r = await client.get("/api/graph/campaigns?min_ips=3")
            data = await r.json()
            assert data["total_campaigns"] == 1
            await client.close()
        _run(go())


class TestDashboardGraphCorrelationModuleWiring:
    def test_register_function_importable(self):
        from cnsl.dashboard_graph_correlation import register_graph_correlation_routes
        assert callable(register_graph_correlation_routes)

    def test_routes_present_in_source(self):
        from pathlib import Path
        root = Path(__file__).parent.parent / "cnsl"
        src = (root / "dashboard.py").read_text(encoding="utf-8") + \
              (root / "dashboard_graph_correlation.py").read_text(encoding="utf-8")
        assert "/api/graph/campaigns" in src
        assert "/api/graph/explain/{ip_a}/{ip_b}" in src

    def test_dashboard_py_stays_under_line_budget(self):
        from pathlib import Path
        lines = len((Path(__file__).parent.parent / "cnsl" / "dashboard.py"
                     ).read_text(encoding="utf-8").splitlines())
        assert lines < 2000