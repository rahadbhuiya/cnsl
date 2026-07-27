"""
tests/test_stix_taxii.py -- tests for STIX 2.1 bundle export
(cnsl/stix_export.py) and the minimal read-only TAXII 2.1 server
(cnsl/taxii.py).
"""

from __future__ import annotations

import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock

from cnsl.stix_export import (
    build_stix_bundle,
    indicator_from_attacker,
    cnsl_identity_object,
    _ip_pattern,
    _deterministic_indicator_id,
    _severity_to_confidence,
)


def _run(coro):
    return asyncio.run(coro)


def _attacker(**overrides):
    base = {
        "src_ip": "45.33.32.1", "flag": "🇺🇸", "country": "US", "city": "Ashburn",
        "isp": "Example ISP", "incident_count": 5, "max_severity": "HIGH",
        "first_seen": 1700000000.0, "last_seen": 1700003600.0,
    }
    base.update(overrides)
    return base


class TestIpPattern:
    def test_ipv4_pattern(self):
        assert _ip_pattern("45.33.32.1") == "[ipv4-addr:value = '45.33.32.1']"

    def test_ipv6_pattern(self):
        assert _ip_pattern("2001:db8::1") == "[ipv6-addr:value = '2001:db8::1']"

    def test_invalid_ip_returns_none(self):
        assert _ip_pattern("not-an-ip") is None


class TestSeverityToConfidence:
    def test_high(self):
        assert _severity_to_confidence("HIGH") == 85

    def test_medium(self):
        assert _severity_to_confidence("MEDIUM") == 60

    def test_low(self):
        assert _severity_to_confidence("LOW") == 35

    def test_unknown_defaults_to_50(self):
        assert _severity_to_confidence("WEIRD") == 50

    def test_none_defaults_to_50(self):
        assert _severity_to_confidence(None) == 50

    def test_case_insensitive(self):
        assert _severity_to_confidence("high") == 85


class TestDeterministicIndicatorId:
    def test_same_ip_same_id(self):
        a = _deterministic_indicator_id("45.33.32.1")
        b = _deterministic_indicator_id("45.33.32.1")
        assert a == b

    def test_different_ip_different_id(self):
        a = _deterministic_indicator_id("45.33.32.1")
        b = _deterministic_indicator_id("45.33.32.2")
        assert a != b

    def test_id_has_indicator_prefix(self):
        assert _deterministic_indicator_id("1.2.3.4").startswith("indicator--")


class TestIndicatorFromAttacker:
    def test_builds_valid_indicator_for_ipv4(self):
        ind = indicator_from_attacker(_attacker())
        assert ind["type"] == "indicator"
        assert ind["spec_version"] == "2.1"
        assert ind["pattern"] == "[ipv4-addr:value = '45.33.32.1']"
        assert ind["pattern_type"] == "stix"
        assert "malicious-activity" in ind["indicator_types"]

    def test_builds_valid_indicator_for_ipv6(self):
        ind = indicator_from_attacker(_attacker(src_ip="2001:db8::1"))
        assert ind["pattern"] == "[ipv6-addr:value = '2001:db8::1']"

    def test_missing_ip_returns_none(self):
        assert indicator_from_attacker(_attacker(src_ip=None)) is None
        assert indicator_from_attacker({}) is None

    def test_invalid_ip_returns_none(self):
        assert indicator_from_attacker(_attacker(src_ip="garbage")) is None

    def test_confidence_reflects_severity(self):
        ind = indicator_from_attacker(_attacker(max_severity="HIGH"))
        assert ind["confidence"] == 85

    def test_description_mentions_count_and_country(self):
        ind = indicator_from_attacker(_attacker(incident_count=7, country="RU"))
        assert "7 incident" in ind["description"]
        assert "RU" in ind["description"]

    def test_description_omits_country_when_absent(self):
        ind = indicator_from_attacker(_attacker(country=None))
        assert "seen from" not in ind["description"]

    def test_created_by_ref_points_to_identity(self):
        ind = indicator_from_attacker(_attacker())
        assert ind["created_by_ref"] == cnsl_identity_object()["id"]

    def test_label_reflects_severity(self):
        ind = indicator_from_attacker(_attacker(max_severity="MEDIUM"))
        assert "cnsl-severity-medium" in ind["labels"]

    def test_missing_first_seen_falls_back_to_last_seen(self):
        ind = indicator_from_attacker(_attacker(first_seen=None, last_seen=1700003600.0))
        assert ind is not None  # must not crash

    def test_id_is_deterministic_across_calls(self):
        ind1 = indicator_from_attacker(_attacker())
        ind2 = indicator_from_attacker(_attacker())
        assert ind1["id"] == ind2["id"]


class TestCnslIdentityObject:
    def test_identity_shape(self):
        ident = cnsl_identity_object()
        assert ident["type"] == "identity"
        assert ident["identity_class"] == "system"
        assert ident["id"].startswith("identity--")

    def test_identity_id_is_stable(self):
        assert cnsl_identity_object()["id"] == cnsl_identity_object()["id"]


class TestBuildStixBundle:
    def test_bundle_shape(self):
        bundle = build_stix_bundle([_attacker()])
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        assert isinstance(bundle["objects"], list)

    def test_bundle_always_includes_identity(self):
        bundle = build_stix_bundle([])
        types = [o["type"] for o in bundle["objects"]]
        assert "identity" in types
        assert len(bundle["objects"]) == 1

    def test_bundle_includes_one_indicator_per_valid_attacker(self):
        bundle = build_stix_bundle([_attacker(src_ip="1.1.1.1"), _attacker(src_ip="2.2.2.2")])
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 2

    def test_bundle_skips_bad_rows_without_failing(self):
        rows = [_attacker(src_ip="1.1.1.1"), {"src_ip": None}, _attacker(src_ip="garbage")]
        bundle = build_stix_bundle(rows)
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 1

    def test_empty_input_still_valid_bundle(self):
        bundle = build_stix_bundle([])
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) == 1  # identity only

    def test_bundle_id_unique_per_call(self):
        b1 = build_stix_bundle([])
        b2 = build_stix_bundle([])
        assert b1["id"] != b2["id"]


class TestTaxiiRoutes:
    """End-to-end route tests using aiohttp's test client."""

    def _make_store(self, attackers=None):
        store = MagicMock()
        store.available = True
        store.top_attackers = AsyncMock(return_value=attackers or [_attacker()])
        return store

    async def _client(self, store):
        from aiohttp import web
        from aiohttp.test_utils import TestClient, TestServer
        from cnsl.taxii import register_stix_export_route, register_taxii_routes

        def _require_auth(req):
            return {"sub": "admin", "role": "admin"}, None

        def _rate_check(req):
            return None

        router = web.RouteTableDef()
        register_stix_export_route(router, store, _require_auth, _rate_check)
        register_taxii_routes(router, store, _require_auth, _rate_check)
        app = web.Application()
        app.add_routes(router)
        client = TestClient(TestServer(app))
        await client.start_server()
        return client

    def test_stix_bundle_download_route(self):
        async def go():
            client = await self._client(self._make_store())
            r = await client.get("/api/export/stix")
            assert r.status == 200
            assert "attachment" in r.headers.get("Content-Disposition", "")
            data = await r.json()
            assert data["type"] == "bundle"
            await client.close()
        _run(go())

    def test_stix_bundle_respects_limit_param(self):
        async def go():
            store = self._make_store()
            client = await self._client(store)
            await client.get("/api/export/stix?limit=5")
            store.top_attackers.assert_called_with(limit=5)
            await client.close()
        _run(go())

    def test_stix_bundle_empty_when_store_unavailable(self):
        async def go():
            store = MagicMock()
            store.available = False
            client = await self._client(store)
            r = await client.get("/api/export/stix")
            data = await r.json()
            assert len(data["objects"]) == 1  # identity only
            await client.close()
        _run(go())

    def test_taxii_discovery(self):
        async def go():
            client = await self._client(self._make_store())
            r = await client.get("/taxii2/")
            assert r.status == 200
            assert r.content_type == "application/taxii+json"
            data = await r.json()
            assert data["default"] == "/taxii2/cnsl/"
            await client.close()
        _run(go())

    def test_taxii_api_root(self):
        async def go():
            client = await self._client(self._make_store())
            r = await client.get("/taxii2/cnsl/")
            assert r.status == 200
            data = await r.json()
            assert "application/taxii+json;version=2.1" in data["versions"]
            await client.close()
        _run(go())

    def test_taxii_collections_list(self):
        async def go():
            client = await self._client(self._make_store())
            r = await client.get("/taxii2/cnsl/collections/")
            data = await r.json()
            assert len(data["collections"]) == 1
            assert data["collections"][0]["id"] == "attacker-ips"
            assert data["collections"][0]["can_write"] is False
            await client.close()
        _run(go())

    def test_taxii_collection_detail(self):
        async def go():
            client = await self._client(self._make_store())
            r = await client.get("/taxii2/cnsl/collections/attacker-ips/")
            assert r.status == 200
            data = await r.json()
            assert data["id"] == "attacker-ips"
            await client.close()
        _run(go())

    def test_taxii_collection_detail_404_for_unknown_id(self):
        async def go():
            client = await self._client(self._make_store())
            r = await client.get("/taxii2/cnsl/collections/nonexistent/")
            assert r.status == 404
            await client.close()
        _run(go())

    def test_taxii_objects_returns_stix_objects(self):
        async def go():
            client = await self._client(self._make_store())
            r = await client.get("/taxii2/cnsl/collections/attacker-ips/objects/")
            assert r.status == 200
            assert r.content_type == "application/stix+json"
            data = await r.json()
            assert any(o["type"] == "indicator" for o in data["objects"])
            await client.close()
        _run(go())

    def test_taxii_objects_404_for_unknown_collection(self):
        async def go():
            client = await self._client(self._make_store())
            r = await client.get("/taxii2/cnsl/collections/nonexistent/objects/")
            assert r.status == 404
            await client.close()
        _run(go())

    def test_taxii_objects_respects_limit(self):
        async def go():
            store = self._make_store()
            client = await self._client(store)
            await client.get("/taxii2/cnsl/collections/attacker-ips/objects/?limit=10")
            store.top_attackers.assert_called_with(limit=10)
            await client.close()
        _run(go())

    def test_taxii_objects_empty_collection_when_store_unavailable(self):
        async def go():
            store = MagicMock()
            store.available = False
            client = await self._client(store)
            r = await client.get("/taxii2/cnsl/collections/attacker-ips/objects/")
            data = await r.json()
            assert len(data["objects"]) == 1  # identity only
            await client.close()
        _run(go())


class TestDashboardStixTaxiiWiring:
    def test_register_functions_importable(self):
        from cnsl.taxii import register_stix_export_route, register_taxii_routes
        assert callable(register_stix_export_route)
        assert callable(register_taxii_routes)

    def test_routes_present_in_source(self):
        from pathlib import Path
        root = Path(__file__).parent.parent / "cnsl"
        src = (root / "dashboard.py").read_text(encoding="utf-8") + \
              (root / "taxii.py").read_text(encoding="utf-8")
        assert "/api/export/stix" in src
        assert "/taxii2/" in src

    def test_dashboard_py_stays_under_line_budget(self):
        from pathlib import Path
        lines = len((Path(__file__).parent.parent / "cnsl" / "dashboard.py"
                     ).read_text(encoding="utf-8").splitlines())
        assert lines < 2000


class TestStoreTopAttackersFirstSeen:
    """store.top_attackers() gained first_seen (MIN(ts)) for STIX's
    valid_from/created fields."""

    def test_top_attackers_query_includes_first_seen(self):
        from pathlib import Path
        src = (Path(__file__).parent.parent / "cnsl" / "store.py").read_text(encoding="utf-8")
        assert "first_seen" in src
        assert "MIN(ts)" in src