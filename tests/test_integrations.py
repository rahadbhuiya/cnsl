"""
tests/test_integrations.py -- split from test_cnsl.py (v3.4.3 test suite reorg).

Run:
    pytest tests/test_integrations.py -v
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


class TestSIEMSeverityFiltering:
    """min_severity filtering logic shared by all connectors."""

    def test_sev_passes_equal_severity(self):
        from cnsl.siem_connectors import _sev_passes
        assert _sev_passes("MEDIUM", "MEDIUM") is True

    def test_sev_passes_higher_severity(self):
        from cnsl.siem_connectors import _sev_passes
        assert _sev_passes("HIGH", "MEDIUM") is True

    def test_sev_fails_lower_severity(self):
        from cnsl.siem_connectors import _sev_passes
        assert _sev_passes("LOW", "MEDIUM") is False

    def test_sev_unknown_defaults_to_low_rank(self):
        from cnsl.siem_connectors import _sev_passes
        assert _sev_passes("UNKNOWN", "LOW") is True
        assert _sev_passes("UNKNOWN", "MEDIUM") is False

class TestSIEMConnectorConfig:
    """Connector construction reads config correctly."""

    def test_splunk_disabled_by_default(self):
        from cnsl.siem_connectors import SplunkHECConnector
        c = SplunkHECConnector({})
        assert c.enabled is False

    def test_splunk_reads_config(self):
        from cnsl.siem_connectors import SplunkHECConnector
        c = SplunkHECConnector({"siem": {"splunk": {
            "enabled": True, "hec_url": "https://splunk.example.com:8088",
            "token": "abc123", "index": "myindex",
        }}})
        assert c.enabled is True
        assert c.hec_url == "https://splunk.example.com:8088"
        assert c.index == "myindex"

    def test_sentinel_disabled_by_default(self):
        from cnsl.siem_connectors import SentinelConnector
        c = SentinelConnector({})
        assert c.enabled is False

    def test_webhook_disabled_by_default(self):
        from cnsl.siem_connectors import WebhookConnector
        c = WebhookConnector({})
        assert c.enabled is False

    def test_webhook_reads_bearer_token(self):
        from cnsl.siem_connectors import WebhookConnector
        c = WebhookConnector({"siem": {"webhook": {
            "enabled": True, "url": "https://example.com/ingest",
            "bearer_token": "secret-token",
        }}})
        assert c.bearer_token == "secret-token"

class TestSIEMRouter:
    """SIEMRouter orchestration, push, and disabled-connector behavior."""

    def test_router_disabled_when_no_connector_enabled(self):
        from cnsl.siem_connectors import SIEMRouter
        router = SIEMRouter({})
        assert router.enabled is False

    def test_router_enabled_when_any_connector_enabled(self):
        from cnsl.siem_connectors import SIEMRouter
        router = SIEMRouter({"siem": {"splunk": {"enabled": True,
                             "hec_url": "https://x.com", "token": "t"}}})
        assert router.enabled is True

    def test_push_noop_when_disabled(self):
        from cnsl.siem_connectors import SIEMRouter
        from cnsl.models import Detection

        async def _go():
            router = SIEMRouter({})
            d = Detection(src_ip="1.2.3.4", severity="HIGH", reasons=["test"],
                          fail_count=1, uniq_users=1, window_sec=60)
            # Should not raise even though no connector is enabled
            await router.push(d)

        _run(_go())

    def test_status_returns_all_connector_names(self):
        from cnsl.siem_connectors import SIEMRouter

        async def _go():
            router = SIEMRouter({})
            return await router.status()

        status = _run(_go())
        assert set(status["connectors"].keys()) == {"splunk", "sentinel", "webhook"}

    def test_flush_queue_empty_returns_empty_dict(self):
        from cnsl.siem_connectors import SIEMRouter

        async def _go():
            router = SIEMRouter({})
            return await router.flush_queue()

        result = _run(_go())
        assert result == {}

    def test_close_does_not_raise_with_no_sessions(self):
        from cnsl.siem_connectors import SIEMRouter

        async def _go():
            router = SIEMRouter({})
            await router.close()  # connectors never opened a session

        _run(_go())

class TestFederatedSignal:
    """FederatedSignal serialization round-trip and malformed-input handling."""

    def test_to_dict_round_trip(self):
        from cnsl.federation import FederatedSignal
        sig = FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="SSH_FAIL",
                              severity="MEDIUM")
        d = sig.to_dict()
        restored = FederatedSignal.from_dict(d)
        assert restored.node_id == "node-a"
        assert restored.ip == "1.2.3.4"
        assert restored.kind == "SSH_FAIL"
        assert restored.severity == "MEDIUM"

    def test_from_dict_missing_required_field_returns_none(self):
        from cnsl.federation import FederatedSignal
        assert FederatedSignal.from_dict({"node_id": "a", "ip": "1.2.3.4"}) is None

    def test_from_dict_severity_defaults_to_low(self):
        from cnsl.federation import FederatedSignal
        sig = FederatedSignal.from_dict({"node_id": "a", "ip": "1.2.3.4", "kind": "X"})
        assert sig.severity == "LOW"

class TestFederatedIPRecord:
    """Cross-node detection: is_cross_node only True with 2+ distinct nodes."""

    def test_single_node_not_cross_node(self):
        from cnsl.federation import FederatedIPRecord, FederatedSignal
        record = FederatedIPRecord(ip="1.2.3.4")
        record.add(FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="SSH_FAIL"))
        assert record.is_cross_node is False
        assert record.node_count == 1

    def test_two_nodes_is_cross_node(self):
        from cnsl.federation import FederatedIPRecord, FederatedSignal
        record = FederatedIPRecord(ip="1.2.3.4")
        record.add(FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="SSH_FAIL"))
        record.add(FederatedSignal(node_id="node-b", ip="1.2.3.4", kind="WEB_SCAN"))
        assert record.is_cross_node is True
        assert record.node_count == 2

    def test_same_node_multiple_signals_not_cross_node(self):
        from cnsl.federation import FederatedIPRecord, FederatedSignal
        record = FederatedIPRecord(ip="1.2.3.4")
        record.add(FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="SSH_FAIL"))
        record.add(FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="SSH_FAIL"))
        record.add(FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="SSH_FAIL"))
        assert record.is_cross_node is False

    def test_to_dict_includes_kinds_per_node(self):
        from cnsl.federation import FederatedIPRecord, FederatedSignal
        record = FederatedIPRecord(ip="1.2.3.4")
        record.add(FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="SSH_FAIL"))
        record.add(FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="WEB_SCAN"))
        d = record.to_dict()
        assert set(d["nodes"]["node-a"]["kinds"]) == {"SSH_FAIL", "WEB_SCAN"}

    def test_signal_history_bounded_per_node(self):
        from cnsl.federation import FederatedIPRecord, FederatedSignal
        record = FederatedIPRecord(ip="1.2.3.4")
        for _ in range(60):
            record.add(FederatedSignal(node_id="node-a", ip="1.2.3.4", kind="SSH_FAIL"))
        assert len(record.node_signals["node-a"]) <= 50

class TestFederationBusConfig:
    """FederationBus construction and config defaults."""

    def _make_redis_sync_stub(self, connected=False, node_id="test-node"):
        class _Stub:
            pass
        stub = _Stub()
        stub.node_id   = node_id
        stub.prefix    = "cnsl"
        stub.connected = connected
        stub._redis    = None
        return stub

    def test_enabled_by_default(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({}, self._make_redis_sync_stub(), logger=None)
        assert bus.enabled is True

    def test_disabled_via_config(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({"federation": {"enabled": False}},
                            self._make_redis_sync_stub(), logger=None)
        assert bus.enabled is False

    def test_channel_uses_redis_sync_prefix(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({}, self._make_redis_sync_stub(), logger=None)
        assert bus._channel == "cnsl:federation"

    def test_node_id_taken_from_redis_sync(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({}, self._make_redis_sync_stub(node_id="web-01-abc"), logger=None)
        assert bus.node_id == "web-01-abc"

    def test_not_connected_when_redis_sync_not_connected(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({}, self._make_redis_sync_stub(connected=False), logger=None)
        assert bus.is_connected is False

    def test_connected_when_redis_sync_connected_and_enabled(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({}, self._make_redis_sync_stub(connected=True), logger=None)
        assert bus.is_connected is True

    def test_dedupe_window_reads_config(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({"federation": {"dedupe_window_sec": 30}},
                            self._make_redis_sync_stub(), logger=None)
        assert bus.dedupe_window_sec == 30

class TestFederationBusPublish:
    """publish() behavior: disabled is a no-op success, disconnected fails cleanly."""

    def _make_redis_sync_stub(self, connected=False):
        class _Stub:
            pass
        stub = _Stub()
        stub.node_id   = "test-node"
        stub.prefix    = "cnsl"
        stub.connected = connected
        stub._redis    = None
        return stub

    def test_publish_disabled_returns_true(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({"federation": {"enabled": False}},
                            self._make_redis_sync_stub(), logger=None)
        result = _run(bus.publish("1.2.3.4", "SSH_FAIL"))
        assert result is True  # disabled federation must never look like a failure

    def test_publish_without_ip_returns_true(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({}, self._make_redis_sync_stub(connected=True), logger=None)
        result = _run(bus.publish("", "SSH_FAIL"))
        assert result is True

    def test_publish_when_not_connected_returns_false(self):
        from cnsl.federation import FederationBus
        bus = FederationBus({}, self._make_redis_sync_stub(connected=False), logger=None)
        result = _run(bus.publish("1.2.3.4", "SSH_FAIL"))
        assert result is False

    def test_publish_dedupes_within_window(self):
        from cnsl.federation import FederationBus

        class _StubWithRedis:
            def __init__(self):
                self.node_id   = "test-node"
                self.prefix    = "cnsl"
                self.connected = True
                self.calls     = []

                async def _publish(channel, data):
                    self.calls.append((channel, data))
                self._redis = type("R", (), {"publish": staticmethod(_publish)})()

        stub = _StubWithRedis()
        bus  = FederationBus({"federation": {"dedupe_window_sec": 60}}, stub, logger=None)

        async def _go():
            await bus.publish("1.2.3.4", "SSH_FAIL")
            await bus.publish("1.2.3.4", "SSH_FAIL")  # should be deduped
            await bus.publish("1.2.3.4", "WEB_SCAN")  # different kind, not deduped

        _run(_go())
        assert len(stub.calls) == 2  # SSH_FAIL once, WEB_SCAN once

class TestFederationBusReceive:
    """Remote signal handling: IP record updates and callback invocation."""

    def _make_bus(self):
        from cnsl.federation import FederationBus
        class _Stub:
            pass
        stub = _Stub()
        stub.node_id   = "local-node"
        stub.prefix    = "cnsl"
        stub.connected = False
        stub._redis    = None
        return FederationBus({}, stub, logger=None)

    def test_handle_remote_signal_creates_ip_record(self):
        from cnsl.federation import FederatedSignal
        bus = self._make_bus()
        sig = FederatedSignal(node_id="remote-node", ip="1.2.3.4", kind="SSH_FAIL")
        _run(bus._handle_remote_signal(sig))
        record = bus.get_ip_record("1.2.3.4")
        assert record is not None
        assert "remote-node" in record.node_signals

    def test_handle_remote_signal_invokes_callback(self):
        from cnsl.federation import FederatedSignal
        bus = self._make_bus()
        received = []

        async def _cb(signal):
            received.append(signal)

        bus.on_remote_signal = _cb
        sig = FederatedSignal(node_id="remote-node", ip="1.2.3.4", kind="SSH_FAIL")
        _run(bus._handle_remote_signal(sig))
        assert len(received) == 1
        assert received[0].ip == "1.2.3.4"

    def test_callback_exception_does_not_propagate(self):
        from cnsl.federation import FederatedSignal
        bus = self._make_bus()

        async def _bad_cb(signal):
            raise RuntimeError("boom")

        bus.on_remote_signal = _bad_cb
        sig = FederatedSignal(node_id="remote-node", ip="1.2.3.4", kind="SSH_FAIL")
        _run(bus._handle_remote_signal(sig))  # must not raise

    def test_node_last_seen_tracked(self):
        from cnsl.federation import FederatedSignal
        bus = self._make_bus()
        sig = FederatedSignal(node_id="remote-node", ip="1.2.3.4", kind="SSH_FAIL")
        _run(bus._handle_remote_signal(sig))
        assert "remote-node" in bus._node_last_seen

    def test_signals_received_counter_increments(self):
        from cnsl.federation import FederatedSignal
        bus = self._make_bus()
        sig = FederatedSignal(node_id="remote-node", ip="1.2.3.4", kind="SSH_FAIL")
        _run(bus._handle_remote_signal(sig))
        _run(bus._handle_remote_signal(sig))
        assert bus._signals_received == 2

    def test_max_remote_ips_evicts_oldest(self):
        from cnsl.federation import FederatedSignal, FederationBus
        class _Stub:
            pass
        stub = _Stub()
        stub.node_id, stub.prefix, stub.connected, stub._redis = "local", "cnsl", False, None
        bus = FederationBus({"federation": {"max_remote_ips": 2}}, stub, logger=None)

        async def _go():
            await bus._handle_remote_signal(
                FederatedSignal(node_id="r", ip="1.1.1.1", kind="SSH_FAIL"))
            await bus._handle_remote_signal(
                FederatedSignal(node_id="r", ip="2.2.2.2", kind="SSH_FAIL"))
            await bus._handle_remote_signal(
                FederatedSignal(node_id="r", ip="3.3.3.3", kind="SSH_FAIL"))

        _run(_go())
        assert len(bus._ip_records) == 2
        assert "1.1.1.1" not in bus._ip_records

class TestFederationBusQueries:
    """get_cross_node_ips, known_nodes, and status reporting."""

    def _make_bus_with_signals(self):
        from cnsl.federation import FederationBus, FederatedSignal
        class _Stub:
            pass
        stub = _Stub()
        stub.node_id, stub.prefix, stub.connected, stub._redis = "local", "cnsl", False, None
        bus = FederationBus({}, stub, logger=None)

        async def _go():
            # 1.1.1.1 seen by two nodes -- cross-node
            await bus._handle_remote_signal(
                FederatedSignal(node_id="node-a", ip="1.1.1.1", kind="WEB_SCAN"))
            await bus._handle_remote_signal(
                FederatedSignal(node_id="node-b", ip="1.1.1.1", kind="SSH_FAIL"))
            # 2.2.2.2 seen by only one node -- not cross-node
            await bus._handle_remote_signal(
                FederatedSignal(node_id="node-a", ip="2.2.2.2", kind="WEB_SCAN"))

        _run(_go())
        return bus

    def test_get_cross_node_ips_filters_correctly(self):
        bus     = self._make_bus_with_signals()
        crossed = bus.get_cross_node_ips()
        ips     = [r.ip for r in crossed]
        assert "1.1.1.1" in ips
        assert "2.2.2.2" not in ips

    def test_known_nodes_lists_all_seen_nodes(self):
        bus   = self._make_bus_with_signals()
        nodes = bus.known_nodes()
        node_ids = [n["node_id"] for n in nodes]
        assert "node-a" in node_ids
        assert "node-b" in node_ids

    def test_status_reports_cross_node_count(self):
        bus    = self._make_bus_with_signals()
        status = bus.status()
        assert status["cross_node_ips"] == 1
        assert status["ips_tracked"] == 2
        assert status["known_peer_count"] == 2

class TestCloudEventKinds:
    """Cloud event kind constants are correct strings."""

    def test_signin_fail_kind(self):
        from cnsl.cloud_identity import CloudEventKind
        assert CloudEventKind.SIGNIN_FAIL == "CLOUD_SIGNIN_FAIL"

    def test_signin_success_kind(self):
        from cnsl.cloud_identity import CloudEventKind
        assert CloudEventKind.SIGNIN_SUCCESS == "CLOUD_SIGNIN_SUCCESS"

    def test_mfa_fail_kind(self):
        from cnsl.cloud_identity import CloudEventKind
        assert CloudEventKind.MFA_FAIL == "CLOUD_MFA_FAIL"

    def test_risky_signin_kind(self):
        from cnsl.cloud_identity import CloudEventKind
        assert CloudEventKind.RISKY_SIGNIN == "CLOUD_RISKY_SIGNIN"

    def test_impossible_travel_kind(self):
        from cnsl.cloud_identity import CloudEventKind
        assert CloudEventKind.IMPOSSIBLE_TRAVEL == "CLOUD_IMPOSSIBLE_TRAVEL"

class TestCloudConnectorConfig:
    """Connector construction reads config and defaults correctly."""

    def test_aws_disabled_by_default(self):
        from cnsl.cloud_identity import AWSCloudTrailConnector
        c = AWSCloudTrailConnector({})
        assert c.enabled is False

    def test_aws_reads_config(self):
        from cnsl.cloud_identity import AWSCloudTrailConnector
        c = AWSCloudTrailConnector({"cloud_identity": {"aws": {
            "enabled": True, "access_key_id": "AK123",
            "secret_access_key": "secret", "region": "eu-west-1",
        }}})
        assert c.enabled is True
        assert c.region == "eu-west-1"
        assert c.access_key == "AK123"

    def test_azure_disabled_by_default(self):
        from cnsl.cloud_identity import AzureADConnector
        c = AzureADConnector({})
        assert c.enabled is False

    def test_azure_reads_config(self):
        from cnsl.cloud_identity import AzureADConnector
        c = AzureADConnector({"cloud_identity": {"azure_ad": {
            "enabled": True, "tenant_id": "tenant-xyz",
            "client_id": "client-abc", "client_secret": "s3cr3t",
        }}})
        assert c.enabled is True
        assert c.tenant_id == "tenant-xyz"

    def test_poller_disabled_when_no_connector_enabled(self):
        from cnsl.cloud_identity import CloudIdentityPoller
        poller = CloudIdentityPoller({})
        assert poller.any_enabled is False

    def test_poller_enabled_when_aws_enabled(self):
        from cnsl.cloud_identity import CloudIdentityPoller
        poller = CloudIdentityPoller({"cloud_identity": {
            "aws": {"enabled": True, "access_key_id": "AK", "secret_access_key": "SK"}
        }})
        assert poller.any_enabled is True

    def test_poller_status_reports_events_fed(self):
        from cnsl.cloud_identity import CloudIdentityPoller
        poller = CloudIdentityPoller({})
        status = poller.status()
        assert "events_fed" in status
        assert "connectors" in status
        assert "aws_cloudtrail" in status["connectors"]
        assert "azure_ad" in status["connectors"]
