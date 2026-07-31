"""
tests/test_helm_chart.py -- structural validation of the Helm chart
(helm/cnsl/) without requiring the helm binary itself:

- Chart.yaml / values.yaml are well-formed YAML with the expected shape.
- Every template file has balanced {{ }} and if/with/range/end blocks.
- The default embedded config.json (values.yaml's `config` key) is valid
  JSON and passes CNSL's own config validator with zero errors.
- Key safety properties hold: dry_run defaults to true, NET_ADMIN/NET_RAW
  capabilities are requested, DaemonSet mode never uses a shared PVC.

Requires PyYAML (the `yaml` extra) -- skipped gracefully if unavailable,
matching the sklearn-optional pattern in tests/helpers.py.
"""

from __future__ import annotations

import glob
import json
import re
from pathlib import Path

import pytest

try:
    import yaml
    _YAML_AVAILABLE = True
except Exception:
    _YAML_AVAILABLE = False

pytestmark = pytest.mark.skipif(not _YAML_AVAILABLE, reason="PyYAML not installed")

CHART_DIR = Path(__file__).parent.parent / "helm" / "cnsl"


def _template_files():
    return sorted(glob.glob(str(CHART_DIR / "templates" / "**" / "*.yaml"), recursive=True))


def _read(path) -> str:
    return Path(path).read_text(encoding="utf-8")


class TestChartYaml:
    def test_chart_yaml_parses(self):
        chart = yaml.safe_load(_read(CHART_DIR / "Chart.yaml"))
        assert chart["name"] == "cnsl"
        assert chart["apiVersion"] == "v2"

    def test_app_version_matches_cnsl_version(self):
        chart = yaml.safe_load(_read(CHART_DIR / "Chart.yaml"))
        from cnsl import __version__
        assert chart["appVersion"] == __version__, (
            "Chart.yaml's appVersion is out of sync with cnsl.__version__ -- "
            "bump it alongside every other version reference."
        )

    def test_kube_version_constraint_present(self):
        chart = yaml.safe_load(_read(CHART_DIR / "Chart.yaml"))
        assert "kubeVersion" in chart


class TestValuesYaml:
    def _values(self):
        return yaml.safe_load(_read(CHART_DIR / "values.yaml"))

    def test_values_yaml_parses(self):
        values = self._values()
        assert isinstance(values, dict)

    def test_default_deployment_mode_is_daemonset(self):
        values = self._values()
        assert values["deploymentMode"] == "daemonset"

    def test_daemonset_mode_supports_per_node_state(self):
        """DaemonSet mode must default to a hostPath, not a shared PVC --
        a single ReadWriteOnce PVC can't be mounted by pods on different
        nodes at once."""
        values = self._values()
        assert values["persistence"]["hostPath"], (
            "persistence.hostPath must have a default value for daemonset "
            "mode -- a PVC can't be shared across nodes."
        )

    def test_host_network_enabled_by_default(self):
        values = self._values()
        assert values["hostNetwork"] is True

    def test_dns_policy_set_for_host_network(self):
        values = self._values()
        assert values["dnsPolicy"] == "ClusterFirstWithHostNet"

    def test_net_admin_and_net_raw_capabilities_requested(self):
        values = self._values()
        caps = values["securityContext"]["capabilities"]["add"]
        assert "NET_ADMIN" in caps
        assert "NET_RAW" in caps

    def test_dashboard_enabled_by_default(self):
        values = self._values()
        assert values["dashboard"]["enabled"] is True
        assert values["dashboard"]["port"] == 8765

    def test_redis_disabled_by_default(self):
        """Bundled Redis is opt-in -- a plain `helm install` shouldn't
        silently deploy an extra stateful component."""
        values = self._values()
        assert values["redis"]["enabled"] is False

    def test_secrets_blank_by_default_for_auto_generation(self):
        values = self._values()
        assert values["secrets"]["jwtSecret"] == ""
        assert values["secrets"]["apiSecret"] == ""

    def test_control_plane_tolerations_present(self):
        """DaemonSets should schedule onto control-plane nodes too --
        those need protecting like any other node."""
        values = self._values()
        toleration_keys = {t["key"] for t in values["tolerations"]}
        assert "node-role.kubernetes.io/control-plane" in toleration_keys


class TestEmbeddedConfigJson:
    """values.yaml's `config` key is CNSL's own config.json, embedded as a
    raw string. It must be valid JSON and pass CNSL's own validator."""

    def _rendered_config(self) -> dict:
        values = yaml.safe_load(_read(CHART_DIR / "values.yaml"))
        config_str = values["config"]
        # Simulate Helm's `tpl` rendering of the one template expression
        # this default config contains (the bundled Redis service name).
        rendered = re.sub(r"\{\{.*?\}\}", "cnsl-redis-dummy", config_str)
        return json.loads(rendered)

    def test_config_is_valid_json(self):
        cfg = self._rendered_config()
        assert isinstance(cfg, dict)

    def test_config_defaults_to_dry_run(self):
        """Safety-first default: a plain `helm install` must never start
        actually blocking IPs without the operator opting in."""
        cfg = self._rendered_config()
        assert cfg["actions"]["dry_run"] is True

    def test_config_passes_cnsl_validator_with_no_errors(self):
        from cnsl.validator import validate_config
        from cnsl.config import DEFAULT_CONFIG
        cfg = self._rendered_config()
        merged = {**DEFAULT_CONFIG, **cfg}
        errors = [i for i in validate_config(merged) if i.level == "error"]
        assert errors == [], f"Chart's default config.json fails validation: {errors}"

    def test_config_store_path_matches_persistence_mount(self):
        """The configured SQLite path must live under the volume that's
        actually mounted at /var/lib/cnsl, or CNSL's state silently
        wouldn't persist across pod restarts."""
        cfg = self._rendered_config()
        assert cfg["store"]["db_path"].startswith("/var/lib/cnsl/")

    def test_config_dashboard_port_matches_values_dashboard_port(self):
        values = yaml.safe_load(_read(CHART_DIR / "values.yaml"))
        cfg = self._rendered_config()
        assert cfg["dashboard"]["port"] == values["dashboard"]["port"]


class TestTemplateFilesWellFormed:
    """Structural checks that don't require actually running `helm
    template` -- catch unbalanced braces/blocks, which are the most
    common copy-paste error in hand-written Helm templates."""

    def test_every_expected_template_exists(self):
        names = {Path(f).name for f in _template_files()}
        expected = {
            "configmap.yaml", "secret.yaml", "serviceaccount.yaml",
            "service.yaml", "daemonset.yaml", "deployment.yaml",
            "pvc.yaml", "redis.yaml", "NOTES.txt", "test-connection.yaml",
        }
        # NOTES.txt isn't a .yaml file so glob for *.yaml won't find it --
        # check it separately.
        assert expected - {"NOTES.txt"} <= names
        assert (CHART_DIR / "templates" / "NOTES.txt").exists()

    def test_helpers_tpl_exists(self):
        assert (CHART_DIR / "templates" / "_helpers.tpl").exists()

    @pytest.mark.parametrize("path", _template_files())
    def test_braces_balanced(self, path):
        text = _read(path)
        assert text.count("{{") == text.count("}}"), f"Unbalanced braces in {path}"

    @pytest.mark.parametrize("path", _template_files())
    def test_control_blocks_balanced(self, path):
        text = _read(path)
        opens = len(re.findall(r"\{\{-?\s*(if|range|with|define)\b", text))
        ends  = len(re.findall(r"\{\{-?\s*end\s*-?\}\}", text))
        assert opens == ends, f"Unbalanced if/range/with/end blocks in {path}"

    def test_helpers_tpl_braces_balanced(self):
        text = _read(CHART_DIR / "templates" / "_helpers.tpl")
        assert text.count("{{") == text.count("}}")


class TestDeploymentModeConditionals:
    """DaemonSet and Deployment templates must be mutually exclusive on
    .Values.deploymentMode -- both should never render at once."""

    def test_daemonset_gated_on_deploymentmode(self):
        text = _read(CHART_DIR / "templates" / "daemonset.yaml")
        assert 'eq .Values.deploymentMode "daemonset"' in text

    def test_deployment_gated_on_deploymentmode(self):
        text = _read(CHART_DIR / "templates" / "deployment.yaml")
        assert 'eq .Values.deploymentMode "deployment"' in text

    def test_pvc_only_for_deployment_mode_without_hostpath(self):
        """A PVC must never be offered for daemonset mode -- a single
        ReadWriteOnce volume can't be shared across nodes."""
        text = _read(CHART_DIR / "templates" / "pvc.yaml")
        assert 'eq .Values.deploymentMode "deployment"' in text
        assert "persistence.hostPath" in text

    def test_daemonset_never_references_pvc_claim(self):
        """Regression guard: daemonset.yaml must not mount a
        persistentVolumeClaim under any code path -- only hostPath or
        emptyDir make sense for per-node state."""
        text = _read(CHART_DIR / "templates" / "daemonset.yaml")
        assert "persistentVolumeClaim" not in text


class TestHealthProbesUseHealthEndpoint:
    """Probes must hit the unauthenticated /api/health endpoint, not a
    route that requires a bearer token (which the kubelet can't supply)."""

    @pytest.mark.parametrize("template", ["daemonset.yaml", "deployment.yaml"])
    def test_liveness_and_readiness_use_health_endpoint(self, template):
        text = _read(CHART_DIR / "templates" / template)
        assert text.count("/api/health") == 2  # liveness + readiness

    @pytest.mark.parametrize("template", ["daemonset.yaml", "deployment.yaml"])
    def test_probes_target_named_dashboard_port(self, template):
        text = _read(CHART_DIR / "templates" / template)
        assert "port: dashboard" in text


class TestRedisTemplate:
    def test_redis_gated_on_values_redis_enabled(self):
        text = _read(CHART_DIR / "templates" / "redis.yaml")
        assert ".Values.redis.enabled" in text

    def test_redis_deployment_uses_recreate_strategy(self):
        """Recreate (not RollingUpdate) avoids two Redis pods briefly both
        claiming the same PVC during an upgrade."""
        text = _read(CHART_DIR / "templates" / "redis.yaml")
        assert "type: Recreate" in text


class TestSecretGeneration:
    def test_secret_supports_existing_secret_opt_out(self):
        text = _read(CHART_DIR / "templates" / "secret.yaml")
        assert ".Values.secrets.existingSecret" in text

    def test_secret_uses_lookup_for_upgrade_stability(self):
        """Secrets must not be re-randomized on every `helm upgrade` --
        that would invalidate every existing session/API token."""
        text = _read(CHART_DIR / "templates" / "secret.yaml")
        assert "lookup" in text
        assert "randAlphaNum" in text


class TestHelmignoreExists:
    def test_helmignore_present(self):
        assert (CHART_DIR / ".helmignore").exists()


class TestChartReadme:
    def test_readme_exists(self):
        assert (CHART_DIR / "README.md").exists()

    def test_readme_mentions_daemonset_rationale(self):
        text = _read(CHART_DIR / "README.md")
        assert "DaemonSet" in text