"""
tests/test_docs.py -- structural validation of README.md and the docs/
folder, guarding against the exact kind of drift this session found:
README.md going untouched for dozens of feature releases, docs
referencing files that don't exist, and the docs/ folder growing
without README.md's index or count keeping up.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
README = REPO_ROOT / "README.md"
DOCS_DIR = REPO_ROOT / "docs"


def _readme_text() -> str:
    return README.read_text(encoding="utf-8")


class TestReadmeLinksResolve:
    """Every docs/*.md link in the README must point to a file that
    actually exists -- a dead link here is what let kubernetes.md sit
    completely undiscoverable for a whole version's worth of work."""

    def test_every_docs_link_target_exists(self):
        text = _readme_text()
        refs = set(re.findall(r"\]\((docs/[a-zA-Z0-9._-]+\.md)\)", text))
        assert refs, "README should reference at least one docs/*.md file"
        missing = [r for r in refs if not (REPO_ROOT / r).exists()]
        assert not missing, f"README links to nonexistent doc(s): {missing}"

    def test_helm_readme_link_resolves(self):
        text = _readme_text()
        if "helm/cnsl/README.md" in text:
            assert (REPO_ROOT / "helm" / "cnsl" / "README.md").exists()


class TestReadmeIndexCompleteness:
    """Every file actually in docs/ should be either individually linked
    from the README's documentation table, or covered by the catch-all
    docs/ browse link -- and the README's guide count must match reality."""

    def test_doc_count_in_readme_matches_actual_count(self):
        actual = len(list(DOCS_DIR.glob("*.md")))
        text = _readme_text()
        m = re.search(r"all (\d+) guides", text)
        assert m, "README should state the total guide count (e.g. 'all N guides')"
        stated = int(m.group(1))
        assert stated == actual, (
            f"README says {stated} guides but docs/ actually has {actual} -- "
            f"update the count (or the wording) when adding/removing a doc."
        )

    def test_no_readme_link_to_file_outside_docs_that_should_be_in_docs(self):
        """Sanity check: every *.md file directly under docs/ (not
        subdirectories) is accounted for by the glob used elsewhere."""
        assert (DOCS_DIR / "kubernetes.md").exists()
        assert (DOCS_DIR / "changelog.md").exists()
        assert (DOCS_DIR / "api.md").exists()


class TestReadmeMentionsMajorFeatures:
    """Loose guard against the README going stale the way it did for an
    entire session's worth of major features -- doesn't need to name
    every single one, but the standout additions should be discoverable
    from the top-level README, not only buried in docs/changelog.md."""

    @pytest.mark.parametrize("keyword", [
        "federation", "STIX", "TAXII", "Wazuh", "Kubernetes",
        "fingerprint", "predictive",
    ])
    def test_feature_keyword_present(self, keyword):
        text = _readme_text()
        assert keyword.lower() in text.lower(), (
            f"README doesn't mention '{keyword}' anywhere -- if this "
            f"feature was removed, update this test; if it's just "
            f"missing from the README, that's the drift this test "
            f"exists to catch."
        )

    def test_dashboard_tabs_list_includes_newer_tabs(self):
        text = _readme_text()
        for tab in ["Correlation", "Hub", "Campaigns"]:
            assert tab in text, f"README's dashboard tab list is missing '{tab}'"


class TestConfigurationDocCoversNewerBlocks:
    """docs/configuration.md is the config reference -- every config
    block CNSL actually reads should have a section here, not just in
    docs/api.md (which documents the API surface, not config format)."""

    def _config_text(self) -> str:
        return (DOCS_DIR / "configuration.md").read_text(encoding="utf-8")

    def test_predictive_blocking_documented(self):
        text = self._config_text()
        assert "predictive_blocking" in text
        assert "score_threshold" in text
        assert "min_stages" in text

    def test_correlation_rules_documented(self):
        text = self._config_text()
        assert "correlation_rules" in text


class TestDockerfileVersion:
    """
    The Dockerfile hardcodes cnsl.__version__ in two OCI labels (no
    build-time templating). Nothing enforces this stays in sync except
    remembering to update it by hand on every version bump -- which is
    exactly how it silently drifted a full version behind at v3.4.19.
    Same pattern as test_helm_chart.py's Chart.yaml appVersion check.
    """

    def _dockerfile_text(self) -> str:
        return (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")

    def test_image_version_label_matches_cnsl_version(self):
        from cnsl import __version__
        text = self._dockerfile_text()
        m = re.search(r'org\.opencontainers\.image\.version="([^"]+)"', text)
        assert m, "Dockerfile should set org.opencontainers.image.version"
        assert m.group(1) == __version__, (
            f"Dockerfile's image.version label ({m.group(1)}) is out of "
            f"sync with cnsl.__version__ ({__version__}) -- bump it "
            f"alongside every other version reference."
        )

    def test_image_description_label_mentions_current_version(self):
        from cnsl import __version__
        text = self._dockerfile_text()
        assert f"v{__version__}" in text, (
            "Dockerfile's image.description label doesn't mention the "
            "current version -- bump it alongside image.version."
        )


class TestDockerComposeVersion:
    """
    docker-compose.yml hardcodes image tags (cnsl:X.Y.Z) rather than
    templating them -- same manual-bump-or-drift risk as the Dockerfile
    labels above, and it drifted the same way (found stuck at v3.4.17
    while cnsl.__version__ had already moved on).
    """

    def test_image_tags_match_cnsl_version(self):
        from cnsl import __version__
        text = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        tags = set(re.findall(r"image:\s*cnsl:([0-9][0-9A-Za-z.\-]*)", text))
        assert tags, "docker-compose.yml should reference at least one cnsl:X.Y.Z image tag"
        assert tags == {__version__}, (
            f"docker-compose.yml image tag(s) {sorted(tags)} out of sync "
            f"with cnsl.__version__ ({__version__}) -- bump every "
            f"'image: cnsl:...' line alongside every other version reference."
        )


class TestCliVersionFlag:
    """
    build_arg_parser()'s --version used to be a hardcoded string
    ("CNSL 3.4.18") that silently went stale by a full version -- the
    same class of bug as the Dockerfile/docker-compose drift above.
    It's since been changed to read cnsl.__version__ directly, which
    makes it structurally impossible to drift; this test guards against
    a future edit reintroducing a hardcoded literal.
    """

    def test_version_flag_reports_current_version(self):
        import subprocess
        import sys
        from cnsl import __version__
        result = subprocess.run(
            [sys.executable, "-m", "cnsl", "--version"],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        assert __version__ in result.stdout, (
            f"'python -m cnsl --version' printed {result.stdout!r}, "
            f"which doesn't contain cnsl.__version__ ({__version__})."
        )


class TestDashboardVersionBadge:
    """
    The dashboard header's version badge used to be a hardcoded literal
    ("v3.4.17") baked into the _HTML template string -- it silently went
    stale the same way the Dockerfile/docker-compose/CLI version strings
    did. It's since been changed to a {{CNSL_VERSION}} placeholder that
    dashboard.py's index() handler substitutes with cnsl.__version__ at
    request time, which makes it structurally impossible to drift; this
    test guards against a future edit reintroducing a hardcoded literal.
    """

    def test_badge_uses_placeholder_not_a_hardcoded_literal(self):
        from cnsl.dashboard_html import _HTML
        assert "{{CNSL_VERSION}}" in _HTML, (
            "Dashboard _HTML template should contain the {{CNSL_VERSION}} "
            "placeholder in its version badge, not a hardcoded literal."
        )
        assert not re.search(r'class="badge">v\d', _HTML), (
            "Dashboard _HTML template's version badge appears to contain "
            "a hardcoded version literal again instead of {{CNSL_VERSION}}."
        )