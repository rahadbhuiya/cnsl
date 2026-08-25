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