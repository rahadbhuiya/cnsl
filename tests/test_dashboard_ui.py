"""
tests/test_dashboard_ui.py -- structural validation of the dashboard's
embedded HTML/JS (cnsl/dashboard_html.py), specifically the UI added
for correlation-rules tuning, ML false-positive marking, the
multi-node hub, and fingerprint/graph campaign views.

These don't run a browser -- they check the served page actually
contains what the JS expects (matching element ids) and that the
embedded JavaScript is syntactically valid, which is exactly the class
of copy-paste error (an onclick calling a function that was never
defined, or referencing an element id that doesn't exist) that's easy
to introduce when hand-editing a large HTML-in-a-Python-string file.
"""

from __future__ import annotations

import re
import shutil
import subprocess

import pytest

from cnsl.dashboard_html import _HTML

_NODE_AVAILABLE = shutil.which("node") is not None


class TestNewTabsPresent:
    @pytest.mark.parametrize("tab_id", ["tab-correlation", "tab-hub", "tab-campaigns"])
    def test_tab_button_present(self, tab_id):
        assert f'id="{tab_id}"' in _HTML

    @pytest.mark.parametrize("page_id", ["page-correlation", "page-hub", "page-campaigns"])
    def test_page_div_present(self, page_id):
        assert f'id="{page_id}"' in _HTML

    def test_ml_alerts_table_has_actions_column(self):
        assert "ml-alerts-tbody" in _HTML
        assert "mlMarkFalsePositive" in _HTML


class TestNewTabsWiredIntoShowTab:
    def test_correlation_dispatches_to_loader(self):
        assert "name==='correlation'" in _HTML or 'name==="correlation"' in _HTML

    def test_hub_dispatches_to_loader(self):
        assert "name==='hub'" in _HTML or 'name==="hub"' in _HTML

    def test_campaigns_dispatches_to_loader(self):
        assert "name==='campaigns'" in _HTML or 'name==="campaigns"' in _HTML


class TestRequiredElementIdsExist:
    """Every element id the new JS functions read/write via $() must
    actually exist in the served HTML, or the UI silently breaks."""

    @pytest.mark.parametrize("element_id", [
        "correlation-tbody", "correlation-edit-panel", "correlation-edit-title",
        "correlation-edit-window", "correlation-edit-cooldown", "correlation-edit-confidence",
        "hub-summary", "hub-nodes-tbody", "hub-cross-tbody",
        "fp-clusters-tbody", "graph-campaigns-tbody",
    ])
    def test_element_id_present(self, element_id):
        assert f'id="{element_id}"' in _HTML


class TestNewJsFunctionsDefinedAndCalled:
    """Every new onclick handler must reference a function that's
    actually defined somewhere in the script -- the exact class of bug
    a copy-paste edit can silently introduce."""

    @pytest.mark.parametrize("fn", [
        "loadCorrelationRules", "enableCorrelationRule", "disableCorrelationRule",
        "openCorrelationEdit", "saveCorrelationRule", "resetCorrelationRule",
        "loadHub", "loadCampaigns", "mlMarkFalsePositive",
    ])
    def test_function_defined(self, fn):
        assert re.search(rf"(?:async\s+)?function\s+{re.escape(fn)}\s*\(", _HTML) is not None

    @pytest.mark.parametrize("fn", [
        "loadCorrelationRules", "loadHub", "loadCampaigns",
        "enableCorrelationRule", "disableCorrelationRule", "openCorrelationEdit",
        "mlMarkFalsePositive",
    ])
    def test_function_called_somewhere(self, fn):
        # Called either from an onclick="..." attribute or from showTab()'s dispatch.
        assert fn + "(" in _HTML


class TestScriptSyntaxValid:
    """Extracts the actual served <script> block and validates it with
    a real JS engine (Node) if available -- catches genuine syntax
    errors (mismatched braces/parens/quotes) that string-matching
    alone can't."""

    def _extract_main_script(self) -> str:
        blocks = re.findall(r"<script>(.*?)</script>", _HTML, re.DOTALL)
        # The dashboard's main script is by far the largest <script> block
        # (a small one exists on the login page).
        return max(blocks, key=len)

    @pytest.mark.skipif(not _NODE_AVAILABLE, reason="node not installed")
    def test_main_script_is_valid_javascript(self, tmp_path):
        script = self._extract_main_script()
        js_file = tmp_path / "dashboard_main.js"
        js_file.write_text(script, encoding="utf-8")
        result = subprocess.run(
            ["node", "--check", str(js_file)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"JS syntax error:\n{result.stderr}"

    def test_main_script_is_substantial(self):
        """Sanity check the extraction itself picked the real script,
        not the small login-page one."""
        assert len(self._extract_main_script()) > 10000


class TestDivBalance:
    """The dashboard's HTML has one pre-existing stray </div> in the
    Settings page (unrelated to correlation/hub/campaigns work -- noted
    here rather than fixed, since fixing it is a separate, unrelated
    change). This locks in that the imbalance doesn't get WORSE, and
    that newly added blocks are individually balanced."""

    def _without_scripts(self) -> str:
        return re.sub(r"<script>.*?</script>", "", _HTML, flags=re.DOTALL)

    def test_known_preexisting_imbalance_is_exactly_one(self):
        html = self._without_scripts()
        opens = html.count("<div")
        closes = html.count("</div>")
        assert closes - opens == 1, (
            f"div balance changed (opens={opens}, closes={closes}) -- if you fixed "
            f"the pre-existing stray </div> in Settings, update this test to assert "
            f"opens == closes instead."
        )

    def test_new_correlation_hub_campaigns_block_is_internally_balanced(self):
        """The block added for this session's UI work must not itself
        introduce any new imbalance."""
        import cnsl.dashboard_html as mod
        import inspect
        src = inspect.getsource(mod)
        start = src.index("<!-- CORRELATION RULES -->")
        end = src.index("<!-- RATE LIMIT -->")
        block = src[start:end]
        assert block.count("<div") == block.count("</div>")