"""
cnsl/dashboard_attack.py -- MITRE ATT&CK coverage API route.

Split out of cnsl/dashboard.py (same pattern as dashboard_hub.py,
dashboard_sigma.py, ...) to keep dashboard.py under its enforced
line-count budget.

Route:
  GET /api/attack/coverage   Aggregate ATT&CK technique coverage across
                             built-in rules, correlation rules, and
                             currently-imported Sigma rules.

See cnsl/attack.py for the technique reference table and the
aggregation logic itself -- this module is just the thin route wrapper.
"""

from __future__ import annotations

from typing import Any, Callable


def register_attack_routes(
    router:        Any,
    detector:      Any,
    correlator:    Any,
    sigma:         Any,
    _require_auth: Callable,
    _rate_check:   Callable,
) -> None:
    """Attach /api/attack/coverage to `router`.

    Called once from start_dashboard(). Each of detector/correlator/sigma
    may be None -- the report is built from whichever sources are
    actually wired up, never raises for a missing one.
    """
    from aiohttp import web
    from .attack import build_coverage_report

    @router.get("/api/attack/coverage")
    async def api_attack_coverage(req: web.Request) -> web.Response:
        """
        Which MITRE ATT&CK techniques does this deployment currently
        have coverage for, and from which rule(s)? Only enabled rules
        count -- a disabled rule isn't actually watching right now.
        """
        if (r := _rate_check(req)): return r
        _, err = _require_auth(req)
        if err: return err

        builtin_rules = detector.rules.all_rules() if detector is not None else []
        corr_rules    = correlator.all_rules() if correlator is not None else []
        sigma_rules   = sigma.all_rules() if sigma is not None else []

        report = build_coverage_report(
            builtin_rules=builtin_rules,
            correlation_rules=corr_rules,
            sigma_rules=sigma_rules,
        )
        return web.json_response(report)