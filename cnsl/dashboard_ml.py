"""
cnsl/dashboard_ml.py -- ML false-positive feedback route.

Split out of cnsl/dashboard.py (same pattern as dashboard_html.py and
dashboard_correlation.py) to keep dashboard.py under its enforced
line-count budget.

Route:
  POST /api/ml/alerts/{alert_id}/false-positive
       Mark a recent ML anomaly alert as a false positive. See
       MLDetector.mark_false_positive() in cnsl/ml_detector.py for how
       this feeds back into training data.
"""

from __future__ import annotations

from typing import Any, Callable


def register_ml_feedback_routes(
    router:        Any,
    ml_detector:   Any,
    _require_auth: Callable,
    rbac:          Any,
    logger:        Any,
    _audit:        Callable,
    _rate_check:   Callable,
) -> None:
    """Attach the ML false-positive feedback route to `router`.

    Called once from start_dashboard(). `ml_detector` may be None (ML
    disabled) -- the handler degrades to a 400 rather than raising.
    """
    from aiohttp import web

    @router.post("/api/ml/alerts/{alert_id}/false-positive")
    async def api_ml_mark_false_positive(req: web.Request) -> web.Response:
        """
        Mark a recent ML anomaly alert as a false positive. Folds its
        feature vector back into training data (with extra weight) so
        similar patterns are treated as normal on the next retrain.
        """
        if (r := _rate_check(req)): return r
        payload, err = _require_auth(req)
        if err: return err
        if guard := rbac.require(payload["role"], "block:write"):   # analyst+
            return web.json_response(guard, status=403)
        if ml_detector is None:
            return web.json_response({"error": "ML not enabled"}, status=400)
        alert_id = req.match_info["alert_id"]
        err = ml_detector.mark_false_positive(alert_id)
        if err:
            return web.json_response({"error": err}, status=404)
        await logger.log("ml_false_positive_marked", {"alert_id": alert_id, "by": payload["sub"]})
        await _audit(req, payload, "ml_false_positive", target=alert_id)
        return web.json_response({"ok": True, "status": ml_detector.status()})