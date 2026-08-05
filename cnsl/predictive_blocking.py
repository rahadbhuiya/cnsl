"""
cnsl/predictive_blocking.py — Block on kill-chain trajectory, not just
single-rule thresholds.

Every other blocking decision in CNSL fires when ONE rule's own
threshold is crossed (e.g. "5 SSH fails in 60s"). That's precise, but
it means an attacker who spreads their steps across *different* attack
types -- recon, then a web exploit attempt, then a credential-stuffing
attempt, none of which individually reaches its own rule's threshold --
can walk most of the way through the kill chain without ever tripping a
single rule.

Predictive blocking looks at the *shape* of what an IP has done so far
(cnsl.kill_chain.KillChain -- its score and how many distinct stages
it's touched) rather than any one rule's count, and blocks early when
that trajectory looks like a real attack in progress. This deliberately
trades a bit of precision for reacting before the attacker reaches
Actions-on-Objectives, not after.

Usage (wired into detector.py's _kc_update, the single choke point
every kill-chain-relevant event already passes through):
    reason = should_predictively_block(chain, cfg)
    if reason:
        await blocker.block_ip(chain.ip, reason=reason)

Blocker.block_ip() is already idempotent (skips allowlisted/already-
blocked IPs), so this never double-blocks or needs its own dedup state.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .kill_chain import KillChain, STAGE_NAMES

_DEFAULTS = {
    "enabled":         False,  # opt-in -- this trades precision for speed
    "score_threshold": 0.60,
    "min_stages":      2,
}


def _config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    pb_cfg = dict(_DEFAULTS)
    pb_cfg.update(cfg.get("predictive_blocking", {}) or {})
    return pb_cfg


def should_predictively_block(
    chain: Optional[KillChain],
    cfg: Dict[str, Any],
) -> Optional[str]:
    """
    Return a block reason string if `chain`'s trajectory warrants
    blocking now, or None if not (feature disabled, chain missing, or
    thresholds not yet met).

    Two conditions must BOTH hold, not just a high score alone -- a
    single very-late-stage event (e.g. one HIGH-severity hit) can spike
    `score` without the IP having shown a real multi-step pattern:
      1. chain.score >= score_threshold
      2. chain has touched at least min_stages distinct stages
    """
    if chain is None:
        return None

    pb_cfg = _config(cfg)
    if not pb_cfg["enabled"]:
        return None

    if chain.score < pb_cfg["score_threshold"]:
        return None
    if len(chain.stages) < pb_cfg["min_stages"]:
        return None

    stage_names = ", ".join(
        STAGE_NAMES.get(s, str(s)) for s in sorted(chain.stages.keys())
    )
    return (
        f"predictive: kill-chain score {chain.score:.2f} across "
        f"{len(chain.stages)} stages ({stage_names})"
    )