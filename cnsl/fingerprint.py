"""
cnsl/fingerprint.py — Attacker fingerprinting & cross-IP actor clustering.

The same attacker frequently rotates through many IPs (VPN exits, botnet
nodes, cloud-provider churn) while their *behavior* stays recognizable:
the same mix of attack types, the same timing rhythm (bots tend to hit
at suspiciously regular intervals; humans don't), the same TTP keywords
in the reasons CNSL already logged for each incident. This module builds
a compact behavioral fingerprint per IP from its incident history and
finds/clusters IPs whose fingerprints are similar enough to plausibly be
the same actor -- e.g. "this attack from 45.33.32.1 looks like the same
actor as last week's 91.108.4.88".

This is deliberately NOT machine learning -- no training, no model file,
nothing that needs sklearn. It's a similarity metric over hand-picked
behavioral features, computed fresh from whatever's in the incidents
table. That keeps it fast, dependency-free, and easy to reason about
(every score traces back to features you can print and sanity-check).

Usage:
    fps = build_fingerprints(await store.recent_incidents(limit=5000))
    clusters = cluster_attackers(fps, threshold=0.80)
    similar = find_similar("45.33.32.1", fps, threshold=0.75)
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# The event kinds we track a distribution over. Any kind not in this list
# still counts toward totals but is folded into "other" in the ratio
# vector, so an unfamiliar future event kind doesn't break scoring.
_TRACKED_KINDS = [
    "SSH_FAIL", "SSH_SUCCESS", "WEB_SCAN", "DB_FAIL", "FW_HONEYPOT_PORT",
    "WAZUH_ALERT", "OT_MODBUS_SCAN", "OT_SCADA_ALARM",
]

_SEVERITY_WEIGHT = {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3}

# Minimum incidents before a fingerprint is considered reliable enough to
# cluster on -- a single incident tells you almost nothing about rhythm.
MIN_INCIDENTS_FOR_FINGERPRINT = 3


@dataclass
class AttackerFingerprint:
    ip:                str
    incident_count:    int
    first_seen:        float
    last_seen:         float

    # Normalized ratios (sum to ~1.0), in _TRACKED_KINDS order + "other".
    kind_ratios:       List[float] = field(default_factory=list)

    # Timing rhythm: mean and coefficient of variation of inter-incident
    # intervals. Low CV (regular spacing) reads as automated/scripted;
    # a single incident has no interval and gets cv=0.0, mean=0.0.
    mean_interval_sec: float = 0.0
    interval_cv:       float = 0.0

    # Average severity weight (HIGH=1.0 .. LOW=0.3) across incidents.
    avg_severity:      float = 0.0

    # Coarse TTP signature: distinct "reason" keywords (the part before
    # the first ":" in each reason string CNSL already logs, e.g.
    # "brute_force", "sql_injection", "wazuh") seen for this IP.
    reason_keywords:   frozenset = field(default_factory=frozenset)

    # Average unique users touched per incident (credential-stuffing
    # signature: many distinct usernames vs. one repeatedly).
    avg_uniq_users:    float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip":                self.ip,
            "incident_count":    self.incident_count,
            "first_seen":        self.first_seen,
            "last_seen":         self.last_seen,
            "kind_ratios":       {k: round(v, 3) for k, v in
                                   zip(_TRACKED_KINDS + ["other"], self.kind_ratios)},
            "mean_interval_sec": round(self.mean_interval_sec, 1),
            "interval_cv":       round(self.interval_cv, 3),
            "avg_severity":      round(self.avg_severity, 3),
            "reason_keywords":   sorted(self.reason_keywords),
            "avg_uniq_users":    round(self.avg_uniq_users, 2),
        }


def _reason_keyword(reason: str) -> str:
    """Extract the coarse category from a reason string like
    "brute_force: 5 fails in 60s" -> "brute_force"."""
    return reason.split(":", 1)[0].strip().lower() if reason else "unknown"


def build_fingerprint(ip: str, incidents: List[Dict[str, Any]]) -> Optional[AttackerFingerprint]:
    """
    Build a behavioral fingerprint for one IP from its incident rows
    (each shaped like store.recent_incidents()'s output: ts, kind,
    severity, reasons, uniq_users, ...).

    Returns None if there are fewer than MIN_INCIDENTS_FOR_FINGERPRINT
    incidents -- too little data to fingerprint reliably.
    """
    if len(incidents) < MIN_INCIDENTS_FOR_FINGERPRINT:
        return None

    incidents = sorted(incidents, key=lambda r: r.get("ts", 0))
    timestamps = [float(r.get("ts", 0)) for r in incidents]

    kind_counts: Counter = Counter()
    for r in incidents:
        kind = r.get("kind", "")
        kind_counts[kind if kind in _TRACKED_KINDS else "other"] += 1
    total = sum(kind_counts.values()) or 1
    kind_ratios = [kind_counts.get(k, 0) / total for k in _TRACKED_KINDS]
    kind_ratios.append(kind_counts.get("other", 0) / total)

    intervals = [b - a for a, b in zip(timestamps, timestamps[1:]) if b > a]
    if intervals:
        mean_interval = sum(intervals) / len(intervals)
        if len(intervals) > 1 and mean_interval > 0:
            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            interval_cv = math.sqrt(variance) / mean_interval
        else:
            interval_cv = 0.0
    else:
        mean_interval = 0.0
        interval_cv = 0.0

    severities = [_SEVERITY_WEIGHT.get(str(r.get("severity", "")).upper(), 0.3) for r in incidents]
    avg_severity = sum(severities) / len(severities)

    keywords: set = set()
    for r in incidents:
        for reason in (r.get("reasons") or []):
            keywords.add(_reason_keyword(reason))

    uniq_users_vals = [float(r.get("uniq_users", 0) or 0) for r in incidents]
    avg_uniq_users = sum(uniq_users_vals) / len(uniq_users_vals)

    return AttackerFingerprint(
        ip=ip,
        incident_count=len(incidents),
        first_seen=timestamps[0],
        last_seen=timestamps[-1],
        kind_ratios=kind_ratios,
        mean_interval_sec=mean_interval,
        interval_cv=interval_cv,
        avg_severity=avg_severity,
        reason_keywords=frozenset(keywords),
        avg_uniq_users=avg_uniq_users,
    )


def build_fingerprints(incidents: List[Dict[str, Any]]) -> Dict[str, AttackerFingerprint]:
    """Group incidents by src_ip and build a fingerprint for each IP
    with enough history. IPs below MIN_INCIDENTS_FOR_FINGERPRINT are
    omitted from the result."""
    by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in incidents:
        ip = r.get("src_ip")
        if ip:
            by_ip[ip].append(r)

    result: Dict[str, AttackerFingerprint] = {}
    for ip, rows in by_ip.items():
        fp = build_fingerprint(ip, rows)
        if fp is not None:
            result[ip] = fp
    return result


def _cosine(a: List[float], b: List[float]) -> float:
    dot   = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def _jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 1.0  # both empty -- no keywords is itself a (weak) match
    union = a | b
    if not union:
        return 1.0
    return len(a & b) / len(union)


def similarity(fp1: AttackerFingerprint, fp2: AttackerFingerprint) -> float:
    """
    Similarity score in [0.0, 1.0] between two attacker fingerprints,
    combining:
      - cosine similarity of kind_ratios (what they attack)          40%
      - closeness of timing rhythm (mean_interval_sec, interval_cv)  25%
      - Jaccard similarity of reason_keywords (TTP signature)        25%
      - closeness of avg_severity                                   10%

    Weights are heuristic, not learned -- tune _WEIGHTS below if a
    deployment's data suggests a different balance matters more.
    """
    kind_sim = _cosine(fp1.kind_ratios, fp2.kind_ratios)

    # Timing: compare on a normalized scale so a 2s vs 4s gap (100% off,
    # clearly different) isn't drowned out by two very slow, similar
    # attackers both averaging ~500s apart.
    def _closeness(a: float, b: float) -> float:
        if a == 0 and b == 0:
            return 1.0
        return 1.0 - min(1.0, abs(a - b) / max(a, b, 1e-9))

    interval_sim = _closeness(fp1.mean_interval_sec, fp2.mean_interval_sec)
    cv_sim       = _closeness(fp1.interval_cv, fp2.interval_cv)
    timing_sim   = (interval_sim + cv_sim) / 2

    keyword_sim  = _jaccard(fp1.reason_keywords, fp2.reason_keywords)
    severity_sim = _closeness(fp1.avg_severity, fp2.avg_severity)

    return (
        0.40 * kind_sim +
        0.25 * timing_sim +
        0.25 * keyword_sim +
        0.10 * severity_sim
    )


def find_similar(
    ip: str,
    fingerprints: Dict[str, AttackerFingerprint],
    threshold: float = 0.75,
    limit: int = 20,
) -> List[Tuple[str, float]]:
    """Return [(other_ip, score), ...] for every other IP whose
    fingerprint similarity to `ip` meets `threshold`, sorted by score
    descending. Returns [] if `ip` has no fingerprint (not enough
    incident history)."""
    target = fingerprints.get(ip)
    if target is None:
        return []

    scored = []
    for other_ip, fp in fingerprints.items():
        if other_ip == ip:
            continue
        score = similarity(target, fp)
        if score >= threshold:
            scored.append((other_ip, score))

    scored.sort(key=lambda t: t[1], reverse=True)
    return scored[:limit]


def cluster_attackers(
    fingerprints: Dict[str, AttackerFingerprint],
    threshold: float = 0.80,
) -> List[List[str]]:
    """
    Group IPs into clusters of probable same-actor behavior using
    union-find over pairwise similarity >= threshold. O(n^2) in the
    number of fingerprinted IPs -- fine for the hundreds-to-low-
    thousands range a self-hosted SIEM's incident table realistically
    holds; callers should cap the incident window (e.g.
    store.recent_incidents(limit=5000)) rather than fingerprint an
    unbounded history.

    Returns only clusters with 2+ IPs -- a cluster of one isn't a
    cluster, it's just an unmatched attacker.
    """
    ips = list(fingerprints.keys())
    parent = {ip: ip for ip in ips}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x: str, y: str) -> None:
        rx, ry = find(x), find(y)
        if rx != ry:
            parent[rx] = ry

    for i, ip_a in enumerate(ips):
        for ip_b in ips[i + 1:]:
            if similarity(fingerprints[ip_a], fingerprints[ip_b]) >= threshold:
                union(ip_a, ip_b)

    groups: Dict[str, List[str]] = defaultdict(list)
    for ip in ips:
        groups[find(ip)].append(ip)

    clusters = [sorted(members) for members in groups.values() if len(members) >= 2]
    clusters.sort(key=len, reverse=True)
    return clusters