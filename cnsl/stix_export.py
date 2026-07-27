"""
cnsl/stix_export.py — STIX 2.1 bundle export of detected attacker IPs.

Turns CNSL's own detections (store.top_attackers()) into a standard
STIX 2.1 bundle: one Indicator object per attacker IP, plus an Identity
object identifying CNSL as the producer. This is what feeds both:

  - GET /api/export/stix          -- a downloadable bundle file
  - GET /taxii2/.../objects/      -- the minimal read-only TAXII 2.1
                                     server (cnsl/taxii.py), so any
                                     TAXII 2.1 client (SOAR, TIP, other
                                     SIEMs) can pull CNSL's IOCs
                                     automatically.

STIX 2.1 spec: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
This module only produces Indicator + Identity objects (the subset
relevant to "IPs we've seen attacking us") -- it does not attempt
full STIX coverage (Malware, Campaign, Attack-Pattern, etc.).
"""

from __future__ import annotations

import hashlib
import ipaddress
import uuid
from typing import Any, Dict, List, Optional

from .models import iso_time

_IDENTITY_ID = "identity--b3b5c9c0-0a58-4f2e-9b1a-9c0e2f3a4b5c"


def _severity_to_confidence(severity: Optional[str]) -> int:
    """Map CNSL severity to a STIX confidence score (0-100)."""
    return {"HIGH": 85, "MEDIUM": 60, "LOW": 35}.get((severity or "").upper(), 50)


def _ip_pattern(ip: str) -> Optional[str]:
    """Build a STIX pattern expression for an IPv4 or IPv6 address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    kind = "ipv6-addr" if addr.version == 6 else "ipv4-addr"
    return f"[{kind}:value = '{ip}']"


def _deterministic_indicator_id(ip: str) -> str:
    """
    Derive a stable indicator--<uuid> for a given IP, so re-exporting
    the same IP always yields the same STIX object id (lets consumers
    dedupe/update rather than accumulate duplicates across pulls).
    """
    digest  = hashlib.sha256(f"cnsl-indicator:{ip}".encode()).hexdigest()
    derived = uuid.UUID(digest[:32])
    return f"indicator--{derived}"


def cnsl_identity_object() -> Dict[str, Any]:
    """The STIX Identity object representing this CNSL instance as the
    producer of every Indicator it exports."""
    return {
        "type":          "identity",
        "spec_version":  "2.1",
        "id":            _IDENTITY_ID,
        "created":       "2026-01-01T00:00:00.000Z",
        "modified":      "2026-01-01T00:00:00.000Z",
        "name":          "CNSL",
        "identity_class":"system",
        "description":   "Correlated Network Security Layer -- self-hosted SIEM",
    }


def indicator_from_attacker(attacker: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Build a STIX Indicator object from one row of store.top_attackers():
    {src_ip, flag, country, city, isp, incident_count, max_severity,
     first_seen, last_seen}.

    Returns None if src_ip is missing/unparseable (skipped by the
    caller rather than raising, so one bad row doesn't kill an export).
    """
    ip = attacker.get("src_ip")
    if not ip:
        return None
    pattern = _ip_pattern(ip)
    if pattern is None:
        return None

    first_seen = attacker.get("first_seen") or attacker.get("last_seen")
    last_seen  = attacker.get("last_seen") or first_seen
    count      = attacker.get("incident_count", 1)
    severity   = attacker.get("max_severity")
    country    = attacker.get("country")

    location_note = f" (seen from {country})" if country else ""
    description = (
        f"IP flagged by CNSL after {count} incident(s){location_note}. "
        f"Highest observed severity: {severity or 'UNKNOWN'}."
    )

    created_ts  = first_seen if isinstance(first_seen, (int, float)) else None
    modified_ts = last_seen  if isinstance(last_seen,  (int, float)) else None

    return {
        "type":            "indicator",
        "spec_version":    "2.1",
        "id":              _deterministic_indicator_id(ip),
        "created":         iso_time(created_ts) if created_ts is not None else iso_time(),
        "modified":        iso_time(modified_ts) if modified_ts is not None else iso_time(),
        "created_by_ref":  _IDENTITY_ID,
        "name":            f"Malicious IP: {ip}",
        "description":     description,
        "indicator_types": ["malicious-activity"],
        "pattern":         pattern,
        "pattern_type":    "stix",
        "valid_from":      iso_time(created_ts) if created_ts is not None else iso_time(),
        "confidence":      _severity_to_confidence(severity),
        "labels":          [f"cnsl-severity-{(severity or 'unknown').lower()}"],
    }


def build_stix_bundle(attackers: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a full STIX 2.1 bundle from a list of top_attackers()-shaped
    rows. Always includes the CNSL Identity object; skips any row whose
    IP is missing or unparseable rather than failing the whole export.
    """
    objects: List[Dict[str, Any]] = [cnsl_identity_object()]
    for attacker in attackers:
        indicator = indicator_from_attacker(attacker)
        if indicator is not None:
            objects.append(indicator)

    return {
        "type":    "bundle",
        "id":      f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }