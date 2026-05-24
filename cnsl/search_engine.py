"""
cnsl/search_engine.py — Search & Query Engine for CNSL events.

Provides:
  - Full-text search across incidents (IP, country, ISP, reasons)
  - Time-range filtering
  - Field-based filtering (severity, src_ip, country, kind)
  - Aggregations (top IPs, top countries, hourly buckets)
  - KQL-inspired simple query syntax
  - Elasticsearch/OpenSearch bulk push (optional)

This sits on top of SQLite (always available) with optional
Elasticsearch/OpenSearch as a secondary index for scale.

KQL-like query syntax supported in /api/search:
  src_ip:1.2.3.4
  severity:HIGH
  country:China
  reasons:brute_force
  1.2.3.4                  (bare term — matches any field)
  severity:HIGH country:China   (AND — all terms must match)

Config:
  "search": {
    "elasticsearch": {
      "enabled":  false,
      "url":      "http://localhost:9200",
      "index":    "cnsl-events",
      "username": "",
      "password": "",
      "timeout_sec": 5
    }
  }
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple



# KQL-like query parser


# Supported field names and their SQLite column equivalents
_FIELD_MAP = {
    "src_ip":   "src_ip",
    "ip":       "src_ip",
    "severity": "severity",
    "sev":      "severity",
    "country":  "country",
    "city":     "city",
    "isp":      "isp",
    "reasons":  "reasons",
    "reason":   "reasons",
}

_KQL_TERM_RE = re.compile(
    r'(?:(?P<field>\w+):)?(?P<value>"[^"]*"|\S+)'
)


def parse_query(query: str) -> List[Tuple[Optional[str], str]]:
    """
    Parse a KQL-like query string into (field, value) pairs.

    Examples:
      "1.2.3.4"              → [(None, "1.2.3.4")]
      "severity:HIGH"        → [("severity", "HIGH")]
      "severity:HIGH country:China"  → [("severity","HIGH"), ("country","China")]
      'reasons:"brute force"' → [("reasons", "brute force")]
    """
    terms = []
    for m in _KQL_TERM_RE.finditer(query.strip()):
        field = m.group("field")
        value = m.group("value").strip('"')
        if not value:
            continue
        # Map alias to real column name
        if field:
            field = _FIELD_MAP.get(field.lower(), field.lower())
        terms.append((field, value))
    return terms


def build_sql_filter(
    terms:       List[Tuple[Optional[str], str]],
    since_ts:    Optional[float] = None,
    until_ts:    Optional[float] = None,
    severity:    Optional[str]   = None,
) -> Tuple[str, List[Any]]:
    """
    Convert parsed query terms + filters into a SQL WHERE clause.
    Returns (where_clause_str, params_list).
    """
    clauses: List[str] = []
    params:  List[Any] = []

    # Time range
    if since_ts is not None:
        clauses.append("ts >= ?")
        params.append(since_ts)
    if until_ts is not None:
        clauses.append("ts <= ?")
        params.append(until_ts)

    # Explicit severity filter (from query param)
    if severity:
        clauses.append("UPPER(severity) = UPPER(?)")
        params.append(severity)

    # Query terms
    for field, value in terms:
        val_like = f"%{value}%"
        if field is None:
            # Bare term — search across all text fields
            clauses.append(
                "(src_ip LIKE ? OR UPPER(severity) = UPPER(?)"
                " OR country LIKE ? OR isp LIKE ? OR reasons LIKE ?)"
            )
            params.extend([val_like, value, val_like, val_like, val_like])
        elif field == "severity":
            clauses.append("UPPER(severity) = UPPER(?)")
            params.append(value)
        elif field == "src_ip":
            clauses.append("src_ip LIKE ?")
            params.append(val_like)
        elif field in ("country", "city", "isp"):
            clauses.append(f"{field} LIKE ?")
            params.append(val_like)
        elif field == "reasons":
            clauses.append("reasons LIKE ?")
            params.append(val_like)
        else:
            # Unknown field — try as a generic LIKE on reasons
            clauses.append("reasons LIKE ?")
            params.append(val_like)

    where = "WHERE " + " AND ".join(clauses) if clauses else ""
    return where, params



# SQLite search engine


class SearchEngine:
    """
    Full-text search and aggregation engine over CNSL's SQLite store.

    All methods are async but run SQL synchronously via aiosqlite.
    Falls back gracefully when aiosqlite is not installed.
    """

    def __init__(self, db_path: str, es_cfg: Optional[Dict] = None):
        self._db_path = db_path
        self._es_cfg  = es_cfg or {}
        self._db      = None
        self._available = False

    async def init(self) -> bool:
        try:
            import aiosqlite
            self._db = await aiosqlite.connect(self._db_path)
            self._db.row_factory = aiosqlite.Row
            self._available = True
            return True
        except ImportError:
            return False
        except Exception:
            return False

    @property
    def available(self) -> bool:
        return self._available

    async def search(
        self,
        query:    str        = "",
        since:    Optional[float] = None,
        until:    Optional[float] = None,
        severity: Optional[str]   = None,
        limit:    int         = 100,
        offset:   int         = 0,
    ) -> Dict[str, Any]:
        """
        Execute a search query. Returns:
          {
            "total":  int,
            "hits":   [...incident dicts...],
            "took_ms": float
          }
        """
        if not self._available or self._db is None:
            return {"total": 0, "hits": [], "took_ms": 0}

        t0     = time.monotonic()
        terms  = parse_query(query) if query.strip() else []
        where, params = build_sql_filter(
            terms, since_ts=since, until_ts=until, severity=severity
        )

        limit  = max(1, min(limit, 1000))
        offset = max(0, offset)

        # Count total matches
        count_sql = f"SELECT COUNT(*) FROM incidents {where}"
        async with self._db.execute(count_sql, params) as cur:
            row   = await cur.fetchone()
            total = row[0] if row else 0

        # Fetch page
        data_sql = (
            f"SELECT * FROM incidents {where} "
            f"ORDER BY ts DESC LIMIT ? OFFSET ?"
        )
        async with self._db.execute(data_sql, params + [limit, offset]) as cur:
            rows = await cur.fetchall()

        hits = []
        for row in rows:
            d = dict(row)
            try:
                d["reasons"] = json.loads(d["reasons"])
            except Exception:
                pass
            hits.append(d)

        took_ms = round((time.monotonic() - t0) * 1000, 2)
        return {"total": total, "hits": hits, "took_ms": took_ms}

    async def aggregate(
        self,
        since:    Optional[float] = None,
        until:    Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Return aggregations useful for analytics:
          - by_severity:  {HIGH: N, MEDIUM: N, LOW: N}
          - top_ips:      [{src_ip, count, country}, ...]
          - top_countries:{country: count, ...}
          - hourly:       [{hour_ts, count}, ...]  (last 24h)
        """
        if not self._available or self._db is None:
            return {}

        base_where = "WHERE 1=1"
        base_params: List[Any] = []
        if since is not None:
            base_where += " AND ts >= ?"
            base_params.append(since)
        if until is not None:
            base_where += " AND ts <= ?"
            base_params.append(until)

        result: Dict[str, Any] = {}

        # Severity breakdown
        async with self._db.execute(
            f"""SELECT severity, COUNT(*) as cnt FROM incidents
                {base_where} GROUP BY severity""",
            base_params,
        ) as cur:
            rows = await cur.fetchall()
        result["by_severity"] = {r["severity"]: r["cnt"] for r in rows}

        # Top 10 attacking IPs
        async with self._db.execute(
            f"""SELECT src_ip, country, COUNT(*) as cnt FROM incidents
                {base_where}
                GROUP BY src_ip ORDER BY cnt DESC LIMIT 10""",
            base_params,
        ) as cur:
            rows = await cur.fetchall()
        result["top_ips"] = [dict(r) for r in rows]

        # Top 10 countries
        async with self._db.execute(
            f"""SELECT country, COUNT(*) as cnt FROM incidents
                {base_where} AND country IS NOT NULL
                GROUP BY country ORDER BY cnt DESC LIMIT 10""",
            base_params,
        ) as cur:
            rows = await cur.fetchall()
        result["top_countries"] = {r["country"]: r["cnt"] for r in rows}

        # Hourly buckets — use provided range or last 30 days
        hourly_cutoff = since if since is not None else (time.time() - 30 * 86400)
        async with self._db.execute(
            """SELECT
                 CAST(ts / 3600 AS INTEGER) * 3600 AS hour_ts,
                 COUNT(*) as cnt
               FROM incidents
               WHERE ts >= ?
               GROUP BY hour_ts
               ORDER BY hour_ts""",
            (hourly_cutoff,),
        ) as cur:
            rows = await cur.fetchall()
        result["hourly"] = [dict(r) for r in rows]

        return result

    async def close(self) -> None:
        if self._db:
            try:
                await self._db.close()
            except Exception:
                pass



# Optional Elasticsearch / OpenSearch push


class ElasticsearchPusher:
    """
    Pushes normalized CNSL events to Elasticsearch or OpenSearch.

    Only used when search.elasticsearch.enabled=true in config.
    Does not replace SQLite — it's an additional secondary index.

    Usage:
        pusher = ElasticsearchPusher(cfg)
        await pusher.push(normalized_events)
    """

    def __init__(self, cfg: Dict[str, Any]):
        es = cfg.get("search", {}).get("elasticsearch", {})
        self.enabled  = bool(es.get("enabled", False))
        self.url      = es.get("url", "http://localhost:9200").rstrip("/")
        self.index    = es.get("index", "cnsl-events")
        self.username = es.get("username", "")
        self.password = es.get("password", "")
        self.timeout  = int(es.get("timeout_sec", 5))
        self._session = None

    async def _get_session(self):
        if self._session is None:
            try:
                import aiohttp
                auth = None
                if self.username:
                    auth = aiohttp.BasicAuth(self.username, self.password)
                self._session = aiohttp.ClientSession(
                    auth=auth,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                )
            except ImportError:
                return None
        return self._session

    async def health(self) -> Dict[str, Any]:
        """Check Elasticsearch cluster health."""
        session = await self._get_session()
        if not session:
            return {"error": "aiohttp not installed"}
        try:
            async with session.get(f"{self.url}/_cluster/health") as resp:
                return await resp.json()
        except Exception as e:
            return {"error": str(e)}

    async def push(self, normalized_events: list) -> Dict[str, Any]:
        """
        Bulk-index a list of NormalizedEvent objects.
        Returns Elasticsearch bulk response summary.
        """
        if not self.enabled or not normalized_events:
            return {"pushed": 0}

        session = await self._get_session()
        if not session:
            return {"error": "aiohttp not installed"}

        # Build NDJSON bulk body
        lines = []
        for norm in normalized_events:
            action = json.dumps({"index": {"_index": self.index}})
            doc    = norm.to_ecs_json()
            lines.append(action)
            lines.append(doc)

        body = "\n".join(lines) + "\n"

        try:
            async with session.post(
                f"{self.url}/_bulk",
                data=body,
                headers={"Content-Type": "application/x-ndjson"},
            ) as resp:
                result = await resp.json()
                errors = result.get("errors", False)
                items  = result.get("items", [])
                pushed = sum(1 for i in items if i.get("index", {}).get("result") in ("created", "updated"))
                return {
                    "pushed": pushed,
                    "errors": errors,
                    "total":  len(items),
                }
        except Exception as e:
            return {"error": str(e), "pushed": 0}

    async def close(self) -> None:
        if self._session:
            try:
                await self._session.close()
            except Exception:
                pass