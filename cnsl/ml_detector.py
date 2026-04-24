"""
cnsl/ml_detector.py — ML-based anomaly detection.

Uses scikit-learn IsolationForest to learn each server's normal
behavior and flag statistical outliers — attacks that evade
fixed thresholds.

How it works:
  1. Collect features per IP per time-window:
       - fail rate (fails/minute)
       - unique user count
       - hour of day (0-23)
       - day of week (0-6)
       - inter-event interval (seconds between events)
       - source diversity (how many log sources)
       - web/ssh/db event ratio
  2. After MIN_SAMPLES observations, train IsolationForest
  3. Score each new window — anomaly_score < threshold = alert
  4. Retrain periodically as behavior evolves

Why IsolationForest:
  - No labeled data needed (unsupervised)
  - Works well on small datasets (100-1000 samples)
  - Fast inference (< 1ms per prediction)
  - Interpretable contamination parameter

Config:
  "ml": {
    "enabled": true,
    "min_samples": 100,
    "retrain_interval_sec": 3600,
    "contamination": 0.05,
    "anomaly_score_threshold": -0.1
  }
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .logger import JsonLogger
from .models import Event, EventKind, iso_time, now



# Feature extraction


@dataclass
class FeatureWindow:
    """One time-window of features for a single IP."""
    ip:               str
    ts:               float

    # Volume features
    ssh_fail_count:   int   = 0
    ssh_success_count:int   = 0
    web_event_count:  int   = 0
    db_fail_count:    int   = 0
    fw_block_count:   int   = 0

    # Diversity features
    unique_users:     int   = 0
    source_count:     int   = 0

    # Temporal features
    hour_of_day:      int   = 0
    day_of_week:      int   = 0
    events_per_min:   float = 0.0
    avg_interval_sec: float = 0.0

    def to_vector(self) -> List[float]:
        """Convert to feature vector for sklearn."""
        return [
            float(self.ssh_fail_count),
            float(self.ssh_success_count),
            float(self.web_event_count),
            float(self.db_fail_count),
            float(self.fw_block_count),
            float(self.unique_users),
            float(self.source_count),
            float(self.hour_of_day),
            float(self.day_of_week),
            self.events_per_min,
            self.avg_interval_sec,
        ]

    @staticmethod
    def feature_names() -> List[str]:
        return [
            "ssh_fails", "ssh_success", "web_events", "db_fails", "fw_blocks",
            "unique_users", "source_count",
            "hour_of_day", "day_of_week",
            "events_per_min", "avg_interval_sec",
        ]



# Per-IP event accumulator


class _IPAccumulator:
    """Accumulates events for one IP in a sliding window."""

    WINDOW_SEC = 60

    def __init__(self):
        self._events: deque = deque()  # (ts, kind, source, user)
        self._users:  set   = set()

    def add(self, ev: Event) -> None:
        t = ev.ts or now()
        self._events.append((t, ev.kind, ev.source, ev.user or ""))
        if ev.user:
            self._users.add(ev.user)
        self._prune(t)

    def _prune(self, t: float) -> None:
        cutoff = t - self.WINDOW_SEC
        while self._events and self._events[0][0] < cutoff:
            old = self._events.popleft()
            # Recalculate users from remaining events
        self._users = {u for _, _, _, u in self._events if u}

    def extract(self, ip: str) -> FeatureWindow:
        t = now()
        self._prune(t)

        events   = list(self._events)
        n        = len(events)
        struct_t = time.localtime(t)

        fw = FeatureWindow(ip=ip, ts=t)
        fw.hour_of_day  = struct_t.tm_hour
        fw.day_of_week  = struct_t.tm_wday
        fw.unique_users = len(self._users)

        sources = set()
        for ts_e, kind, source, user in events:
            sources.add(source)
            if kind == EventKind.SSH_FAIL:
                fw.ssh_fail_count += 1
            elif kind == EventKind.SSH_SUCCESS:
                fw.ssh_success_count += 1
            elif kind in ("WEB_SCAN", "WEB_AUTH_FAIL", "WEB_EXPLOIT_ATTEMPT"):
                fw.web_event_count += 1
            elif kind == "DB_AUTH_FAIL":
                fw.db_fail_count += 1
            elif kind in ("FW_BLOCK", "FW_HONEYPOT_PORT"):
                fw.fw_block_count += 1

        fw.source_count    = len(sources)
        fw.events_per_min  = n / (self.WINDOW_SEC / 60.0)

        if n >= 2:
            intervals = [events[i+1][0] - events[i][0] for i in range(n-1)]
            fw.avg_interval_sec = sum(intervals) / len(intervals)

        return fw



# ML Detector


@dataclass
class MLAlert:
    ip:            str
    anomaly_score: float
    features:      FeatureWindow
    top_reasons:   List[str]
    ts:            float

    def to_dict(self) -> Dict:
        return {
            "ip":            self.ip,
            "anomaly_score": round(self.anomaly_score, 4),
            "top_reasons":   self.top_reasons,
            "features":      {
                name: val
                for name, val in zip(
                    FeatureWindow.feature_names(),
                    self.features.to_vector()
                )
            },
            "time": iso_time(self.ts),
        }


class MLDetector:
    """
    Unsupervised anomaly detector using IsolationForest.

    Usage:
        ml = MLDetector(cfg, logger)
        alert = await ml.ingest(event)
        if alert:
            # handle ML anomaly
    """

    def __init__(self, cfg: Dict[str, Any], logger: JsonLogger):
        ml_cfg = cfg.get("ml", {})

        self.enabled      = bool(ml_cfg.get("enabled", False))
        self.min_samples  = int(ml_cfg.get("min_samples", 100))
        self.retrain_sec  = int(ml_cfg.get("retrain_interval_sec", 3600))
        self.contamination= float(ml_cfg.get("contamination", 0.05))
        self.threshold    = float(ml_cfg.get("anomaly_score_threshold", -0.1))

        self.logger       = logger
        self._accumulators: Dict[str, _IPAccumulator] = defaultdict(_IPAccumulator)
        self._training_data: List[List[float]] = []
        self._model       = None
        self._last_train  = 0.0
        self._trained     = False
        self._lock        = asyncio.Lock()

        # Per-IP cooldown (don't spam ML alerts)
        self._last_alert: Dict[str, float] = {}
        self._alert_cooldown = 300  # 5 minutes

    async def ingest(self, ev: Event) -> Optional[MLAlert]:
        """Process one event. Returns MLAlert if anomaly detected."""
        if not self.enabled or not ev.src_ip:
            return None

        ip  = ev.src_ip
        acc = self._accumulators[ip]
        acc.add(ev)

        features = acc.extract(ip)
        vector   = features.to_vector()

        # Accumulate training data
        async with self._lock:
            self._training_data.append(vector)
            # Keep training buffer bounded
            if len(self._training_data) > 50000:
                self._training_data = self._training_data[-25000:]

        # Retrain periodically
        if (now() - self._last_train) > self.retrain_sec:
            await self._retrain()

        # Score if model is ready
        if not self._trained or self._model is None:
            return None

        # Cooldown per IP
        last = self._last_alert.get(ip, 0)
        if (now() - last) < self._alert_cooldown:
            return None

        score = await self._score(vector)
        if score is None or score >= self.threshold:
            return None

        # Anomaly detected
        self._last_alert[ip] = now()
        reasons = self._explain(features, score)

        alert = MLAlert(
            ip=ip, anomaly_score=score,
            features=features, top_reasons=reasons,
            ts=now(),
        )
        await self.logger.log("ml_anomaly", alert.to_dict())
        return alert

    async def _retrain(self) -> None:
        """Train IsolationForest on accumulated data."""
        async with self._lock:
            data = list(self._training_data)

        if len(data) < self.min_samples:
            # Not enough data yet — still bump the timer so we don't
            # hammer _retrain() on every single event until min_samples is reached.
            self._last_train = now()
            return

        loop = asyncio.get_running_loop()
        try:
            model = await loop.run_in_executor(None, self._fit, data)
            async with self._lock:
                self._model    = model
                self._trained  = True
                self._last_train = now()

            await self.logger.log("ml_retrained", {
                "samples":      len(data),
                "contamination": self.contamination,
            })
        except Exception as e:
            await self.logger.log("ml_error", {"error": str(e)})

    def _fit(self, data: List[List[float]]):
        """CPU-bound: fit sklearn model (runs in executor)."""
        from sklearn.ensemble import IsolationForest
        model = IsolationForest(
            contamination=self.contamination,
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(data)
        return model

    async def _score(self, vector: List[float]) -> Optional[float]:
        """Score one vector. Returns anomaly score (lower = more anomalous)."""
        loop = asyncio.get_running_loop()
        try:
            async with self._lock:
                model = self._model
            if model is None:
                return None
            score = await loop.run_in_executor(
                None,
                lambda: float(model.score_samples([vector])[0])
            )
            return score
        except Exception:
            return None

    def _explain(self, fw: FeatureWindow, score: float) -> List[str]:
        """Generate human-readable explanation of why this was flagged."""
        reasons = []
        v = fw.to_vector()
        names = FeatureWindow.feature_names()

        # Simple threshold-based explanation
        explanation_rules = [
            ("ssh_fails",       lambda x: x > 3,   f"{fw.ssh_fail_count} SSH failures in window"),
            ("web_events",      lambda x: x > 10,  f"{fw.web_event_count} web events in window"),
            ("db_fails",        lambda x: x > 2,   f"{fw.db_fail_count} DB failures in window"),
            ("fw_blocks",       lambda x: x > 1,   f"{fw.fw_block_count} firewall blocks"),
            ("unique_users",    lambda x: x > 3,   f"{fw.unique_users} distinct usernames"),
            ("source_count",    lambda x: x > 2,   f"{fw.source_count} different log sources"),
            ("events_per_min",  lambda x: x > 5,   f"{fw.events_per_min:.1f} events/min"),
        ]

        for name, check_fn, desc in explanation_rules:
            idx = names.index(name) if name in names else -1
            if idx >= 0 and check_fn(v[idx]):
                reasons.append(desc)

        if not reasons:
            reasons = [f"statistical anomaly (score={score:.3f})"]

        return reasons

    @property
    def is_trained(self) -> bool:
        return self._trained

    @property
    def training_samples(self) -> int:
        return len(self._training_data)

    def status(self) -> Dict:
        return {
            "enabled":          self.enabled,
            "trained":          self._trained,
            "training_samples": len(self._training_data),
            "min_samples":      self.min_samples,
            "last_trained":     iso_time(self._last_train) if self._last_train else None,
            "tracked_ips":      len(self._accumulators),
        }