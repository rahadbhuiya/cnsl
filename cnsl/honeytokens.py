"""
cnsl/honeytokens.py -- Deception & Honeytoken Engine for CNSL.

Generates canary files (fake AWS keys, db credentials, canary tokens) and monitors
filesystem access to detect unauthorized intrusion with zero false-positives.
"""

from __future__ import annotations

import asyncio
import os
import time
import logging
from typing import Any, Dict, List, Optional

from .models import Event, now

logger = logging.getLogger("cnsl.honeytokens")


CANARY_TEMPLATE_AWS = """[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

CANARY_TEMPLATE_ENV = """# Production DB Configuration
DB_HOST=10.0.0.45
DB_USER=root
DB_PASS=SuperSecretStolenPass123!
"""


class HoneytokenEngine:
    """
    Manages deception canary tokens and watches for unauthorized access.
    """

    def __init__(self, config: Dict[str, Any] | None = None, queue: Optional[asyncio.Queue] = None):
        cfg = (config or {}).get("honeytokens", {})
        self.enabled = bool(cfg.get("enabled", True))
        self.auto_block = bool(cfg.get("auto_block", True))
        self.canary_paths = cfg.get("canary_paths", [
            "/tmp/fake_aws_credentials",
            "/tmp/fake_database.env"
        ])
        self.queue = queue
        self._initial_stats: Dict[str, float] = {}
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def deploy_tokens(self) -> None:
        """Create canary honeytoken files if they do not exist."""
        try:
            for path in self.canary_paths:
                dirname = os.path.dirname(path)
                if dirname and not os.path.exists(dirname):
                    os.makedirs(dirname, exist_ok=True)

                if not os.path.exists(path):
                    content = CANARY_TEMPLATE_AWS if "aws" in path else CANARY_TEMPLATE_ENV
                    with open(path, "w") as f:
                        f.write(content)
                    logger.info(f"Deployed honeytoken canary file: {path}")

                stat = os.stat(path)
                self._initial_stats[path] = stat.st_atime
        except Exception as e:
            logger.error(f"Failed to deploy honeytokens: {e}")

    async def start_watcher(self) -> None:
        """Start async file access monitoring loop."""
        if not self.enabled:
            return
        self.deploy_tokens()
        self._running = True
        self._task = asyncio.create_task(self._watch_loop())

    async def stop_watcher(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()

    async def _watch_loop(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(3.0)
                for path in self.canary_paths:
                    if not os.path.exists(path):
                        continue
                    stat = os.stat(path)
                    prev_atime = self._initial_stats.get(path, 0)
                    if stat.st_atime > prev_atime + 1.0:
                        self._initial_stats[path] = stat.st_atime
                        await self._trigger_alert(path)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in honeytoken watcher loop: {e}")

    async def _trigger_alert(self, path: str) -> None:
        logger.warning(f"CRITICAL: Honeytoken canary file accessed: {path}")
        ev = Event(
            timestamp=now(),
            source_type="honeytoken",
            ip="127.0.0.1",
            user="unauthorized_actor",
            details={
                "rule": "honeytoken.triggered",
                "canary_file": path,
                "msg": f"Canary file {path} was accessed or read!",
                "severity": "CRITICAL",
            }
        )
        if self.queue:
            await self.queue.put(ev)
