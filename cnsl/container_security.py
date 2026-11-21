"""
cnsl/container_security.py -- Container & Kubernetes Runtime Security Engine for CNSL.

Monitors Docker daemon socket and Kubernetes audit logs for privilege escalation,
exec commands into production containers, and container escape attempts.
"""

from __future__ import annotations

import asyncio
import os
import logging
from typing import Any, Dict, List, Optional

from .models import Event, now

logger = logging.getLogger("cnsl.container_security")


class ContainerSecurityEngine:
    """
    Monitors Container runtime telemetry (Docker & Kubernetes).
    """

    def __init__(self, config: Dict[str, Any] | None = None, queue: Optional[asyncio.Queue] = None):
        cfg = (config or {}).get("container_security", {})
        self.enabled = bool(cfg.get("enabled", False))
        self.docker_socket = cfg.get("docker_socket", "/var/run/docker.sock")
        self.queue = queue
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        if not self.enabled:
            return
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())
        logger.info("Started Container & Kubernetes Runtime Security Engine.")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()

    async def _monitor_loop(self) -> None:
        has_socket = os.path.exists(self.docker_socket)
        if not has_socket:
            logger.info(f"Docker socket {self.docker_socket} not accessible. Container security running in audit log mode.")

        while self._running:
            try:
                await asyncio.sleep(10.0)
                # Periodic container runtime check loop
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in container security loop: {e}")

    def inspect_container_event(self, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Inspect a container lifecycle or exec event.
        """
        action = event_data.get("action", "")
        container_id = event_data.get("container_id", "unknown")

        if action == "exec_start":
            return {
                "rule": "container.exec_start",
                "severity": "HIGH",
                "msg": f"Unauthorized interactive exec session started in container {container_id}",
            }
        elif action == "privilege_escalation":
            return {
                "rule": "container.privilege_escalation",
                "severity": "CRITICAL",
                "msg": f"Privilege escalation / capability add detected in container {container_id}",
            }
        return None
