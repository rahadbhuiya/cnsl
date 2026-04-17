"""
cnsl/blocker.py — IP blocking backend.

Supports:
  - iptables  (simple, default)
  - ipset     (fast, preferred for production with many IPs)

Default mode is DRY-RUN — no commands are executed unless --execute is passed.

Safety rules enforced here:
  1. Allowlisted IPs are never blocked.
  2. Already-blocked IPs are not blocked again.
  3. All blocks are temporary (auto-unblock after block_duration_sec).
  4. Every action is logged to JsonLogger before execution.
  5. iptables commands use subprocess with argument list (no shell injection).
"""

from __future__ import annotations

import asyncio
import subprocess
from typing import Dict, Optional, Set

from .logger import JsonLogger
from .models import now, iso_time


class Blocker:
    def __init__(
        self,
        *,
        dry_run: bool,
        backend: str,               # "iptables" | "ipset"
        chain: str,
        ipset_name: str,
        block_duration_sec: int,
        allowlist: Set[str],
        logger: JsonLogger,
    ):
        self.dry_run            = dry_run
        self.backend            = backend
        self.chain              = chain
        self.ipset_name         = ipset_name
        self.block_duration_sec = block_duration_sec
        self.allowlist          = allowlist
        self.logger             = logger

        # ip -> unblock_at timestamp
        self.active_blocks: Dict[str, float] = {}

    # ── Public ────────────────────────────────────────────────────────────────

    async def block_ip(self, ip: str, reason: str) -> bool:
        """Schedule (and optionally execute) a block for the given IP."""
        if not ip:
            return False
        if ip in self.allowlist:
            await self.logger.log("action_skip_allowlist", {"ip": ip, "reason": reason})
            return False
        if ip in self.active_blocks:
            return False  # already blocked

        unblock_at = now() + self.block_duration_sec
        self.active_blocks[ip] = unblock_at

        await self.logger.log("action_block_scheduled", {
            "ip":         ip,
            "reason":     reason,
            "backend":    self.backend,
            "unblock_at": iso_time(unblock_at),
            "dry_run":    self.dry_run,
        })

        if self.dry_run:
            return True

        ok = await self._execute_block(ip)
        if not ok:
            self.active_blocks.pop(ip, None)
        return ok

    async def unblock_due(self) -> None:
        """Called periodically from the engine to remove expired blocks."""
        if not self.active_blocks:
            return
        t = now()
        due = [ip for ip, exp in self.active_blocks.items() if exp <= t]
        for ip in due:
            await self._unblock_ip(ip)

    def is_blocked(self, ip: str) -> bool:
        return ip in self.active_blocks

    # ── Private ───────────────────────────────────────────────────────────────

    async def _execute_block(self, ip: str) -> bool:
        if self.backend == "ipset":
            cmd = ["sudo", "ipset", "add", self.ipset_name, ip, "-exist"]
        else:
            cmd = ["sudo", "iptables", "-I", self.chain, "1", "-s", ip, "-j", "DROP"]

        return await self._run(cmd, "action_block_executed", "action_block_failed", ip)

    async def _unblock_ip(self, ip: str) -> None:
        await self.logger.log("action_unblock_scheduled", {
            "ip":      ip,
            "dry_run": self.dry_run,
        })

        if not self.dry_run:
            if self.backend == "ipset":
                cmd = ["sudo", "ipset", "del", self.ipset_name, ip, "-exist"]
            else:
                cmd = ["sudo", "iptables", "-D", self.chain, "-s", ip, "-j", "DROP"]

            await self._run(cmd, "action_unblock_executed", "action_unblock_failed", ip)

        self.active_blocks.pop(ip, None)

    async def _run(self, cmd: list, ok_type: str, fail_type: str, ip: str) -> bool:
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    cmd, check=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                ),
            )
            await self.logger.log(ok_type, {"ip": ip, "cmd": cmd})
            return True
        except subprocess.CalledProcessError as e:
            await self.logger.log(fail_type, {"ip": ip, "cmd": cmd, "error": str(e)})
            return False


# ── ipset setup helper ────────────────────────────────────────────────────────

async def ensure_ipset(name: str, logger: JsonLogger) -> bool:
    """
    Create the ipset blocklist and the iptables rule pointing at it.
    Call once at startup when using the ipset backend.
    """
    cmds = [
        ["sudo", "ipset", "create", name, "hash:ip", "timeout", "0", "-exist"],
        ["sudo", "iptables", "-I", "INPUT", "1", "-m", "set",
         "--match-set", name, "src", "-j", "DROP"],
    ]
    for cmd in cmds:
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            await logger.log("ipset_setup_failed", {"cmd": cmd, "error": str(e)})
            return False

    await logger.log("ipset_setup_ok", {"name": name})
    return True