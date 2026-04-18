"""
cnsl/sources.py — Async readers that feed events into the central queue.

Each source runs as a long-lived asyncio task.
If the subprocess dies (e.g. log rotation, permission error), it retries
after a short backoff so the engine keeps running.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from .logger import JsonLogger
from .parsers import parse_auth_event, parse_tcpdump_hint


_RETRY_DELAY = 5   # seconds before retrying a failed source process



# Auth.log reader (uses tail -F so it survives log rotation)


async def tail_authlog(
    queue: asyncio.Queue,
    path:  str,
    logger: JsonLogger,
) -> None:
    """Continuously tail an auth.log file and push parsed Events to queue."""
    await logger.log("source_start", {"source": "authlog", "path": path})

    while True:
        try:
            proc = await asyncio.create_subprocess_exec(
                "sudo", "tail", "-F", path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            assert proc.stdout is not None

            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                text = line.decode(errors="ignore").strip()
                if not text:
                    continue
                ev = parse_auth_event(text)
                if ev:
                    await queue.put(ev)

        except Exception as e:
            await logger.log("source_error", {"source": "authlog", "error": str(e)})

        await logger.log("source_restart", {"source": "authlog", "delay": _RETRY_DELAY})
        await asyncio.sleep(_RETRY_DELAY)



# tcpdump reader (optional, hint-only)

async def run_tcpdump(
    queue:  asyncio.Queue,
    iface:  str,
    bpf:    str,
    logger: JsonLogger,
) -> None:
    """Run tcpdump and push NET_HINT Events to queue."""
    await logger.log("source_start", {"source": "tcpdump", "iface": iface, "bpf": bpf})

    # Build command.  Pass the BPF filter as a single argument — tcpdump
    # handles its own tokenisation of the filter expression.
    cmd = ["sudo", "tcpdump", "-i", iface, "-l", "-nn", "-q"]
    if bpf:
        cmd.append(bpf)

    while True:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            assert proc.stdout is not None

            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                text = line.decode(errors="ignore").strip()
                if not text:
                    continue
                ev = parse_tcpdump_hint(text)
                if ev:
                    await queue.put(ev)

        except Exception as e:
            await logger.log("source_error", {"source": "tcpdump", "error": str(e)})

        await logger.log("source_restart", {"source": "tcpdump", "delay": _RETRY_DELAY})
        await asyncio.sleep(_RETRY_DELAY)