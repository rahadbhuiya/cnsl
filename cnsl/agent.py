"""
cnsl/agent.py — CNSL Log Forwarding Agent.

A lightweight agent that runs on remote servers and forwards log events
to a central CNSL instance via WebSocket.

Features:
  - Tails auth.log, nginx, apache, mysql, ufw, syslog (configurable)
  - Forwards parsed events to CNSL server over WebSocket
  - Automatic reconnection with exponential backoff
  - JWT authentication (uses CNSL API token)
  - Backpressure: drops oldest events if queue fills up
  - TLS support (wss://)
  - Agent hostname tagged on every event

Usage:
  python -m cnsl.agent --server wss://cnsl.example.com/ws/agent \\
                       --token YOUR_JWT_TOKEN \\
                       --hostname web-01

Config file (~/.cnsl-agent.json or /etc/cnsl/agent.json):
  {
    "server":   "wss://cnsl.example.com/ws/agent",
    "token":    "your-jwt-token",
    "hostname": "web-01",
    "sources": {
      "auth":   "/var/log/auth.log",
      "nginx":  "/var/log/nginx/access.log",
      "apache": null,
      "mysql":  null,
      "ufw":    "/var/log/ufw.log",
      "syslog": "/var/log/syslog"
    },
    "queue_size":    1000,
    "batch_size":    50,
    "flush_interval": 1.0
  }

Running as a systemd service:
  See docs/agent.md for a complete setup guide.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import socket
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .models import iso_time


#  Agent config defaults 

DEFAULT_AGENT_CONFIG: Dict[str, Any] = {
    "server":         "ws://localhost:8765/ws/agent",
    "token":          "",
    "hostname":       socket.gethostname(),
    "sources": {
        "auth":   "/var/log/auth.log",
        "nginx":  None,
        "apache": None,
        "mysql":  None,
        "ufw":    None,
        "syslog": None,
    },
    "queue_size":     1000,
    "batch_size":     50,
    "flush_interval": 1.0,
    "reconnect_min":  2.0,
    "reconnect_max":  60.0,
}

_CONFIG_PATHS = [
    Path.home() / ".cnsl-agent.json",
    Path("/etc/cnsl/agent.json"),
    Path("cnsl-agent.json"),
]


def load_agent_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Load agent config from file, merging with defaults."""
    cfg = dict(DEFAULT_AGENT_CONFIG)
    cfg["sources"] = dict(DEFAULT_AGENT_CONFIG["sources"])

    search = [Path(path)] if path else _CONFIG_PATHS
    for p in search:
        if p.exists():
            try:
                loaded = json.loads(p.read_text())
                cfg.update({k: v for k, v in loaded.items() if k != "sources"})
                if "sources" in loaded:
                    cfg["sources"].update(loaded["sources"])
            except Exception:
                pass
            break

    return cfg


#  Event queue 


class AgentQueue:
    """Bounded queue with drop-oldest on overflow."""

    def __init__(self, maxsize: int = 1000):
        self._q:    asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self.dropped: int         = 0

    def put_nowait(self, item: Any) -> None:
        try:
            self._q.put_nowait(item)
        except asyncio.QueueFull:
            try:
                self._q.get_nowait()   # drop oldest
                self.dropped += 1
            except asyncio.QueueEmpty:
                pass
            self._q.put_nowait(item)

    async def get_batch(self, max_items: int, timeout: float) -> List[Any]:
        items = []
        deadline = time.monotonic() + timeout
        while len(items) < max_items:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                item = await asyncio.wait_for(self._q.get(), timeout=remaining)
                items.append(item)
            except asyncio.TimeoutError:
                break
        return items

    @property
    def qsize(self) -> int:
        return self._q.qsize()


#  Log tailer 


async def tail_file(path: str, queue: AgentQueue, parser_fn, hostname: str) -> None:
    """
    Tail a log file and push parsed events to the queue.
    Handles log rotation by re-opening when the file shrinks.
    """
    pos = 0
    while True:
        try:
            if not os.path.exists(path):
                await asyncio.sleep(5)
                continue

            stat = os.stat(path)

            # Detect rotation (file shrank or was replaced)
            if stat.st_size < pos:
                pos = 0

            if stat.st_size == pos:
                await asyncio.sleep(0.5)
                continue

            with open(path, "r", errors="replace") as f:
                f.seek(pos)
                for line in f:
                    line = line.rstrip("\n")
                    if not line:
                        continue
                    try:
                        ev = parser_fn(line)
                        if ev:
                            payload = ev.to_dict() if hasattr(ev, "to_dict") else {"raw": line}
                            payload["_agent_host"] = hostname
                            payload["_source_file"] = path
                            queue.put_nowait(payload)
                    except Exception:
                        pass
                pos = f.tell()

        except Exception:
            await asyncio.sleep(2)


#  WebSocket sender 


async def ws_sender(cfg: Dict[str, Any], queue: AgentQueue) -> None:
    """
    Main WebSocket sender loop.
    Connects to the CNSL server, authenticates, and flushes event batches.
    Reconnects with exponential backoff on failure.
    """
    try:
        import aiohttp
    except ImportError:
        print("ERROR: aiohttp not installed. Run: pip install aiohttp", file=sys.stderr)
        return

    server   = cfg["server"]
    token    = cfg["token"]
    hostname = cfg["hostname"]
    batch    = int(cfg.get("batch_size", 50))
    interval = float(cfg.get("flush_interval", 1.0))
    backoff  = float(cfg.get("reconnect_min", 2.0))
    max_back = float(cfg.get("reconnect_max", 60.0))

    while True:
        try:
            timeout = aiohttp.ClientTimeout(total=None, connect=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.ws_connect(
                    server,
                    headers={"Authorization": f"Bearer {token}"},
                    heartbeat=30,
                ) as ws:
                    # Send agent handshake
                    await ws.send_json({
                        "type":     "agent_hello",
                        "hostname": hostname,
                        "version":  "1.9.0",
                        "pid":      os.getpid(),
                        "platform": platform.system(),
                        "time":     iso_time(),
                    })

                    # Wait for server ack
                    msg = await asyncio.wait_for(ws.receive(), timeout=10)
                    if msg.type != aiohttp.WSMsgType.TEXT:
                        raise ConnectionError("Bad handshake response")
                    ack = json.loads(msg.data)
                    if not ack.get("ok"):
                        raise ConnectionError(f"Server rejected: {ack.get('error')}")

                    print(f"[agent] Connected to {server} as {hostname}", file=sys.stderr)
                    backoff = float(cfg.get("reconnect_min", 2.0))  # reset on success

                    # Flush loop
                    while True:
                        events = await queue.get_batch(batch, interval)
                        if events:
                            await ws.send_json({
                                "type":   "agent_events",
                                "host":   hostname,
                                "count":  len(events),
                                "events": events,
                            })
                        else:
                            # Keepalive ping
                            await ws.ping()

        except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
            print(f"[agent] Disconnected ({exc}). Retry in {backoff:.0f}s", file=sys.stderr)
        except Exception as exc:
            print(f"[agent] Error: {exc}. Retry in {backoff:.0f}s", file=sys.stderr)

        await asyncio.sleep(backoff)
        backoff = min(backoff * 1.5, max_back)


#  Agent entrypoint 


async def run_agent(cfg: Dict[str, Any]) -> None:
    """Start all log tailers and the WebSocket sender."""
    from .parsers     import parse_auth_event
    from .log_sources import parse_web_access, parse_mysql, parse_ufw, parse_syslog

    hostname = cfg["hostname"]
    queue    = AgentQueue(maxsize=int(cfg.get("queue_size", 1000)))
    sources  = cfg.get("sources", {})

    parsers = {
        "auth":   parse_auth_event,
        "nginx":  lambda l: parse_web_access(l, "nginx"),
        "apache": lambda l: parse_web_access(l, "apache"),
        "mysql":  parse_mysql,
        "ufw":    parse_ufw,
        "syslog": parse_syslog,
    }

    tasks = []
    for name, path in sources.items():
        if not path or not isinstance(path, str):
            continue
        parser = parsers.get(name)
        if not parser:
            continue
        if not os.path.exists(path):
            print(f"[agent] Warning: {path} not found — skipping", file=sys.stderr)
            continue
        tasks.append(asyncio.create_task(
            tail_file(path, queue, parser, hostname),
            name=f"tail_{name}",
        ))
        print(f"[agent] Tailing {path} ({name})", file=sys.stderr)

    if not tasks:
        print("[agent] Warning: no log sources found", file=sys.stderr)

    tasks.append(asyncio.create_task(ws_sender(cfg, queue), name="ws_sender"))

    # Status printer
    async def _status() -> None:
        while True:
            await asyncio.sleep(60)
            print(
                f"[agent] queue={queue.qsize} dropped={queue.dropped}",
                file=sys.stderr,
            )

    tasks.append(asyncio.create_task(_status(), name="status"))

    await asyncio.gather(*tasks, return_exceptions=True)


def main() -> None:
    """CLI entrypoint: python -m cnsl.agent"""
    import argparse

    ap = argparse.ArgumentParser(description="CNSL Log Forwarding Agent")
    ap.add_argument("--config",   metavar="FILE",  help="Config file path")
    ap.add_argument("--server",   metavar="URL",   help="CNSL WebSocket URL")
    ap.add_argument("--token",    metavar="TOKEN", help="JWT authentication token")
    ap.add_argument("--hostname", metavar="NAME",  help="Agent hostname label")
    args = ap.parse_args()

    cfg = load_agent_config(args.config)
    if args.server:
        cfg["server"] = args.server
    if args.token:
        cfg["token"] = args.token
    if args.hostname:
        cfg["hostname"] = args.hostname

    if not cfg.get("token"):
        print("ERROR: --token required", file=sys.stderr)
        sys.exit(1)

    print(f"[agent] Starting CNSL agent v1.9.0 on {cfg['hostname']}", file=sys.stderr)
    asyncio.run(run_agent(cfg))


if __name__ == "__main__":
    main()