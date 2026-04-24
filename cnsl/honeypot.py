"""
cnsl/honeypot.py — Active response and honeypot redirect.

Instead of just blocking attackers, CNSL can redirect them to
a fake server (honeypot). The attacker thinks they got in —
while we watch what they do.

Modes:
  DROP      — silently drop all traffic (classic block)
  REDIRECT  — redirect attacker to honeypot IP/port via iptables DNAT
  TARPIT    — slow down attacker with iptables TARPIT (needs xt_TARPIT)
  LOG_ONLY  — just log, don't block (for observation)

Honeypot:
  CNSL includes a built-in fake SSH honeypot that:
    - Accepts any username/password
    - Shows a fake banner
    - Logs every command the attacker types
    - Never actually executes anything
    - Reports all attacker activity back to CNSL

Architecture:
  [Attacker] ──SSH──> [Port 22 DNAT] ──> [Honeypot on Port 2222]
                              ^
                         iptables PREROUTING

Config:
  "honeypot": {
    "enabled":       false,
    "mode":          "redirect",
    "honeypot_host": "127.0.0.1",
    "honeypot_port": 2222,
    "fake_hostname": "ubuntu-server",
    "fake_version":  "Ubuntu 22.04.3 LTS",
    "log_commands":  true,
    "auto_redirect_severity": "HIGH"
  }
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import random
import socket
import string
import subprocess
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, List, Optional

from .logger import JsonLogger
from .models import iso_time, now



# Attacker session log


@dataclass
class HoneypotSession:
    attacker_ip:   str
    attacker_port: int
    start_time:    float
    commands:      List[str] = field(default_factory=list)
    end_time:      Optional[float] = None
    auth_attempts: List[Dict] = field(default_factory=list)

    def duration_sec(self) -> float:
        end = self.end_time or now()
        return end - self.start_time

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["time"]         = iso_time(self.start_time)
        d["duration_sec"] = round(self.duration_sec(), 2)
        return d



# Fake SSH honeypot server


class FakeSSHServer:
    """
    Minimal fake SSH honeypot using asyncio.
    Accepts any login, logs all commands, never executes anything.

    Uses a simplified SSH-like protocol (banner exchange + fake shell)
    without a full SSH stack. For a production honeypot, use
    paramiko-based cowrie integration instead.
    """

    SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

    def __init__(
        self,
        host:         str,
        port:         int,
        fake_hostname:str,
        fake_version: str,
        logger:       JsonLogger,
        on_session:   Optional[Callable] = None,
    ):
        self.host          = host
        self.port          = port
        self.fake_hostname = fake_hostname
        self.fake_version  = fake_version
        self.logger        = logger
        self.on_session    = on_session
        self._server       = None
        self._sessions:    List[HoneypotSession] = []

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_connection, self.host, self.port
        )
        await self.logger.log("honeypot_started", {
            "host": self.host, "port": self.port,
            "fake_hostname": self.fake_hostname,
        })
        async with self._server:
            await self._server.serve_forever()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer    = writer.get_extra_info("peername", ("unknown", 0))
        ip, port = peer[0], peer[1]
        session  = HoneypotSession(attacker_ip=ip, attacker_port=port,
                                    start_time=now())
        self._sessions.append(session)

        await self.logger.log("honeypot_connection", {
            "ip": ip, "port": port,
        })

        try:
            await self._fake_ssh_handshake(reader, writer, session)
        except (ConnectionResetError, asyncio.IncompleteReadError, OSError):
            pass
        except Exception as e:
            await self.logger.log("honeypot_error", {"ip": ip, "error": str(e)})
        finally:
            session.end_time = now()
            writer.close()
            await self.logger.log("honeypot_session_end", session.to_dict())
            if self.on_session:
                try:
                    await self.on_session(session)
                except Exception:
                    pass

    async def _fake_ssh_handshake(
        self,
        reader:  asyncio.StreamReader,
        writer:  asyncio.StreamWriter,
        session: HoneypotSession,
    ) -> None:
        # Send SSH banner
        writer.write(self.SSH_BANNER.encode())
        await writer.drain()

        # Read client banner (ignore it)
        try:
            await asyncio.wait_for(reader.readline(), timeout=10)
        except asyncio.TimeoutError:
            return

        # Fake authentication loop (accept anything after 1-2 "failures")
        # Real SSH would do key exchange here — we skip to a fake login prompt
        await asyncio.sleep(random.uniform(0.5, 1.5))

        attempts = 0
        max_attempts = random.randint(2, 4)

        while attempts < max_attempts:
            writer.write(b"\r\nlogin: ")
            await writer.drain()

            try:
                username_line = await asyncio.wait_for(reader.read(256), timeout=30)
                username = username_line.decode(errors="ignore").strip()
            except asyncio.TimeoutError:
                return

            writer.write(b"Password: ")
            await writer.drain()

            try:
                password_line = await asyncio.wait_for(reader.read(256), timeout=30)
                password = password_line.decode(errors="ignore").strip()
            except asyncio.TimeoutError:
                return

            session.auth_attempts.append({
                "username": username,
                "password": password,
                "ts":       now(),
            })
            await self.logger.log("honeypot_credentials", {
                "ip":       session.attacker_ip,
                "username": username,
                "password": password,
            })

            attempts += 1
            if attempts < max_attempts:
                await asyncio.sleep(random.uniform(1, 2))
                writer.write(b"\r\nLogin incorrect\r\n")
                await writer.drain()
            else:
                break

        # Fake successful login
        await asyncio.sleep(random.uniform(0.3, 0.8))
        motd = (
            f"\r\nWelcome to {self.fake_version}\r\n"
            f" * Documentation:  https://help.ubuntu.com\r\n"
            f" * Management:     https://landscape.canonical.com\r\n"
            f"\r\nLast login: {_fake_last_login()}\r\n\r\n"
        )
        writer.write(motd.encode())
        await writer.drain()

        # Fake shell
        await self._fake_shell(reader, writer, session)

    async def _fake_shell(
        self,
        reader:  asyncio.StreamReader,
        writer:  asyncio.StreamWriter,
        session: HoneypotSession,
    ) -> None:
        prompt = f"{session.auth_attempts[-1]['username'] if session.auth_attempts else 'root'}@{self.fake_hostname}:~$ ".encode()

        _FAKE_RESPONSES: Dict[str, bytes] = {
            "id":       b"uid=0(root) gid=0(root) groups=0(root)\r\n",
            "whoami":   b"root\r\n",
            "uname -a": f"Linux {self.fake_hostname} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n".encode(),
            "pwd":      b"/root\r\n",
            "ls":       b"snap  .bashrc  .profile  .ssh\r\n",
            "ls -la":   b"total 32\r\ndrwx------ 4 root root 4096 Jan  1 00:00 .\r\ndrwxr-xr-x 20 root root 4096 Jan  1 00:00 ..\r\n",
            "cat /etc/passwd": b"root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n",
            "history":  b"    1  ls\r\n    2  pwd\r\n    3  history\r\n",
            "env":      b"HOME=/root\r\nUSER=root\r\nSHELL=/bin/bash\r\nTERM=xterm-256color\r\n",
            "ps aux":   b"USER  PID %CPU %MEM    VSZ   RSS TTY  STAT START TIME COMMAND\r\nroot    1  0.0  0.1  37400  5988 ?  Ss   00:00 0:01 /sbin/init\r\n",
            "netstat -an": b"Active Internet connections (servers and established)\r\nProto Recv-Q Send-Q Local Address  Foreign Address  State\r\ntcp  0  0 0.0.0.0:22  0.0.0.0:*  LISTEN\r\n",
            "ifconfig": b"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 10.0.0.1  netmask 255.255.255.0  broadcast 10.0.0.255\r\n",
            "ip a":     b"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\r\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\r\n",
            "crontab -l": b"no crontab for root\r\n",
        }

        for _ in range(200):   # max 200 commands per session
            writer.write(prompt)
            await writer.drain()

            try:
                cmd_bytes = await asyncio.wait_for(reader.read(4096), timeout=120)
                cmd = cmd_bytes.decode(errors="ignore").strip()
            except asyncio.TimeoutError:
                break

            if not cmd:
                continue

            session.commands.append(cmd)
            await self.logger.log("honeypot_command", {
                "ip":      session.attacker_ip,
                "command": cmd,
                "seq":     len(session.commands),
            })

            cmd_lower = cmd.lower().split()[0] if cmd.split() else ""

            if cmd_lower in ("exit", "logout", "quit"):
                writer.write(b"logout\r\n")
                await writer.drain()
                break

            # Look for known commands
            resp = None
            for known, response in _FAKE_RESPONSES.items():
                if cmd.strip() == known or cmd.strip().startswith(known + " "):
                    resp = response
                    break

            if resp:
                await asyncio.sleep(random.uniform(0.05, 0.2))
                writer.write(resp)
            elif cmd_lower in ("wget", "curl", "nc", "ncat", "python", "python3", "perl", "ruby"):
                # Dangerous commands — simulate slow network/timeout
                await asyncio.sleep(random.uniform(3, 8))
                writer.write(b"curl: (6) Could not resolve host\r\n")
            elif cmd.startswith("cd "):
                writer.write(b"")  # cd silently succeeds
            else:
                cmd_name = cmd.split()[0] if cmd.split() else cmd
                writer.write(f"{cmd_name}: command not found\r\n".encode())

            await writer.drain()

    def recent_sessions(self, limit: int = 20) -> List[Dict]:
        return [s.to_dict() for s in self._sessions[-limit:]]

    def stop(self) -> None:
        if self._server:
            self._server.close()


def _fake_last_login() -> str:
    days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    d = random.choice(days)
    m = random.choice(months)
    day = random.randint(1, 28)
    h, mn = random.randint(0, 23), random.randint(0, 59)
    ip = f"10.0.0.{random.randint(1,254)}"
    return f"{d} {m} {day:2d} {h:02d}:{mn:02d}:00 2024 from {ip}"



# Active response manager


class ActiveResponse:
    """
    Decides what to do with a detected attacker.

    Modes:
      drop      — iptables DROP (silent block, default)
      redirect  — iptables DNAT to honeypot
      tarpit    — iptables TARPIT (TCP stall — needs xt_TARPIT)
      log_only  — no firewall action, just log
    """

    def __init__(self, cfg: Dict[str, Any], logger: JsonLogger):
        hp = cfg.get("honeypot", {})

        self.enabled         = bool(hp.get("enabled", False))
        self.mode            = hp.get("mode", "drop")
        self.honeypot_host   = hp.get("honeypot_host", "127.0.0.1")
        self.honeypot_port   = int(hp.get("honeypot_port", 2222))
        self.fake_hostname   = hp.get("fake_hostname", "ubuntu-server")
        self.fake_version    = hp.get("fake_version", "Ubuntu 22.04.3 LTS")
        self.auto_redirect   = hp.get("auto_redirect_severity", "HIGH")
        self.log_commands    = bool(hp.get("log_commands", True))
        self.dry_run         = bool(cfg.get("actions", {}).get("dry_run", True))

        self.logger          = logger
        self._fake_server:   Optional[FakeSSHServer] = None
        self._redirected:    Dict[str, float] = {}   # ip -> redirect_ts

    async def start_honeypot(self, on_session: Optional[Callable] = None) -> None:
        """Start the built-in fake SSH server."""
        if not self.enabled or self.mode not in ("redirect",):
            return

        self._fake_server = FakeSSHServer(
            host          = self.honeypot_host,
            port          = self.honeypot_port,
            fake_hostname = self.fake_hostname,
            fake_version  = self.fake_version,
            logger        = self.logger,
            on_session    = on_session,
        )
        asyncio.create_task(
            self._fake_server.start(), name="honeypot_ssh"
        )
        await self.logger.log("honeypot_mode", {
            "mode":           self.mode,
            "honeypot_port":  self.honeypot_port,
            "dry_run":        self.dry_run,
        })

    async def respond(self, ip: str, severity: str, dry_run: bool = True) -> str:
        """
        Execute active response for an attacker IP.
        Returns the action taken.
        """
        if not self.enabled:
            return "disabled"

        # Only respond to configured severity
        sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        if sev_order.get(severity, 0) < sev_order.get(self.auto_redirect, 2):
            return "severity_below_threshold"

        action = self.mode
        await self.logger.log("active_response", {
            "ip":      ip,
            "action":  action,
            "severity":severity,
            "dry_run": dry_run,
        })

        if dry_run:
            return f"dry_run:{action}"

        if action == "redirect":
            return await self._redirect_to_honeypot(ip)
        elif action == "tarpit":
            return await self._tarpit(ip)
        elif action == "drop":
            return await self._drop(ip)
        else:
            return "log_only"

    async def _redirect_to_honeypot(self, ip: str) -> str:
        """DNAT attacker's SSH to honeypot port."""
        if ip in self._redirected:
            return "already_redirected"

        cmds = [
            # Redirect incoming SSH from attacker to honeypot
            ["sudo", "iptables", "-t", "nat", "-I", "PREROUTING", "1",
             "-s", ip, "-p", "tcp", "--dport", "22",
             "-j", "DNAT", "--to-destination",
             f"{self.honeypot_host}:{self.honeypot_port}"],
            # Allow traffic to honeypot
            ["sudo", "iptables", "-I", "FORWARD", "1",
             "-s", ip, "-d", self.honeypot_host, "-j", "ACCEPT"],
        ]

        success = True
        for cmd in cmds:
            try:
                subprocess.run(cmd, check=True,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            except Exception as e:
                await self.logger.log("honeypot_redirect_error",
                                       {"ip": ip, "error": str(e)})
                success = False

        if success:
            self._redirected[ip] = now()
            await self.logger.log("honeypot_redirected", {
                "ip":             ip,
                "honeypot_port":  self.honeypot_port,
            })
            return "redirected"
        return "redirect_failed"

    async def _tarpit(self, ip: str) -> str:
        """Slow down attacker with TCP TARPIT."""
        cmd = ["sudo", "iptables", "-I", "INPUT", "1",
               "-s", ip, "-p", "tcp", "--dport", "22",
               "-j", "TARPIT"]
        try:
            subprocess.run(cmd, check=True,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            return "tarpitted"
        except Exception as e:
            await self.logger.log("tarpit_error", {"ip": ip, "error": str(e)})
            return "tarpit_failed"

    async def _drop(self, ip: str) -> str:
        """Standard iptables DROP."""
        cmd = ["sudo", "iptables", "-I", "INPUT", "1",
               "-s", ip, "-j", "DROP"]
        try:
            subprocess.run(cmd, check=True,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            return "dropped"
        except Exception as e:
            await self.logger.log("drop_error", {"ip": ip, "error": str(e)})
            return "drop_failed"

    async def remove_redirect(self, ip: str) -> None:
        """Remove DNAT rule for an IP (unredirect)."""
        if ip not in self._redirected:
            return

        cmds = [
            ["sudo", "iptables", "-t", "nat", "-D", "PREROUTING",
             "-s", ip, "-p", "tcp", "--dport", "22",
             "-j", "DNAT", "--to-destination",
             f"{self.honeypot_host}:{self.honeypot_port}"],
            ["sudo", "iptables", "-D", "FORWARD",
             "-s", ip, "-d", self.honeypot_host, "-j", "ACCEPT"],
        ]
        for cmd in cmds:
            try:
                subprocess.run(cmd, check=True,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            except Exception:
                pass

        self._redirected.pop(ip, None)
        await self.logger.log("honeypot_unredirected", {"ip": ip})

    def recent_sessions(self, limit: int = 20) -> List[Dict]:
        if self._fake_server:
            return self._fake_server.recent_sessions(limit)
        return []

    def is_redirected(self, ip: str) -> bool:
        return ip in self._redirected

    def status(self) -> Dict:
        return {
            "enabled":          self.enabled,
            "mode":             self.mode,
            "honeypot_port":    self.honeypot_port,
            "active_redirects": len(self._redirected),
            "dry_run":          self.dry_run,
        }