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
        user = session.auth_attempts[-1]["username"] if session.auth_attempts else "root"
        home = "/root" if user == "root" else f"/home/{user}"

        # Fake filesystem tree — directories and files
        _FS: Dict[str, List[str]] = {
            "/":                ["bin", "boot", "dev", "etc", "home", "lib", "lib64",
                                 "media", "mnt", "opt", "proc", "root", "run",
                                 "sbin", "srv", "sys", "tmp", "usr", "var"],
            "/root":            [".bashrc", ".bash_history", ".profile", ".ssh",
                                 ".vimrc", "snap"],
            "/root/.ssh":       ["authorized_keys", "known_hosts"],
            "/home":            ["ubuntu", "deploy"],
            "/home/ubuntu":     [".bashrc", ".profile", ".ssh"],
            "/home/deploy":     [".bashrc", ".profile", "app"],
            "/etc":             ["passwd", "shadow", "group", "hostname", "hosts",
                                 "resolv.conf", "ssh", "cron.d", "crontab",
                                 "environment", "fstab", "os-release",
                                 "sudoers", "apt", "nginx", "mysql"],
            "/etc/ssh":         ["sshd_config", "ssh_config", "moduli",
                                 "ssh_host_rsa_key", "ssh_host_ed25519_key"],
            "/etc/apt":         ["sources.list", "trusted.gpg"],
            "/etc/nginx":       ["nginx.conf", "sites-enabled", "sites-available"],
            "/etc/mysql":       ["my.cnf", "mysql.conf.d"],
            "/var":             ["log", "www", "lib", "run", "spool", "tmp"],
            "/var/log":         ["auth.log", "syslog", "kern.log", "dpkg.log",
                                 "nginx", "mysql", "apache2"],
            "/var/log/nginx":   ["access.log", "error.log"],
            "/var/log/mysql":   ["error.log"],
            "/var/www":         ["html"],
            "/var/www/html":    ["index.html", "index.php", ".htaccess"],
            "/tmp":             [],
            "/opt":             [],
            "/proc":            ["cpuinfo", "meminfo", "version", "uptime",
                                 "net", "sys"],
        }

        # Fake file contents
        _FILE_CONTENTS: Dict[str, bytes] = {
            "/etc/passwd":
                b"root:x:0:0:root:/root:/bin/bash\r\n"
                b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
                b"bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n"
                b"ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\r\n"
                b"deploy:x:1001:1001::/home/deploy:/bin/bash\r\n",
            "/etc/shadow":
                b"root:$6$random$fakehash:19000:0:99999:7:::\r\n"
                b"ubuntu:$6$random$fakehash2:19000:0:99999:7:::\r\n",
            "/etc/hostname":   b"ubuntu-server\r\n",
            "/etc/os-release":
                b"NAME=\"Ubuntu\"\r\nVERSION=\"22.04.3 LTS (Jammy Jellyfish)\"\r\n"
                b"ID=ubuntu\r\nID_LIKE=debian\r\nPRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\r\n"
                b"VERSION_ID=\"22.04\"\r\nHOME_URL=\"https://www.ubuntu.com/\"\r\n",
            "/etc/hosts":
                b"127.0.0.1   localhost\r\n"
                b"127.0.1.1   ubuntu-server\r\n"
                b"::1         localhost ip6-localhost ip6-loopback\r\n",
            "/etc/resolv.conf":
                b"nameserver 8.8.8.8\r\nnameserver 8.8.4.4\r\n",
            "/etc/fstab":
                b"UUID=abc-123 /     ext4 defaults 0 1\r\n"
                b"UUID=def-456 /boot ext4 defaults 0 2\r\n",
            "/etc/sudoers":
                b"root    ALL=(ALL:ALL) ALL\r\n"
                b"%sudo   ALL=(ALL:ALL) ALL\r\n"
                b"ubuntu  ALL=(ALL) NOPASSWD: ALL\r\n",
            "/etc/ssh/sshd_config":
                b"Port 22\r\nAddressFamily any\r\nListenAddress 0.0.0.0\r\n"
                b"PermitRootLogin yes\r\nPasswordAuthentication yes\r\n"
                b"ChallengeResponseAuthentication no\r\n"
                b"UsePAM yes\r\nPrintMotd no\r\nAcceptEnv LANG LC_*\r\n"
                b"Subsystem sftp /usr/lib/openssh/sftp-server\r\n",
            "/root/.bashrc":
                b"# ~/.bashrc: executed by bash(1) for non-login shells.\r\n"
                b"export PS1='\\u@\\h:\\w\\$ '\r\nexport PATH=$PATH:/usr/local/bin\r\n"
                b"alias ll='ls -alF'\r\nalias la='ls -A'\r\nalias l='ls -CF'\r\n",
            "/root/.bash_history":
                b"ls -la\r\nwhoami\r\ncat /etc/passwd\r\nuname -a\r\n"
                b"ps aux\r\nnetstat -an\r\nip a\r\nhistory\r\n",
            "/root/.ssh/authorized_keys": b"",
            "/etc/crontab":
                b"SHELL=/bin/sh\r\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\r\n"
                b"17 *\t* * *\troot  cd / && run-parts --report /etc/cron.hourly\r\n"
                b"25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\r\n",
            "/proc/version":
                b"Linux version 5.15.0-91-generic (buildd@lcy02-amd64-059) "
                b"(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) "
                b"#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\r\n",
            "/proc/uptime":    b"86423.12 172641.98\r\n",
            "/proc/cpuinfo":
                b"processor\t: 0\r\nvendor_id\t: GenuineIntel\r\n"
                b"cpu family\t: 6\r\nmodel name\t: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\r\n"
                b"cpu MHz\t\t: 2400.058\r\ncache size\t: 30720 KB\r\n",
            "/proc/meminfo":
                b"MemTotal:        2048000 kB\r\nMemFree:          512000 kB\r\n"
                b"MemAvailable:    1024000 kB\r\nBuffers:           64000 kB\r\n"
                b"Cached:          256000 kB\r\n",
            "/var/www/html/index.html":
                b"<!DOCTYPE html><html><head><title>Apache2 Ubuntu Default Page</title></head>\r\n"
                b"<body><h1>Apache2 Ubuntu Default Page</h1><p>It works!</p></body></html>\r\n",
            "/var/log/auth.log":
                b"May  1 09:00:01 ubuntu-server sshd[1234]: Accepted password for root from 10.0.0.1 port 54321 ssh2\r\n"
                b"May  1 09:00:05 ubuntu-server sshd[1235]: Failed password for invalid user admin from 45.33.32.1 port 12345 ssh2\r\n",
        }

        # Virtual filesystem for session — tracks created files/dirs
        _session_fs: Dict[str, bytes] = {}   # path -> content
        _session_dirs: set = set()            # created directories
        _cwd = home

        def _resolve(path: str) -> str:
            """Resolve a path relative to cwd."""
            if not path or path == "~":
                return home
            if path.startswith("~/"):
                path = home + path[1:]
            if not path.startswith("/"):
                path = _cwd.rstrip("/") + "/" + path
            # Normalize
            parts = []
            for p in path.split("/"):
                if p == "..":
                    if parts:
                        parts.pop()
                elif p and p != ".":
                    parts.append(p)
            return "/" + "/".join(parts)

        def _ls_output(path: str) -> bytes:
            """Generate ls output for a path."""
            entries = _FS.get(path, [])
            # Add session-created entries
            for p in list(_session_fs.keys()) + list(_session_dirs):
                parent = "/".join(p.rstrip("/").split("/")[:-1]) or "/"
                name = p.rstrip("/").split("/")[-1]
                if parent == path and name not in entries:
                    entries = entries + [name]
            if not entries:
                return b""
            return ("  ".join(sorted(entries)) + "\r\n").encode()

        def _ls_long(path: str) -> bytes:
            """Generate ls -la output."""
            entries = _FS.get(path, [])
            for p in list(_session_fs.keys()) + list(_session_dirs):
                parent = "/".join(p.rstrip("/").split("/")[:-1]) or "/"
                name = p.rstrip("/").split("/")[-1]
                if parent == path and name not in entries:
                    entries = entries + [name]
            lines = [f"total {len(entries) * 4 + 8}"]
            lines.append("drwxr-xr-x  2 root root 4096 May  1 09:00 .")
            lines.append("drwxr-xr-x 20 root root 4096 May  1 09:00 ..")
            for e in sorted(entries):
                full = path.rstrip("/") + "/" + e
                is_dir = e in _FS.get(path, []) and (path + "/" + e in _FS or full in _session_dirs)
                perm = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                lines.append(f"{perm}  1 root root 4096 May  1 09:00 {e}")
            return ("\r\n".join(lines) + "\r\n").encode()

        for _ in range(500):   # max 500 commands per session
            # Dynamic prompt showing cwd
            display_cwd = _cwd.replace(home, "~") if _cwd.startswith(home) else _cwd
            prompt = f"{user}@{self.fake_hostname}:{display_cwd}$ ".encode()
            writer.write(prompt)
            await writer.drain()

            try:
                cmd_bytes = await asyncio.wait_for(reader.read(4096), timeout=180)
                cmd = cmd_bytes.decode(errors="ignore").strip()
            except asyncio.TimeoutError:
                break

            if not cmd:
                continue

            session.commands.append(cmd)
            await self.logger.log("honeypot_command", {
                "ip":      session.attacker_ip,
                "command": cmd,
                "cwd":     _cwd,
                "seq":     len(session.commands),
            })

            parts     = cmd.split()
            cmd_name  = parts[0] if parts else ""
            cmd_args  = parts[1:] if len(parts) > 1 else []
            cmd_lower = cmd_name.lower()

            await asyncio.sleep(random.uniform(0.03, 0.15))

            # ── exit / logout ────────────────────────────────────────────────
            if cmd_lower in ("exit", "logout", "quit"):
                writer.write(b"logout\r\n")
                await writer.drain()
                break

            # ── cd ───────────────────────────────────────────────────────────
            elif cmd_lower == "cd":
                target = cmd_args[0] if cmd_args else home
                new_path = _resolve(target)
                if new_path in _FS or new_path in _session_dirs:
                    _cwd = new_path
                else:
                    writer.write(f"bash: cd: {target}: No such file or directory\r\n".encode())

            # ── ls ───────────────────────────────────────────────────────────
            elif cmd_lower == "ls":
                flags = [a for a in cmd_args if a.startswith("-")]
                paths = [a for a in cmd_args if not a.startswith("-")]
                target = _resolve(paths[0]) if paths else _cwd
                long_fmt = any("l" in f for f in flags)
                all_fmt  = any("a" in f for f in flags)
                if long_fmt:
                    writer.write(_ls_long(target))
                else:
                    out = _ls_output(target)
                    writer.write(out if out else b"")

            # ── pwd ──────────────────────────────────────────────────────────
            elif cmd_lower == "pwd":
                writer.write((_cwd + "\r\n").encode())

            # ── cat ──────────────────────────────────────────────────────────
            elif cmd_lower == "cat":
                if not cmd_args:
                    writer.write(b"")
                else:
                    target = _resolve(cmd_args[0])
                    if target in _session_fs:
                        writer.write(_session_fs[target] + b"\r\n")
                    elif target in _FILE_CONTENTS:
                        writer.write(_FILE_CONTENTS[target])
                    else:
                        # Check if it's a directory or doesn't exist
                        if target in _FS or target in _session_dirs:
                            writer.write(f"cat: {cmd_args[0]}: Is a directory\r\n".encode())
                        else:
                            writer.write(f"cat: {cmd_args[0]}: No such file or directory\r\n".encode())

            # ── echo / redirect (echo "x" > file) ───────────────────────────
            elif cmd_lower == "echo":
                if ">" in cmd or ">>" in cmd:
                    # Parse redirect: echo "content" > /path/file
                    try:
                        append = ">>" in cmd
                        sep    = ">>" if append else ">"
                        left, right = cmd.split(sep, 1)
                        content = left.replace("echo", "", 1).strip().strip('"').strip("'")
                        dest    = _resolve(right.strip())
                        data    = (content + "\n").encode()
                        if append and dest in _session_fs:
                            _session_fs[dest] += data
                        else:
                            _session_fs[dest] = data
                    except Exception:
                        writer.write(b"")
                else:
                    text = cmd[5:].strip().strip('"').strip("'") if len(cmd) > 5 else ""
                    writer.write((text + "\r\n").encode())

            # ── touch ────────────────────────────────────────────────────────
            elif cmd_lower == "touch":
                for arg in cmd_args:
                    target = _resolve(arg)
                    if target not in _session_fs and target not in _FILE_CONTENTS:
                        _session_fs[target] = b""

            # ── mkdir ────────────────────────────────────────────────────────
            elif cmd_lower == "mkdir":
                for arg in cmd_args:
                    if arg.startswith("-"):
                        continue
                    target = _resolve(arg)
                    _session_dirs.add(target)
                    if target not in _FS:
                        _FS[target] = []

            # ── rm ───────────────────────────────────────────────────────────
            elif cmd_lower == "rm":
                real_args = [a for a in cmd_args if not a.startswith("-")]
                recursive = "-r" in cmd_args or "-rf" in cmd_args or "-fr" in cmd_args
                for arg in real_args:
                    target = _resolve(arg)
                    if target in _session_fs:
                        del _session_fs[target]
                    elif target in _FILE_CONTENTS:
                        writer.write(f"rm: cannot remove '{arg}': Permission denied\r\n".encode())
                    elif target in _session_dirs and recursive:
                        _session_dirs.discard(target)
                    elif target in _FS:
                        writer.write(f"rm: cannot remove '{arg}': Permission denied\r\n".encode())
                    else:
                        writer.write(f"rm: cannot remove '{arg}': No such file or directory\r\n".encode())

            # ── cp ───────────────────────────────────────────────────────────
            elif cmd_lower == "cp":
                real_args = [a for a in cmd_args if not a.startswith("-")]
                if len(real_args) >= 2:
                    src  = _resolve(real_args[0])
                    dest = _resolve(real_args[1])
                    content = _session_fs.get(src) or _FILE_CONTENTS.get(src)
                    if content is not None:
                        _session_fs[dest] = content
                    else:
                        writer.write(f"cp: cannot stat '{real_args[0]}': No such file or directory\r\n".encode())

            # ── mv ───────────────────────────────────────────────────────────
            elif cmd_lower == "mv":
                real_args = [a for a in cmd_args if not a.startswith("-")]
                if len(real_args) >= 2:
                    src  = _resolve(real_args[0])
                    dest = _resolve(real_args[1])
                    if src in _session_fs:
                        _session_fs[dest] = _session_fs.pop(src)
                    else:
                        writer.write(f"mv: cannot stat '{real_args[0]}': No such file or directory\r\n".encode())

            # ── chmod ────────────────────────────────────────────────────────
            elif cmd_lower == "chmod":
                pass   # silently succeed

            # ── chown ────────────────────────────────────────────────────────
            elif cmd_lower == "chown":
                pass   # silently succeed

            # ── whoami / id ──────────────────────────────────────────────────
            elif cmd_lower == "whoami":
                writer.write(f"{user}\r\n".encode())

            elif cmd_lower == "id":
                uid = "0" if user == "root" else "1000"
                writer.write(f"uid={uid}({user}) gid={uid}({user}) groups={uid}({user})\r\n".encode())

            # ── uname ────────────────────────────────────────────────────────
            elif cmd_lower == "uname":
                if "-a" in cmd_args:
                    writer.write(f"Linux {self.fake_hostname} 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n".encode())
                elif "-r" in cmd_args:
                    writer.write(b"5.15.0-91-generic\r\n")
                elif "-s" in cmd_args:
                    writer.write(b"Linux\r\n")
                elif "-n" in cmd_args:
                    writer.write(f"{self.fake_hostname}\r\n".encode())
                else:
                    writer.write(b"Linux\r\n")

            # ── hostname ─────────────────────────────────────────────────────
            elif cmd_lower == "hostname":
                writer.write(f"{self.fake_hostname}\r\n".encode())

            # ── uptime ───────────────────────────────────────────────────────
            elif cmd_lower == "uptime":
                writer.write(b" 09:00:01 up 1 day,  0:03,  1 user,  load average: 0.08, 0.03, 0.01\r\n")

            # ── ps ───────────────────────────────────────────────────────────
            elif cmd_lower == "ps":
                writer.write(
                    b"USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"
                    b"root         1  0.0  0.1  37400  5988 ?        Ss   May01   0:01 /sbin/init\r\n"
                    b"root       412  0.0  0.2  65432  8192 ?        Ss   May01   0:00 /usr/sbin/sshd -D\r\n"
                    b"root      1234  0.0  0.1  16124  3200 pts/0    Ss   09:00   0:00 -bash\r\n"
                    b"root      1337  0.0  0.0  12784  1856 pts/0    R+   09:00   0:00 ps aux\r\n"
                )

            # ── top ──────────────────────────────────────────────────────────
            elif cmd_lower == "top":
                writer.write(
                    b"top - 09:00:01 up 1 day,  0:03,  1 user,  load average: 0.08, 0.03, 0.01\r\n"
                    b"Tasks:  72 total,   1 running,  71 sleeping,   0 stopped,   0 zombie\r\n"
                    b"%Cpu(s):  0.3 us,  0.1 sy,  0.0 ni, 99.5 id,  0.0 wa,  0.0 hi,  0.1 si\r\n"
                    b"MiB Mem :   1990.7 total,    512.3 free,    498.2 used,    980.2 buff/cache\r\n\r\n"
                    b"  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\r\n"
                    b"    1 root      20   0   37400   5988   3844 S   0.0   0.3   0:01.23 systemd\r\n"
                    b"  412 root      20   0   65432   8192   6144 S   0.0   0.4   0:00.45 sshd\r\n"
                )

            # ── df ───────────────────────────────────────────────────────────
            elif cmd_lower == "df":
                writer.write(
                    b"Filesystem      1K-blocks    Used Available Use% Mounted on\r\n"
                    b"udev               987832       0    987832   0% /dev\r\n"
                    b"tmpfs              203692    1076    202616   1% /run\r\n"
                    b"/dev/xvda1       20511312 4821256  14634372  25% /\r\n"
                    b"tmpfs             1018456       0   1018456   0% /dev/shm\r\n"
                )

            # ── free ─────────────────────────────────────────────────────────
            elif cmd_lower == "free":
                writer.write(
                    b"               total        used        free      shared  buff/cache   available\r\n"
                    b"Mem:         2037760      510080      524288        1076      1003392     1050000\r\n"
                    b"Swap:              0           0           0\r\n"
                )

            # ── env / printenv ───────────────────────────────────────────────
            elif cmd_lower in ("env", "printenv"):
                writer.write((
                    f"USER={user}\r\nHOME={home}\r\nSHELL=/bin/bash\r\n"
                    f"TERM=xterm-256color\r\nLANG=en_US.UTF-8\r\n"
                    f"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\n"
                    f"MAIL=/var/mail/root\r\nLOGNAME=root\r\n"
                ).encode())

            # ── history ──────────────────────────────────────────────────────
            elif cmd_lower == "history":
                hist = [f"    {i+1}  {c}" for i, c in enumerate(session.commands[:-1])]
                writer.write(("\r\n".join(hist) + "\r\n").encode() if hist else b"")

            # ── which / type ─────────────────────────────────────────────────
            elif cmd_lower in ("which", "type"):
                bins = {
                    "ls": "/bin/ls", "cat": "/bin/cat", "echo": "/bin/echo",
                    "bash": "/bin/bash", "sh": "/bin/sh", "python3": "/usr/bin/python3",
                    "python": "/usr/bin/python3", "perl": "/usr/bin/perl",
                    "nc": "/bin/nc", "wget": "/usr/bin/wget", "curl": "/usr/bin/curl",
                    "ssh": "/usr/bin/ssh", "scp": "/usr/bin/scp",
                    "apt": "/usr/bin/apt", "apt-get": "/usr/bin/apt-get",
                    "systemctl": "/bin/systemctl", "service": "/usr/sbin/service",
                    "iptables": "/sbin/iptables", "netstat": "/bin/netstat",
                    "ss": "/bin/ss", "ip": "/sbin/ip", "ifconfig": "/sbin/ifconfig",
                }
                for arg in cmd_args:
                    if arg in bins:
                        writer.write((bins[arg] + "\r\n").encode())
                    else:
                        writer.write(f"{arg} not found\r\n".encode())

            # ── ip / ifconfig ────────────────────────────────────────────────
            elif cmd_lower == "ip":
                writer.write(
                    b"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\r\n"
                    b"    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\r\n"
                    b"    inet 127.0.0.1/8 scope host lo\r\n"
                    b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\r\n"
                    b"    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff\r\n"
                    b"    inet 10.0.0.1/24 brd 10.0.0.255 scope global eth0\r\n"
                )

            elif cmd_lower == "ifconfig":
                writer.write(
                    b"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
                    b"        inet 10.0.0.1  netmask 255.255.255.0  broadcast 10.0.0.255\r\n"
                    b"        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)\r\n"
                    b"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n"
                    b"        inet 127.0.0.1  netmask 255.0.0.0\r\n"
                )

            # ── netstat / ss ─────────────────────────────────────────────────
            elif cmd_lower in ("netstat", "ss"):
                writer.write(
                    b"Netid State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port\r\n"
                    b"tcp   LISTEN 0      128     0.0.0.0:22           0.0.0.0:*\r\n"
                    b"tcp   LISTEN 0      128     0.0.0.0:80           0.0.0.0:*\r\n"
                    b"tcp   ESTAB  0      0       10.0.0.1:22          10.0.0.2:54321\r\n"
                )

            # ── iptables ─────────────────────────────────────────────────────
            elif cmd_lower == "iptables":
                writer.write(
                    b"Chain INPUT (policy ACCEPT)\r\n"
                    b"target     prot opt source               destination\r\n"
                    b"ACCEPT     all  --  anywhere             anywhere   state RELATED,ESTABLISHED\r\n"
                    b"Chain FORWARD (policy DROP)\r\ntarget     prot opt source               destination\r\n"
                    b"Chain OUTPUT (policy ACCEPT)\r\ntarget     prot opt source               destination\r\n"
                )

            # ── crontab ──────────────────────────────────────────────────────
            elif cmd_lower == "crontab":
                if "-l" in cmd_args:
                    writer.write(b"no crontab for root\r\n")
                elif "-e" in cmd_args:
                    writer.write(b"")   # silently open editor (attacker sees nothing)

            # ── systemctl / service ──────────────────────────────────────────
            elif cmd_lower == "systemctl":
                if cmd_args and cmd_args[0] == "status":
                    svc = cmd_args[1] if len(cmd_args) > 1 else "unknown"
                    writer.write(f"* {svc}.service - {svc.capitalize()} Service\r\n"
                                 f"   Loaded: loaded (/lib/systemd/system/{svc}.service; enabled)\r\n"
                                 f"   Active: active (running) since Tue 2024-01-01 00:00:00 UTC\r\n".encode())
                elif cmd_args and cmd_args[0] in ("start", "stop", "restart"):
                    writer.write(b"")   # silently succeed
                else:
                    writer.write(b"")

            # ── apt / apt-get ────────────────────────────────────────────────
            elif cmd_lower in ("apt", "apt-get"):
                writer.write(b"E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\r\n"
                              b"E: Unable to acquire the dpkg frontend lock, are you root?\r\n")

            # ── find ─────────────────────────────────────────────────────────
            elif cmd_lower == "find":
                path_arg = cmd_args[0] if cmd_args and not cmd_args[0].startswith("-") else _cwd
                resolved = _resolve(path_arg)
                entries  = _FS.get(resolved, [])
                lines    = [resolved]
                for e in entries[:20]:
                    lines.append(f"{resolved.rstrip('/')}/{e}")
                writer.write(("\r\n".join(lines) + "\r\n").encode())

            # ── grep ─────────────────────────────────────────────────────────
            elif cmd_lower == "grep":
                # For grep on real file contents, do basic search
                if len(cmd_args) >= 2:
                    pattern  = cmd_args[0].lstrip("-").strip('"').strip("'") if not cmd_args[0].startswith("-") else cmd_args[1] if len(cmd_args) > 1 else ""
                    filepath = _resolve(cmd_args[-1]) if not cmd_args[-1].startswith("-") else ""
                    content  = _session_fs.get(filepath) or _FILE_CONTENTS.get(filepath, b"")
                    if content and pattern:
                        matches = [l for l in content.decode(errors="ignore").split("\n") if pattern.lower() in l.lower()]
                        writer.write(("\r\n".join(matches) + "\r\n").encode() if matches else b"")

            # ── wc ───────────────────────────────────────────────────────────
            elif cmd_lower == "wc":
                if cmd_args:
                    target = _resolve(cmd_args[-1])
                    content = _session_fs.get(target) or _FILE_CONTENTS.get(target, b"")
                    lines   = content.count(b"\n")
                    words   = len(content.split())
                    writer.write(f"  {lines}  {words}  {len(content)} {cmd_args[-1]}\r\n".encode())

            # ── wget / curl — simulate timeout ───────────────────────────────
            elif cmd_lower in ("wget", "curl"):
                await asyncio.sleep(random.uniform(4, 10))
                if cmd_lower == "wget":
                    url = next((a for a in cmd_args if a.startswith("http")), "URL")
                    writer.write((
                        f"--2024-01-01 09:00:00--  {url}\r\n"
                        f"Resolving... failed: Name or service not known.\r\n"
                        f"wget: unable to resolve host address\r\n"
                    ).encode())
                else:
                    writer.write(b"curl: (6) Could not resolve host\r\n")

            # ── nc / ncat / netcat ───────────────────────────────────────────
            elif cmd_lower in ("nc", "ncat", "netcat"):
                await asyncio.sleep(random.uniform(5, 15))
                writer.write(b"")   # timeout silently

            # ── python / python3 / perl / ruby ───────────────────────────────
            elif cmd_lower in ("python", "python3"):
                if "-c" in cmd_args:
                    await asyncio.sleep(random.uniform(0.5, 1.5))
                    writer.write(b"")   # silently run (do nothing)
                else:
                    writer.write(b"Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux\r\n"
                                 b"Type \"help\", \"copyright\", \"credits\" or \"license\" for more information.\r\n"
                                 b">>> ")
                    await writer.drain()
                    # Read one line then exit
                    try:
                        await asyncio.wait_for(reader.read(256), timeout=10)
                    except asyncio.TimeoutError:
                        pass
                    writer.write(b"\r\n")

            elif cmd_lower in ("perl", "ruby", "php"):
                await asyncio.sleep(random.uniform(1, 3))
                writer.write(b"")

            # ── bash / sh ────────────────────────────────────────────────────
            elif cmd_lower in ("bash", "sh"):
                if "-c" in cmd_args:
                    # Execute as nested command
                    idx = cmd_args.index("-c")
                    if idx + 1 < len(cmd_args):
                        nested = cmd_args[idx + 1].strip('"').strip("'")
                        session.commands.append(f"[nested] {nested}")
                        await self.logger.log("honeypot_command", {
                            "ip": session.attacker_ip, "command": f"[nested] {nested}",
                            "seq": len(session.commands),
                        })
                        writer.write(b"")
                    else:
                        writer.write(b"")
                else:
                    writer.write(b"")   # spawn subshell silently

            # ── sudo ─────────────────────────────────────────────────────────
            elif cmd_lower == "sudo":
                if user == "root":
                    # Already root — just run rest of command (ignore)
                    writer.write(b"")
                else:
                    writer.write(b"[sudo] password for " + user.encode() + b": \r\n"
                                 b"Sorry, try again.\r\n")

            # ── passwd ───────────────────────────────────────────────────────
            elif cmd_lower == "passwd":
                writer.write(b"Changing password for root.\r\nCurrent password: ")
                await writer.drain()
                try:
                    await asyncio.wait_for(reader.read(256), timeout=15)
                except asyncio.TimeoutError:
                    pass
                writer.write(b"New password: ")
                await writer.drain()
                try:
                    await asyncio.wait_for(reader.read(256), timeout=15)
                except asyncio.TimeoutError:
                    pass
                writer.write(b"Retype new password: ")
                await writer.drain()
                try:
                    await asyncio.wait_for(reader.read(256), timeout=15)
                except asyncio.TimeoutError:
                    pass
                writer.write(b"passwd: password updated successfully\r\n")

            # ── clear / reset ────────────────────────────────────────────────
            elif cmd_lower in ("clear", "reset"):
                writer.write(b"\033[2J\033[H")   # ANSI clear screen

            # ── date ─────────────────────────────────────────────────────────
            elif cmd_lower == "date":
                from datetime import datetime, timezone
                writer.write((datetime.now(timezone.utc).strftime(
                    "Wed May  1 09:00:01 UTC 2024") + "\r\n").encode())

            # ── last ─────────────────────────────────────────────────────────
            elif cmd_lower == "last":
                writer.write(
                    b"root     pts/0        10.0.0.2         Tue Jan  1 00:00   still logged in\r\n"
                    b"root     pts/0        10.0.0.3         Mon Dec 31 23:55 - 23:58  (00:03)\r\n"
                    b"wtmp begins Mon Dec 25 00:00:00 2023\r\n"
                )

            # ── w / who ──────────────────────────────────────────────────────
            elif cmd_lower in ("w", "who"):
                writer.write(
                    b" 09:00:01 up 1 day,  0:03,  1 user,  load average: 0.08, 0.03, 0.01\r\n"
                    b"USER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT\r\n"
                    b"root     pts/0    10.0.0.2         09:00    0.00s  0.02s  0.00s w\r\n"
                )

            # ── lsb_release ──────────────────────────────────────────────────
            elif cmd_lower == "lsb_release":
                writer.write(
                    b"No LSB modules are available.\r\n"
                    b"Distributor ID:\tUbuntu\r\nDescription:\tUbuntu 22.04.3 LTS\r\n"
                    b"Release:\t22.04\r\nCodename:\tjammy\r\n"
                )

            # ── dpkg / rpm ───────────────────────────────────────────────────
            elif cmd_lower in ("dpkg", "rpm"):
                writer.write(b"dpkg-query: no packages found matching *\r\n"
                              if "-l" in cmd_args else b"")

            # ── unknown command ───────────────────────────────────────────────
            else:
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