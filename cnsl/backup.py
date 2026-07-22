"""
cnsl/backup.py — Backup and restore for CNSL state.

Bundles into a single tar.gz:
  - config file (config.json / .yaml)
  - main store DB (SQLite only — consistent point-in-time snapshot via
    sqlite3's native .backup() API, safe even while CNSL is running)
  - FIM baseline DB (SQLite, same snapshot method)
  - manifest.json describing what's included and where each file
    belongs on restore

PostgreSQL-backed stores are NOT snapshotted here — Postgres needs
pg_dump/pg_restore, which is a separate operational concern. The
manifest records the backend so restore never silently claims to
have restored something it didn't.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
from typing import Any, Callable, Dict, List, Optional

from . import __version__
from .models import iso_time


def _sqlite_snapshot(src_path: str, dest_path: str) -> bool:
    """
    Consistent point-in-time copy of a SQLite DB via sqlite3's native
    backup API. Unlike a plain file copy, this is safe to run against
    a DB that's open elsewhere (e.g. CNSL still running) and correctly
    picks up data sitting in the WAL that a raw `cp` would miss.
    """
    if not src_path or not os.path.exists(src_path):
        return False
    src = sqlite3.connect(src_path)
    try:
        dest = sqlite3.connect(dest_path)
        try:
            src.backup(dest)
        finally:
            dest.close()
    finally:
        src.close()
    return True


def create_backup(cfg: Dict[str, Any], config_path: Optional[str], out_path: str) -> Dict[str, Any]:
    """
    Build a backup tar.gz at out_path.

    Returns {"path": out_path, "included": [...], "skipped": [...]} —
    "included"/"skipped" are human-readable descriptions for CLI output.
    """
    included: List[str] = []
    skipped:  List[str] = []

    with tempfile.TemporaryDirectory(prefix="cnsl_backup_") as tmp:
        manifest: Dict[str, Any] = {
            "cnsl_version": __version__,
            "created": iso_time(),
            "files": {},
        }

        # Config file
        if config_path and os.path.exists(config_path):
            shutil.copy2(config_path, os.path.join(tmp, "config.json"))
            manifest["files"]["config"] = {"archive_name": "config.json", "restore_path": config_path}
            included.append(f"config: {config_path}")
        else:
            skipped.append("config file (not found)")

        # Main store DB
        store_cfg = cfg.get("store", {})
        backend = store_cfg.get("backend", "sqlite")
        db_path = store_cfg.get("db_path", "./cnsl_state.db")
        if backend == "sqlite":
            if _sqlite_snapshot(db_path, os.path.join(tmp, "cnsl_state.db")):
                manifest["files"]["store_db"] = {"archive_name": "cnsl_state.db", "restore_path": db_path}
                included.append(f"store DB: {db_path}")
            else:
                skipped.append(f"store DB (not found: {db_path})")
        else:
            manifest["skipped_backend"] = backend
            skipped.append(f"store DB (backend={backend} — use pg_dump/pg_restore separately)")

        # FIM baseline DB
        fim_db_path = cfg.get("fim", {}).get("db_path", "./cnsl_fim.db")
        if _sqlite_snapshot(fim_db_path, os.path.join(tmp, "cnsl_fim.db")):
            manifest["files"]["fim_db"] = {"archive_name": "cnsl_fim.db", "restore_path": fim_db_path}
            included.append(f"FIM baseline DB: {fim_db_path}")
        else:
            skipped.append(f"FIM baseline DB (not found: {fim_db_path})")

        with open(os.path.join(tmp, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2)

        out_dir = os.path.dirname(os.path.abspath(out_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)

        with tarfile.open(out_path, "w:gz") as tar:
            for name in os.listdir(tmp):
                tar.add(os.path.join(tmp, name), arcname=name)

    return {"path": out_path, "included": included, "skipped": skipped}


def _safe_extract(tar: tarfile.TarFile, path: str) -> None:
    """Extract a tarfile, refusing any member that would escape `path`
    (path traversal / absolute-path guard). Backups are self-produced,
    but restore is a destructive operation so we check anyway."""
    base = os.path.abspath(path)
    for member in tar.getmembers():
        member_path = os.path.abspath(os.path.join(base, member.name))
        if not member_path.startswith(base + os.sep) and member_path != base:
            raise ValueError(f"Unsafe path in backup archive: {member.name}")
    # filter="data" opts in to Python 3.12+'s safer extraction mode now,
    # instead of warning about (and later defaulting to) it in 3.14.
    try:
        tar.extractall(path, filter="data")
    except TypeError:
        # Python < 3.12 doesn't support the filter kwarg.
        tar.extractall(path)


def read_manifest(backup_path: str) -> Dict[str, Any]:
    """Peek at a backup's manifest without restoring anything."""
    with tarfile.open(backup_path, "r:gz") as tar:
        f = tar.extractfile(tar.getmember("manifest.json"))
        if f is None:
            raise ValueError("Backup archive is missing manifest.json")
        return json.loads(f.read().decode("utf-8"))


def restore_backup(
    backup_path: str,
    force: bool = False,
    confirm: Optional[Callable[[str], bool]] = None,
) -> Dict[str, Any]:
    """
    Restore files from a backup tar.gz to the locations recorded in
    the backup's own manifest.

    - force=True overwrites existing files without asking.
    - confirm(path) -> bool, if given, is called per existing file to
      decide whether to overwrite it (used by the CLI for an
      interactive y/N prompt).
    - If neither is given, existing files are left untouched and
      reported as skipped.
    """
    if not os.path.exists(backup_path):
        raise FileNotFoundError(f"Backup file not found: {backup_path}")

    manifest = read_manifest(backup_path)
    restored: List[str] = []
    skipped:  List[str] = []

    with tempfile.TemporaryDirectory(prefix="cnsl_restore_") as tmp:
        with tarfile.open(backup_path, "r:gz") as tar:
            _safe_extract(tar, tmp)

        for key, info in manifest.get("files", {}).items():
            archive_name = info["archive_name"]
            restore_path = info["restore_path"]
            src = os.path.join(tmp, archive_name)
            if not os.path.exists(src):
                skipped.append(f"{key} (missing from archive)")
                continue

            if os.path.exists(restore_path) and not force:
                proceed = confirm(restore_path) if confirm else False
                if not proceed:
                    skipped.append(f"{key} (exists, not overwritten: {restore_path})")
                    continue

            dest_dir = os.path.dirname(os.path.abspath(restore_path))
            if dest_dir:
                os.makedirs(dest_dir, exist_ok=True)
            shutil.copy2(src, restore_path)
            restored.append(f"{key}: {restore_path}")

    return {"manifest": manifest, "restored": restored, "skipped": skipped}