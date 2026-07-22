"""
tests/test_backup.py -- tests for cnsl/backup.py (backup/restore CLI feature).
"""

from __future__ import annotations

import os
import sqlite3
import tempfile

import pytest

from cnsl.backup import create_backup, restore_backup, read_manifest


def _make_sqlite(path: str, table: str, row) -> None:
    conn = sqlite3.connect(path)
    conn.execute(f"CREATE TABLE {table} (v TEXT)")
    conn.execute(f"INSERT INTO {table} VALUES (?)", (row,))
    conn.commit()
    conn.close()


def _read_sqlite(path: str, table: str):
    conn = sqlite3.connect(path)
    rows = conn.execute(f"SELECT v FROM {table}").fetchall()
    conn.close()
    return [r[0] for r in rows]


class TestBackupCreate:
    """create_backup() bundles config + store DB + FIM DB into a tar.gz."""

    def test_backup_includes_all_present_files(self, tmp_path):
        db_path  = str(tmp_path / "state.db")
        fim_path = str(tmp_path / "fim.db")
        cfg_path = str(tmp_path / "config.json")
        out_path = str(tmp_path / "backup.tar.gz")

        _make_sqlite(db_path, "events", "hello")
        _make_sqlite(fim_path, "baseline", "/etc/passwd")
        with open(cfg_path, "w") as f:
            f.write('{"store": {"db_path": "state.db"}}')

        cfg = {"store": {"backend": "sqlite", "db_path": db_path},
               "fim": {"db_path": fim_path}}

        result = create_backup(cfg, cfg_path, out_path)
        assert os.path.exists(out_path)
        assert len(result["included"]) == 3
        assert not result["skipped"]

    def test_backup_reports_missing_files_as_skipped(self, tmp_path):
        out_path = str(tmp_path / "backup.tar.gz")
        cfg = {"store": {"backend": "sqlite", "db_path": str(tmp_path / "nope.db")},
               "fim": {"db_path": str(tmp_path / "nope_fim.db")}}

        result = create_backup(cfg, None, out_path)
        assert os.path.exists(out_path)
        assert not result["included"]
        assert len(result["skipped"]) == 3  # config, store db, fim db

    def test_backup_notes_postgres_backend_skipped(self, tmp_path):
        out_path = str(tmp_path / "backup.tar.gz")
        cfg = {"store": {"backend": "postgresql", "dsn": "postgresql://x"},
               "fim": {"db_path": str(tmp_path / "nope_fim.db")}}

        result = create_backup(cfg, None, out_path)
        assert any("postgresql" in s for s in result["skipped"])
        manifest = read_manifest(out_path)
        assert manifest.get("skipped_backend") == "postgresql"


class TestBackupRestore:
    """restore_backup() puts files back where the manifest says they came from."""

    def _make_backup(self, tmp_path):
        db_path  = str(tmp_path / "state.db")
        fim_path = str(tmp_path / "fim.db")
        cfg_path = str(tmp_path / "config.json")
        out_path = str(tmp_path / "backup.tar.gz")

        _make_sqlite(db_path, "events", "original")
        _make_sqlite(fim_path, "baseline", "/etc/shadow")
        with open(cfg_path, "w") as f:
            f.write('{"a": 1}')

        cfg = {"store": {"backend": "sqlite", "db_path": db_path},
               "fim": {"db_path": fim_path}}
        create_backup(cfg, cfg_path, out_path)
        return out_path, db_path, fim_path, cfg_path

    def test_restore_round_trip_after_deletion(self, tmp_path):
        out_path, db_path, fim_path, cfg_path = self._make_backup(tmp_path)

        os.remove(db_path)
        os.remove(fim_path)
        os.remove(cfg_path)

        result = restore_backup(out_path, force=True)
        assert set(_read_sqlite(db_path, "events")) == {"original"}
        assert set(_read_sqlite(fim_path, "baseline")) == {"/etc/shadow"}
        assert os.path.exists(cfg_path)
        assert len(result["restored"]) == 3
        assert not result["skipped"]

    def test_restore_skips_existing_files_without_force(self, tmp_path):
        out_path, db_path, fim_path, cfg_path = self._make_backup(tmp_path)
        # Files still exist (never deleted) -- default behavior without
        # force or a confirm callback must leave them untouched.
        result = restore_backup(out_path, force=False)
        assert not result["restored"]
        assert len(result["skipped"]) == 3

    def test_restore_confirm_callback_controls_overwrite(self, tmp_path):
        out_path, db_path, fim_path, cfg_path = self._make_backup(tmp_path)
        # Mutate the live DB so we can tell if restore actually overwrote it.
        conn = sqlite3.connect(db_path)
        conn.execute("INSERT INTO events VALUES ('mutated')")
        conn.commit()
        conn.close()

        # Only approve overwriting the store DB, decline everything else.
        def confirm(path):
            return path == db_path

        result = restore_backup(out_path, force=False, confirm=confirm)
        assert any("state.db" in r or "store_db" in r for r in result["restored"])
        assert len(result["restored"]) == 1
        assert len(result["skipped"]) == 2
        assert _read_sqlite(db_path, "events") == ["original"]

    def test_restore_missing_backup_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            restore_backup(str(tmp_path / "does_not_exist.tar.gz"))