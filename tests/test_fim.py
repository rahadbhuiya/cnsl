"""
tests/test_fim.py -- split from test_cnsl.py (v3.4.3 test suite reorg).

Run:
    pytest tests/test_fim.py -v
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from unittest.mock import AsyncMock, MagicMock

import pytest

from cnsl.config import DEFAULT_CONFIG, load_config, safe_int
from cnsl.models import Event, EventKind, Severity, iso_time, now
from cnsl.parsers import parse_auth_event, parse_tcpdump_hint
from cnsl.detector import Detector, IPState, _prune, _unique_users

from helpers import make_cfg, make_detector, _run, _det, _make_cm, _SKLEARN_AVAILABLE


class TestFIMDirectoryScanning:
    """_collect_paths must recurse into directories, not only check isfile()."""

    def test_directory_in_watch_paths_is_scanned(self):
        import tempfile, os
        from unittest.mock import MagicMock, patch

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file inside the temp directory
            test_file = os.path.join(tmpdir, "test_file.conf")
            with open(test_file, "w") as f:
                f.write("test content")

            # Build a minimal FIMEngine-like object using _collect_paths logic directly
            # (avoids needing a full DB / logger for a unit test)
            from cnsl.fim import FIMEngine
            logger = AsyncMock()
            cfg = {
                "fim": {
                    "enabled": True,
                    "watch_paths": [tmpdir],   # a DIRECTORY, not a file
                    "watch_dirs": [],
                    "scan_interval_sec": 60,
                }
            }
            fim = FIMEngine(cfg, logger)
            paths = fim._collect_paths()

            assert test_file in paths, (
                f"File inside watched directory not found in collected paths. "
                f"Got: {paths}"
            )

    def test_file_in_watch_paths_still_works(self):
        """Individual files in watch_paths must still be collected."""
        import tempfile, os
        from cnsl.fim import FIMEngine

        with tempfile.NamedTemporaryFile(delete=False) as f:
            test_file = f.name

        try:
            logger = AsyncMock()
            cfg = {
                "fim": {
                    "enabled": True,
                    "watch_paths": [test_file],
                    "watch_dirs": [],
                    "scan_interval_sec": 60,
                }
            }
            fim = FIMEngine(cfg, logger)
            paths = fim._collect_paths()
            assert test_file in paths
        finally:
            os.unlink(test_file)

    def test_nonexistent_path_ignored(self):
        """Missing paths must not crash _collect_paths."""
        from cnsl.fim import FIMEngine
        logger = AsyncMock()
        cfg = {
            "fim": {
                "enabled": True,
                "watch_paths": ["/nonexistent/path/cnsl_test"],
                "watch_dirs": [],
                "scan_interval_sec": 60,
            }
        }
        fim = FIMEngine(cfg, logger)
        paths = fim._collect_paths()
        assert isinstance(paths, list)


# v1.0.2 — ML retrain timer fix
