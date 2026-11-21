"""Server-side drafts and immutable generated versions for CNSL config."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .config import DEFAULT_CONFIG, _deep_copy, _deep_merge, _read_file, resolve_config_path
from .validator import validate_config

_UNCHANGED_SECRET = {"__cnsl_secret__": "unchanged"}
_SECRET_NAMES = {
    "password", "passwd", "secret", "secret_key", "secret_value", "token",
    "api_key", "private_key", "password_hash", "totp_backup_codes", "webhook_url",
    "dsn", "authorization", "bearer", "shared_key", "access_key_id",
}


def _is_secret(key: str, parents: Sequence[str] = ()) -> bool:
    name = key.lower()
    return (name in _SECRET_NAMES
            or name.endswith(("_password", "_passwd", "_secret", "_token", "_api_key",
                              "_private_key", "_credential", "_access_key", "_signing_key"))
            or (name.startswith("secret_") and name.endswith("_key"))
            or (name in ("url", "uri") and any(p.lower() in ("webhook", "discord", "slack") for p in parents)))


def _copy(value: Any) -> Any:
    return copy.deepcopy(value)


def _merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = _copy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = _copy(value)
    return result


def _walk_secret_paths(value: Any, prefix: str = "", parents: Sequence[str] = ()) -> List[str]:
    paths: List[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else key
            if _is_secret(str(key), parents) and child not in (None, "", [], {}):
                paths.append(path)
            elif isinstance(child, (dict, list)):
                paths.extend(_walk_secret_paths(child, path, (*parents, str(key))))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(_walk_secret_paths(child, f"{prefix}[{index}]", parents))
    return paths


def _mask(value: Any, parents: Sequence[str] = ()) -> Any:
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            if _is_secret(str(key), parents):
                result[key] = _copy(_UNCHANGED_SECRET) if child not in (None, "", [], {}) else None
            else:
                result[key] = _mask(child, (*parents, str(key)))
        return result
    if isinstance(value, list):
        return [_mask(child, parents) for child in value]
    return _copy(value)


def _restore_unchanged_secrets(candidate: Any, current: Any, parents: Sequence[str] = ()) -> Any:
    if isinstance(candidate, dict) and isinstance(current, dict):
        out = {}
        for key, value in candidate.items():
            old = current.get(key)
            if _is_secret(str(key), parents) and value == _UNCHANGED_SECRET:
                out[key] = _copy(old)
            else:
                out[key] = _restore_unchanged_secrets(value, old, (*parents, str(key)))
        return out
    if isinstance(candidate, list) and isinstance(current, list):
        return [_restore_unchanged_secrets(v, current[i] if i < len(current) else None, parents)
                for i, v in enumerate(candidate)]
    return _copy(candidate)


def _flatten(value: Any, prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else key
            out.update(_flatten(child, path))
    else:
        out[prefix] = value
    return out


def _contains_secret(value: Any, parents: Sequence[str] = ()) -> bool:
    if isinstance(value, dict):
        return any(_is_secret(str(key), parents) or _contains_secret(child, (*parents, str(key)))
                   for key, child in value.items())
    if isinstance(value, list):
        return any(_contains_secret(child, parents) for child in value)
    return False


def _redact_nested(value: Any, parents: Sequence[str] = ()) -> Any:
    if isinstance(value, dict):
        return {key: ("[redacted]" if _is_secret(str(key), parents) and child not in (None, "", [], {})
                      else _redact_nested(child, (*parents, str(key)))) for key, child in value.items()}
    if isinstance(value, list):
        return [_redact_nested(child, parents) for child in value]
    return _copy(value)


def _kind(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "object"
    return "null"


def _schema(value: Any, segments: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    segments = segments or []
    fields: List[Dict[str, Any]] = []
    if not isinstance(value, dict):
        return fields
    for key, child in value.items():
        path_parts = segments + [str(key)]
        path = ".".join(path_parts)
        if isinstance(child, dict):
            fields.extend(_schema(child, path_parts))
            if not child:
                fields.append({"path": path, "segments": path_parts, "type": "object", "secret": False})
            continue
        secret = _is_secret(str(key), segments)
        item: Dict[str, Any] = {"path": path, "segments": path_parts, "type": _kind(child), "secret": secret}
        if not secret:
            item["default"] = _mask(child, path_parts)
        if isinstance(child, list):
            item["item_type"] = _kind(child[0]) if child else "any"
        fields.append(item)
    return fields


def _diff(before: Dict[str, Any], after: Dict[str, Any]) -> List[Dict[str, Any]]:
    left, right = _flatten(before), _flatten(after)
    changes = []
    for path in sorted(set(left) | set(right)):
        old, new = left.get(path), right.get(path)
        if old == new and path in left and path in right:
            continue
        parts = re.split(r"[.\[\]]+", path)
        secret = any(_is_secret(part, parts[:index]) for index, part in enumerate(parts)) or _contains_secret(old) or _contains_secret(new)
        changes.append({
            "path": path,
            "before": "[redacted]" if secret else _redact_nested(old) if path in left else None,
            "after": "[redacted]" if secret else _redact_nested(new) if path in right else None,
            "secret": secret,
        })
    return changes


class ConfigService:
    """Owns in-memory drafts and writes validated immutable JSON versions.

    Activation and service restart are deliberately separate operations. The
    deployment-specific mechanism must be configured before those are exposed.
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = resolve_config_path(config_path)
        self._lock = threading.RLock()
        self._drafts: Dict[str, Dict[str, Any]] = {}

    def _current(self) -> Dict[str, Any]:
        config = _deep_copy(DEFAULT_CONFIG)
        if self.config_path and os.path.exists(self.config_path):
            _deep_merge(config, _read_file(self.config_path))
        return config

    def _file_hash(self) -> Optional[str]:
        if not self.config_path or not os.path.isfile(self.config_path):
            return None
        with open(self.config_path, "rb") as stream:
            return hashlib.sha256(stream.read()).hexdigest()

    def _draft_directory(self) -> Optional[Path]:
        if not self.config_path:
            return None
        return Path(self.config_path).parent / "config.versions" / ".drafts"

    def _persist_draft(self, draft_id: str, draft: Dict[str, Any]) -> None:
        folder = self._draft_directory()
        if folder is None:
            return
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            os.chmod(folder, 0o700)
        except OSError:
            pass
        raw = (json.dumps(draft, ensure_ascii=False, separators=(",", ":"), default=str) + "\n").encode("utf-8")
        self._atomic_write(folder / f"{draft_id}.json", raw, 0o600)

    def _load_persisted_draft(self, draft_id: str) -> Optional[Dict[str, Any]]:
        if not re.fullmatch(r"[0-9a-f]{32}", draft_id):
            return None
        folder = self._draft_directory()
        path = folder / f"{draft_id}.json" if folder else None
        if path is None or not path.is_file():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(value, dict) or not isinstance(value.get("config"), dict):
                return None
            if time.time() - float(value.get("created", 0)) > 4 * 60 * 60:
                path.unlink(missing_ok=True)
                return None
            return value
        except (OSError, ValueError, TypeError):
            return None

    @staticmethod
    def _hash_config(config: Dict[str, Any]) -> str:
        raw = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def current(self) -> Dict[str, Any]:
        with self._lock:
            config = self._current()
            return {"config": _mask(config), "secret_paths": _walk_secret_paths(config),
                    "config_path": self.config_path, "config_hash": self._hash_config(config)}

    def schema(self) -> Dict[str, Any]:
        return {"fields": _schema(self._current()), "config_path": self.config_path}

    def status(self) -> Dict[str, Any]:
        version_dir = Path(self.config_path).parent / "config.versions" if self.config_path else None
        write_target = version_dir if version_dir and version_dir.exists() else Path(self.config_path).parent if self.config_path else None
        can_write = bool(write_target and os.access(write_target, os.W_OK))
        return {"config_path": self.config_path, "writable": can_write,
                "config_hash": self._hash_config(self._current()), "file_hash": self._file_hash(),
                "version_directory": str(version_dir) if version_dir else None,
                "activation": "not_configured", "restart": "not_configured"}

    def create_draft(self, actor: str, config: Dict[str, Any],
                     expected_file_hash: Optional[str] = None) -> Dict[str, Any]:
        if not isinstance(config, dict):
            raise ValueError("config must be a JSON object")
        with self._lock:
            if expected_file_hash != self._file_hash():
                raise RuntimeError("Active config changed since it was loaded; reload before creating a draft")
            cutoff = time.time() - 4 * 60 * 60
            self._drafts = {key: value for key, value in self._drafts.items()
                            if value["created"] >= cutoff}
            if len(self._drafts) >= 256:
                oldest = sorted(self._drafts, key=lambda key: self._drafts[key]["created"])
                for key in oldest[:len(self._drafts) - 255]:
                    del self._drafts[key]
                    folder = self._draft_directory()
                    if folder:
                        (folder / f"{key}.json").unlink(missing_ok=True)
            base = self._current()
            candidate = _restore_unchanged_secrets(config, base)
            merged = _merge(base, candidate)
            draft_id = uuid.uuid4().hex
            self._drafts[draft_id] = {"actor": actor, "config": merged, "base_hash": self._file_hash(),
                                      "created": time.time()}
            self._persist_draft(draft_id, self._drafts[draft_id])
            return self.get_draft(draft_id, actor)

    def update_draft(self, draft_id: str, actor: str, config: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            draft = self._get_owned_draft(draft_id, actor)
            if not isinstance(config, dict):
                raise ValueError("config must be a JSON object")
            candidate = _restore_unchanged_secrets(config, draft["config"])
            draft["config"] = _merge(draft["config"], candidate)
            draft.pop("validated_hash", None)
            draft.pop("validated_at", None)
            self._persist_draft(draft_id, draft)
            return self.get_draft(draft_id, actor)

    def _get_owned_draft(self, draft_id: str, actor: str) -> Dict[str, Any]:
        draft = self._drafts.get(draft_id)
        if draft is None:
            draft = self._load_persisted_draft(draft_id)
            if draft is not None:
                self._drafts[draft_id] = draft
        if not draft or draft["actor"] != actor:
            raise KeyError("draft not found")
        return draft

    def get_draft(self, draft_id: str, actor: str) -> Dict[str, Any]:
        with self._lock:
            draft = self._get_owned_draft(draft_id, actor)
            current = self._current()
            return {"draft_id": draft_id, "config": _mask(draft["config"]),
                    "changes": _diff(current, draft["config"]),
                    "config_hash": self._hash_config(draft["config"]),
                    "base_file_hash": draft["base_hash"],
                    "previewed": draft.get("validated_hash") == self._hash_config(draft["config"]),
                    "conflict": draft["base_hash"] != self._file_hash()}

    def validate(self, draft_id: str, actor: str) -> Dict[str, Any]:
        with self._lock:
            draft = self._get_owned_draft(draft_id, actor)
            issues = validate_config(draft["config"])
            config_hash = self._hash_config(draft["config"])
            draft["validated_hash"] = config_hash
            draft["validated_at"] = time.time()
            self._persist_draft(draft_id, draft)
            return {"valid": not any(i.level == "error" for i in issues),
                    "issues": [{"path": i.path, "message": i.message, "level": i.level} for i in issues],
                    "conflict": draft["base_hash"] != self._file_hash(),
                    "config_hash": config_hash,
                    "changes": _diff(self._current(), draft["config"])}

    def generate_version(self, draft_id: str, actor: str, expected_hash: Optional[str] = None) -> Dict[str, Any]:
        with self._lock:
            if not self.config_path:
                raise RuntimeError("No active config file path is configured; generation is read-only")
            draft = self._get_owned_draft(draft_id, actor)
            if draft["base_hash"] != self._file_hash():
                raise RuntimeError("Active config changed since this draft was created")
            config_hash = self._hash_config(draft["config"])
            if not expected_hash or expected_hash != config_hash or draft.get("validated_hash") != config_hash:
                raise RuntimeError("Draft changed since preview; validate and preview again")
            result = self.validate(draft_id, actor)
            if not result["valid"]:
                raise ValueError("Configuration has validation errors")
            target_dir = Path(self.config_path).parent / "config.versions"
            target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            try:
                os.chmod(target_dir, 0o700)
            except OSError:
                pass
            version_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:10]
            config_path = target_dir / f"config-{version_id}.json"
            raw = (json.dumps(draft["config"], indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
            digest = hashlib.sha256(raw).hexdigest()
            self._atomic_write(config_path, raw, 0o600)
            manifest = {"version_id": version_id, "config_file": config_path.name,
                        "sha256": digest, "base_file_hash": draft["base_hash"],
                        "config_hash": self._hash_config(draft["config"]),
                        "created_at": time.time(), "created_by": actor,
                        "changes": result["changes"]}
            meta_path = target_dir / f"config-{version_id}.meta.json"
            self._atomic_write(meta_path, (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8"), 0o600)
            return {"version_id": version_id, "sha256": digest, "config_hash": manifest["config_hash"],
                    "config_file": str(config_path), "created_at": manifest["created_at"]}

    @staticmethod
    def _atomic_write(path: Path, raw: bytes, mode: int) -> None:
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, mode)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, path)
            try:
                dir_fd = os.open(str(path.parent), os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def versions(self) -> List[Dict[str, Any]]:
        if not self.config_path:
            return []
        folder = Path(self.config_path).parent / "config.versions"
        versions = []
        if not folder.is_dir():
            return versions
        for meta_path in sorted(folder.glob("config-*.meta.json"), reverse=True):
            try:
                manifest = json.loads(meta_path.read_text(encoding="utf-8"))
                version_id = manifest.get("version_id", "")
                if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}", version_id):
                    continue
                config_file = folder / manifest["config_file"]
                if (config_file.name != f"config-{version_id}.json"
                        or config_file.resolve().parent != folder.resolve() or not config_file.is_file()):
                    continue
                if hashlib.sha256(config_file.read_bytes()).hexdigest() != manifest.get("sha256"):
                    continue
                versions.append({k: manifest.get(k) for k in ("version_id", "sha256", "config_hash", "created_at", "created_by")})
            except (OSError, ValueError, KeyError, TypeError):
                continue
        return versions

    def get_version(self, version_id: str) -> Dict[str, Any]:
        if not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{10}", version_id):
            raise KeyError("version not found")
        if not self.config_path:
            raise KeyError("version not found")
        folder = Path(self.config_path).parent / "config.versions"
        manifest_path = folder / f"config-{version_id}.meta.json"
        config_path = folder / f"config-{version_id}.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if config_path.resolve().parent != folder.resolve():
                raise KeyError("version not found")
            raw = config_path.read_bytes()
            if manifest.get("version_id") != version_id or manifest.get("config_file") != config_path.name:
                raise KeyError("version not found")
            if hashlib.sha256(raw).hexdigest() != manifest.get("sha256"):
                raise ValueError("Version integrity check failed")
            config = json.loads(raw.decode("utf-8"))
            if not isinstance(config, dict):
                raise ValueError("Version config is not an object")
        except FileNotFoundError as exc:
            raise KeyError("version not found") from exc
        return {"version": {k: manifest.get(k) for k in ("version_id", "sha256", "config_hash", "created_at", "created_by")},
                "config": _mask(config), "integrity": "ok"}
