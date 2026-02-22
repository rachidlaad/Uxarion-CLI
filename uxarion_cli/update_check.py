# SPDX-License-Identifier: Apache-2.0
"""Lightweight PyPI update check with local cache."""
from __future__ import annotations

import json
import os
import sys
import time
from importlib import metadata
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

from packaging.version import InvalidVersion, Version

PYPI_PROJECT = "uxarion"
PYPI_URL = f"https://pypi.org/pypi/{PYPI_PROJECT}/json"
CACHE_TTL_SECONDS = 24 * 60 * 60


def _is_truthy(value: Optional[str]) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _cache_path() -> Path:
    cache_root = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return cache_root / "uxarion" / "update_check.json"


def _read_cache(path: Path) -> Dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(raw, dict):
        return {}
    return raw


def _write_cache(path: Path, payload: Dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload), encoding="utf-8")
    except Exception:
        # Update checks should never break normal execution.
        pass


def _get_installed_version() -> Optional[str]:
    for dist_name in ("uxarion", "uxarion-cli"):
        try:
            return metadata.version(dist_name)
        except metadata.PackageNotFoundError:
            continue
    return None


def _fetch_latest_version(timeout_seconds: float = 2.5) -> Optional[str]:
    request = Request(
        PYPI_URL,
        headers={
            "Accept": "application/json",
            "User-Agent": "uxarion-update-check",
        },
    )
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, URLError, json.JSONDecodeError):
        return None
    info = payload.get("info", {}) if isinstance(payload, dict) else {}
    latest = info.get("version")
    if isinstance(latest, str) and latest.strip():
        return latest.strip()
    return None


def _is_pipx_environment() -> bool:
    executable = Path(sys.executable).as_posix().lower()
    return "/pipx/venvs/" in executable


def _is_newer_version(latest: str, current: str) -> bool:
    try:
        return Version(latest) > Version(current)
    except InvalidVersion:
        return False


def get_update_notice(*, force: bool = False, now: Optional[float] = None) -> Optional[str]:
    """Return one-line update hint when a newer PyPI version is available."""
    if _is_truthy(os.environ.get("UXARION_DISABLE_UPDATE_CHECK")):
        return None
    if not sys.stdout.isatty():
        return None

    current_version = _get_installed_version()
    if not current_version:
        return None

    current_ts = time.time() if now is None else now
    cache_file = _cache_path()
    cache_data = _read_cache(cache_file)
    latest_version: Optional[str] = None

    cached_latest = cache_data.get("latest_version")
    cached_checked = cache_data.get("checked_at")
    if (
        not force
        and isinstance(cached_latest, str)
        and isinstance(cached_checked, (int, float))
        and (current_ts - float(cached_checked)) < CACHE_TTL_SECONDS
    ):
        latest_version = cached_latest.strip()

    if not latest_version:
        latest_version = _fetch_latest_version()
        if latest_version:
            _write_cache(
                cache_file,
                {
                    "checked_at": current_ts,
                    "latest_version": latest_version,
                },
            )

    if not latest_version:
        return None
    if not _is_newer_version(latest_version, current_version):
        return None

    upgrade_cmd = "pipx upgrade uxarion" if _is_pipx_environment() else "python -m pip install -U uxarion"
    return f"Update available: {latest_version} (installed: {current_version}). Run: {upgrade_cmd}"


def maybe_print_update_notice() -> bool:
    notice = get_update_notice()
    if not notice:
        return False
    print(notice)
    return True
