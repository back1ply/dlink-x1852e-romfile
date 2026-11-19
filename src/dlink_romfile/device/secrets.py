"""Resolve device host/credentials without ever storing them in source.

Precedence: explicit argument > environment variable > ``secrets.local.env`` in the
working directory (or the file named by ``X1852E_SECRETS``) > default.

The env file is ``KEY=value`` per line, ``#`` comments allowed. Known keys:
``X1852E_HOST``, ``X1852E_WEB_USER``, ``X1852E_WEB_PASS``, ``X1852E_TELNET_USER``,
``X1852E_TELNET_PASS``. See ``secrets.example.env`` in the repo for a template.
"""
from __future__ import annotations

import os
from pathlib import Path

from . import DeviceError


def secrets_path() -> Path:
    return Path(os.environ.get("X1852E_SECRETS", "secrets.local.env"))


def _file_values() -> dict[str, str]:
    path = secrets_path()
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, val = line.split("=", 1)
        values[key.strip()] = val.strip().strip('"').strip("'")
    return values


def get(name: str, cli_value: str | None = None, default: str | None = None,
        required: bool = False) -> str | None:
    """Resolve one setting; ``cli_value`` wins even when it is an empty string."""
    if cli_value is not None:
        return cli_value
    if os.environ.get(name):
        return os.environ[name]
    file_values = _file_values()
    if file_values.get(name):
        return file_values[name]
    if required:
        raise DeviceError(
            f"{name} is not set: pass the flag, export the variable, or put "
            f"{name}=<value> in {secrets_path()} (see secrets.example.env)")
    return default
