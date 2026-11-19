#!/usr/bin/env python3
"""Credential lookup shared by the router tools.

Order of precedence, so that nothing secret has to be written into a tracked
file: explicit argument > environment variable > secrets.local.env > default.

secrets.local.env sits next to this file's parent directory and is gitignored
(see secrets.example.env for the keys).
"""
import os

SECRETS_FILE = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), os.pardir, "secrets.local.env"))


def _file_values(path=SECRETS_FILE):
    values = {}
    if not os.path.exists(path):
        return values
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            values[key.strip()] = val.strip().strip('"').strip("'")
    return values


def get(name, cli_value=None, default=None, required=False):
    """Resolve one setting; cli_value wins even when it is an empty string."""
    if cli_value is not None:
        return cli_value
    if os.environ.get(name):
        return os.environ[name]
    file_values = _file_values()
    if file_values.get(name):
        return file_values[name]
    if required:
        raise SystemExit(
            "%s is not set: pass the flag, export the variable, or put %s=<value> "
            "in %s (see secrets.example.env)" % (name, name, SECRETS_FILE))
    return default
