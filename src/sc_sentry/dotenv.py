"""`.env` in the working directory, read into the environment before anything else.

Stdlib only, and deliberately small: `KEY=VALUE` lines, `#` comments, and optional matching quotes
around the value. A variable already set in the environment wins, so `RLM_MAIN_MODEL=x sc-sentry
audit ...` overrides the file for one run instead of being silently overridden by it.
"""

from __future__ import annotations

import os
from pathlib import Path

__all__ = ["load"]


def load(path: Path = Path(".env")) -> list[str]:
    """Set each variable the file names and the environment lacks; return their names.

    A missing file is not an error, because exporting the variables is equally valid. Values are
    never printed or returned.
    """
    if not path.is_file():
        return []
    loaded: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        if not key or key in os.environ:
            continue
        os.environ[key] = value
        loaded.append(key)
    return loaded
