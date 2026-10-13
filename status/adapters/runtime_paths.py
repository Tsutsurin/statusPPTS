"""Корневая папка программы и папка .data: для исходников, собранного EXE и тестов."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ENV_APP_ROOT = "STATUS_APP_ROOT"


def get_project_root() -> Path:
    env_root = os.environ.get(ENV_APP_ROOT)
    if env_root:
        return Path(env_root).resolve()

    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent

    current = Path(__file__).resolve()
    for parent in current.parents:
        if (parent / "status").is_dir() and (parent / "requirements.txt").exists():
            return parent
    return Path(__file__).resolve().parents[2]


def data_dir() -> Path:
    return get_project_root() / ".data"
