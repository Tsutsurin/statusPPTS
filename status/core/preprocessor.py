"""Предобработка строки продукта перед сопоставлением: шум, версии, разделение на части."""

from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from status.core.models import ScriptConfig

    ProcessFunc = Callable[[list[dict[str, str]]], list[dict[str, str]]]

logger = logging.getLogger(__name__)

EntryDict = dict[str, str]


def _load_script(script_path: str | Path) -> ProcessFunc | None:
    path = Path(script_path)
    if not path.exists():
        logger.warning("Script not found: %s", path)
        return None

    module_name = f"_plugin_{path.stem}"
    try:
        spec = importlib.util.spec_from_file_location(module_name, str(path))
        if spec is None or spec.loader is None:
            logger.warning("Cannot create module spec for %s", path)
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
    except Exception:
        logger.exception("Failed to load script %s", path)
        return None

    process_fn = getattr(module, "process", None)
    if process_fn is None or not callable(process_fn):
        logger.warning("Script %s has no callable process() function", path)
        return None

    return process_fn


def _evaluate_condition(condition: str, entry: EntryDict) -> bool:
    condition = condition.strip()
    if not condition:
        return True

    parts = condition.split(None, 2)
    if len(parts) != 3:
        logger.warning("Cannot parse condition: %r", condition)
        return False

    field, op, value = parts
    field_value = entry.get(field, "").lower()
    value = value.lower()

    if op == "contains":
        return value in field_value
    if op == "equals":
        return field_value == value
    if op == "startswith":
        return field_value.startswith(value)

    logger.warning("Unknown condition operator: %r", op)
    return False


class Preprocessor:

    def __init__(self, scripts_dir: str | Path = "scripts") -> None:
        self._scripts_dir = Path(scripts_dir)
        self._loaded: dict[str, ProcessFunc] = {}

    def _get_process_func(self, script_path: str) -> ProcessFunc | None:
        if script_path not in self._loaded:
            full_path = self._scripts_dir / script_path
            if not full_path.exists():
                full_path = Path(script_path)
            fn = _load_script(full_path)
            self._loaded[script_path] = fn
        return self._loaded.get(script_path)

    def process(
        self,
        entries: list[EntryDict],
        configs: list[ScriptConfig],
    ) -> list[EntryDict]:
        result = list(entries)

        for config in configs:
            if not config.enabled:
                continue

            process_fn = self._get_process_func(config.script_path)
            if process_fn is None:
                continue

            to_process: list[EntryDict] = []
            passthrough: list[EntryDict] = []

            for entry in result:
                if _evaluate_condition(config.condition, entry):
                    to_process.append(entry)
                else:
                    passthrough.append(entry)

            if not to_process:
                continue

            try:
                processed = process_fn(to_process)
                logger.info(
                    "Script %s: %d entries -> %d entries",
                    config.script_path,
                    len(to_process),
                    len(processed),
                )
                result = passthrough + processed
            except Exception:
                logger.exception(
                    "Script %s failed, keeping original entries",
                    config.script_path,
                )
                result = passthrough + to_process

        return result
