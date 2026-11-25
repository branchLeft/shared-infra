"""Load a hyphenated script by its path, for the tests that exercise it.

A script's filename has hyphens, so no plain import can name it. Every test that needs
one loads it here, and none of them copies the loader. The module is registered in
sys.modules before it runs: dataclasses resolves its owning module through sys.modules
when the class is created, and registering it is harmless to a script that never needs it.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def load_script(path: Path, module_name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path} as {module_name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module
