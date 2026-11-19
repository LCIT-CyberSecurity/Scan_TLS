"""Deprecated alias of `orion_app`, kept so existing imports and commands keep working after the Orion rebranding.

`import tls_scan_app.X` returns the very module object `orion_app.X` (no second copy, so models and settings stay
shared) and `python -m tls_scan_app.X` runs `orion_app.X`. New code must use `orion_app`; this alias will be removed
in a later major version once deployments no longer reference it (see docs/admin/orion-migration.md).
"""
from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import sys
import warnings

LEGACY = __name__
TARGET = "orion_app"

warnings.warn("The 'tls_scan_app' package is deprecated; use 'orion_app'.", DeprecationWarning, stacklevel=2)


class _AliasLoader(importlib.abc.Loader):
    def __init__(self, target: str) -> None:
        self.target = target

    def create_module(self, spec):
        module = importlib.import_module(self.target)
        self.original_spec = module.__spec__
        return module

    def exec_module(self, module) -> None:
        """The target module is already executed; only undo the import system's rebinding of its __spec__."""
        module.__spec__ = self.original_spec

    def get_code(self, fullname: str):
        """Used by `python -m tls_scan_app.X`: run the target's code as __main__."""
        spec = importlib.util.find_spec(self.target)
        return spec.loader.get_code(self.target) if spec and spec.loader else None


class _AliasFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname: str, path=None, target=None):
        if not fullname.startswith(LEGACY + "."):
            return None
        alias = TARGET + fullname[len(LEGACY):]
        real = importlib.util.find_spec(alias)
        if real is None:
            return None
        return importlib.machinery.ModuleSpec(fullname, _AliasLoader(alias), is_package=real.submodule_search_locations is not None)


if not any(isinstance(finder, _AliasFinder) for finder in sys.meta_path):
    sys.meta_path.insert(0, _AliasFinder())

_target = importlib.import_module(TARGET)
__path__: list[str] = []  # a package, so submodules resolve through the finder above
