"""The package must import with only its declared runtime dependencies."""

from __future__ import annotations

import importlib
import importlib.abc
import pkgutil
import sys
from typing import TYPE_CHECKING

from thd75_fw._compat import override

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from importlib.machinery import ModuleSpec
    from types import ModuleType

_BLOCKED = "typing_extensions"


class _BlockModule(importlib.abc.MetaPathFinder):
    """Import-system finder that makes one top-level module unimportable."""

    @override
    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None,
        target: ModuleType | None = None,
    ) -> ModuleSpec | None:
        """Refuse *fullname* when it is the blocked module or one of its parts."""
        del path, target
        if fullname == _BLOCKED or fullname.startswith(f"{_BLOCKED}."):
            raise ModuleNotFoundError(fullname)
        return None


def _package_modules() -> Iterator[str]:
    """Yield the dotted name of every module in the freshly imported package."""
    package = importlib.import_module("thd75_fw")
    yield package.__name__
    for info in pkgutil.walk_packages(package.__path__, f"{package.__name__}."):
        yield info.name


def test_every_module_imports_without_typing_extensions() -> None:
    """``typing_extensions`` is needed only by the type checkers.

    Override markers come from ``thd75_fw._compat`` and ``Self`` is imported
    only under ``TYPE_CHECKING``, so hiding the module must not break any
    import. ``sys.modules`` is restored wholesale afterwards, so the rest of
    the suite keeps its original module objects.
    """
    saved = dict(sys.modules)
    blocker = _BlockModule()
    sys.meta_path.insert(0, blocker)
    try:
        for name in list(sys.modules):
            if name == _BLOCKED or name.startswith(("thd75_fw", f"{_BLOCKED}.")):
                del sys.modules[name]
        imported = [
            importlib.import_module(name).__name__ for name in _package_modules()
        ]
    finally:
        sys.meta_path.remove(blocker)
        sys.modules.clear()
        sys.modules.update(saved)
    assert "thd75_fw.cli" in imported
    assert "thd75_fw.flash.session" in imported
