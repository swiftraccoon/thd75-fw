"""Typing helpers whose standard-library form needs a newer Python."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing_extensions import override
else:
    from collections.abc import Callable
    from typing import TypeVar

    _F = TypeVar("_F", bound=Callable[..., object])

    def override(method: _F, /) -> _F:
        """Mark *method* as overriding a base-class method.

        ``typing.override`` exists only on Python 3.12 and later. Type
        checkers read the ``typing_extensions`` declaration, and at runtime
        this decorator returns *method* unchanged, so no dependency ships.
        """
        return method


__all__ = ["override"]
