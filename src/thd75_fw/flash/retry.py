"""One-retry-on-timeout retry policy.

Mirrors the official updater's ``c(5000)`` pattern (5s timeout before
nearly every send). Protocol-level errors (NAK, FrameError, etc.) are
NOT retried by default — those are surfaced immediately.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from collections.abc import Callable

T = TypeVar("T")


def _is_timeout(exc: Exception) -> bool:
    return isinstance(exc, TimeoutError)


@dataclass(frozen=True, slots=True)
class _RetryableFailure:
    """One attempt that raised an exception the retry predicate accepted."""

    error: Exception


def _attempt_once(
    fn: Callable[[], T],
    is_retryable: Callable[[Exception], bool],
) -> T | _RetryableFailure:
    """Call ``fn`` once, handing a retryable exception back instead of raising.

    Args:
        fn: The operation to attempt.
        is_retryable: Predicate deciding whether an exception may be retried.

    Returns:
        ``fn``'s result, or the retryable exception wrapped in
        :class:`_RetryableFailure` so it cannot be mistaken for a value ``fn``
        returned.

    Raises:
        Exception: Whatever ``fn`` raised, unchanged, when ``is_retryable``
            rejects it.

    """
    try:
        return fn()
    except Exception as exc:
        if not is_retryable(exc):
            raise
        return _RetryableFailure(exc)


def with_retry(
    fn: Callable[[], T],
    *,
    timeout: float,
    attempts: int = 2,
    is_retryable: Callable[[Exception], bool] = _is_timeout,
) -> T:
    """Invoke ``fn`` up to ``attempts`` times; retry only on retryable exceptions.

    Default retryable predicate matches ``TimeoutError`` only. Protocol
    errors are surfaced immediately on the first occurrence.

    The ``timeout`` argument is documented for the caller's accounting
    but doesn't bound execution — caller is responsible for bounding
    ``fn`` via transport read timeouts or similar.
    """
    del timeout  # recorded for the caller's accounting only; see above
    last: Exception | None = None
    for _attempt in range(attempts):
        outcome = _attempt_once(fn, is_retryable)
        if not isinstance(outcome, _RetryableFailure):
            return outcome
        last = outcome.error
    if last is None:
        # Only ``attempts < 1`` gets here: nothing was attempted, so there is no
        # exception to re-raise. This is the bare AssertionError the invariant
        # has always raised.
        raise AssertionError
    raise last
