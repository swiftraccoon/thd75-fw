"""Tests for thd75_fw.flash.retry."""

from __future__ import annotations

import pytest

from thd75_fw.flash.retry import with_retry


class _CountingError(Exception):
    pass


def test_with_retry_succeeds_on_first_try() -> None:
    calls = 0

    def fn() -> int:
        nonlocal calls
        calls += 1
        return 42

    assert with_retry(fn, timeout=1.0) == 42
    assert calls == 1


def test_with_retry_retries_once_on_timeout() -> None:
    calls = 0

    def fn() -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            msg = "first attempt"
            raise TimeoutError(msg)
        return 42

    assert with_retry(fn, timeout=1.0) == 42
    assert calls == 2


def test_with_retry_gives_up_after_attempts() -> None:
    calls = 0

    def fn() -> int:
        nonlocal calls
        calls += 1
        msg = f"attempt {calls}"
        raise TimeoutError(msg)

    with pytest.raises(TimeoutError, match="attempt 2"):
        _ = with_retry(fn, timeout=1.0, attempts=2)
    assert calls == 2


def test_with_retry_does_not_retry_protocol_errors_by_default() -> None:
    calls = 0

    def fn() -> int:
        nonlocal calls
        calls += 1
        msg = "not a timeout"
        raise _CountingError(msg)

    with pytest.raises(_CountingError):
        _ = with_retry(fn, timeout=1.0)
    assert calls == 1
