"""Verify budget accounting with an injected clock (deterministic)."""

import pytest

from crucible.budget import Budget, BudgetExceeded


def test_token_cap_raises_when_exceeded():
    b = Budget(max_tokens=100)
    b.charge_tokens(60)
    with pytest.raises(BudgetExceeded):
        b.charge_tokens(50)  # 110 > 100


def test_call_cap_raises_when_exceeded():
    b = Budget(max_calls=2)
    b.charge_call()
    b.charge_call()
    with pytest.raises(BudgetExceeded):
        b.charge_call()  # 3 > 2


def test_wall_clock_cap_uses_injected_clock():
    now = {"t": 0.0}
    b = Budget(max_wall_s=10.0, clock=lambda: now["t"])
    now["t"] = 9.0
    b.check_time()  # under cap, fine
    now["t"] = 11.0
    with pytest.raises(BudgetExceeded):
        b.check_time()  # over cap


def test_no_caps_never_raises():
    b = Budget()
    b.charge_tokens(10_000_000)
    b.charge_call(10_000)
    b.check_time()  # nothing configured -> never exceeds


def test_counters_are_readable():
    b = Budget()
    b.charge_tokens(5)
    b.charge_call(2)
    assert b.tokens == 5
    assert b.calls == 2
