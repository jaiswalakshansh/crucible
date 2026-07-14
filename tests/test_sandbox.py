"""Verify the local executor with REAL subprocess execution (no mocks)."""

import sys

from crucible.sandbox import ExecutionStatus, LocalSubprocessExecutor


def test_exit_zero_is_ok_and_fired():
    r = LocalSubprocessExecutor().run(
        {"poc.py": "print('demonstrated'); raise SystemExit(0)"},
        [sys.executable, "poc.py"],
    )
    assert r.status is ExecutionStatus.OK
    assert r.exit_code == 0
    assert r.fired is True
    assert "demonstrated" in r.stdout


def test_exit_nonzero_is_failed_not_fired():
    r = LocalSubprocessExecutor().run(
        {"poc.py": "raise SystemExit(3)"},
        [sys.executable, "poc.py"],
    )
    assert r.status is ExecutionStatus.FAILED
    assert r.exit_code == 3
    assert r.fired is False


def test_timeout_is_reported():
    r = LocalSubprocessExecutor().run(
        {"poc.py": "import time; time.sleep(5)"},
        [sys.executable, "poc.py"],
        timeout_s=0.5,
    )
    assert r.status is ExecutionStatus.TIMEOUT
    assert r.fired is False


def test_missing_runtime_is_error_not_raise():
    r = LocalSubprocessExecutor().run(
        {"poc.py": "x"}, ["definitely-not-a-real-binary-xyz", "poc.py"]
    )
    assert r.status is ExecutionStatus.ERROR


def test_writes_nested_files():
    r = LocalSubprocessExecutor().run(
        {
            "pkg/data.txt": "hello",
            "run.py": "print(open('pkg/data.txt').read()); raise SystemExit(0)",
        },
        [sys.executable, "run.py"],
    )
    assert r.status is ExecutionStatus.OK
    assert "hello" in r.stdout


def test_local_executor_reports_no_network_isolation():
    r = LocalSubprocessExecutor().run(
        {"poc.py": "raise SystemExit(0)"}, [sys.executable, "poc.py"]
    )
    # Honest metadata: the local executor cannot isolate network.
    assert r.network_isolated is False
