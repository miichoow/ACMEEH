"""Unit tests for AvailabilityGate: a cheap, shared answer to "is the database reachable now?".

It lets ACMEEH refuse a request with 503 *before* consuming the request's single-use nonce when the
database is down.  Without it, a request that fails afterwards has burned its nonce, so a client
that replays the same signed request gets ``badNonce``.
"""

from __future__ import annotations

import pytest

from acmeeh.db.init import AvailabilityGate


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class _Probe:
    def __init__(self):
        self.calls = 0
        self.fail = False

    def __call__(self):
        self.calls += 1
        if self.fail:
            msg = "database unreachable"
            raise ConnectionError(msg)


@pytest.fixture
def clock():
    return _Clock()


@pytest.fixture
def probe():
    return _Probe()


@pytest.fixture
def gate(probe, clock):
    return AvailabilityGate(probe, ok_ttl=1.0, fail_ttl=0.5, clock=clock)


class TestAvailabilityGate:
    def test_first_check_probes_the_database(self, gate, probe):
        gate.check()
        assert probe.calls == 1

    def test_success_is_cached_so_requests_do_not_each_cost_a_query(self, gate, probe, clock):
        gate.check()
        clock.now += 0.9
        gate.check()
        gate.check()
        assert probe.calls == 1

    def test_success_expires(self, gate, probe, clock):
        gate.check()
        clock.now += 1.1
        gate.check()
        assert probe.calls == 2

    def test_failure_raises(self, gate, probe):
        probe.fail = True
        with pytest.raises(ConnectionError):
            gate.check()

    def test_failure_is_cached_so_blocked_requests_fail_immediately(self, gate, probe, clock):
        probe.fail = True
        with pytest.raises(ConnectionError):
            gate.check()
        clock.now += 0.4
        with pytest.raises(ConnectionError):
            gate.check()
        assert probe.calls == 1  # the second refusal did not wait for another timeout

    def test_recovers_once_the_failure_window_has_passed(self, gate, probe, clock):
        probe.fail = True
        with pytest.raises(ConnectionError):
            gate.check()
        probe.fail = False
        clock.now += 0.6
        gate.check()
        assert probe.calls == 2

    def test_a_success_after_failure_is_cached_again(self, gate, probe, clock):
        probe.fail = True
        with pytest.raises(ConnectionError):
            gate.check()
        probe.fail = False
        clock.now += 0.6
        gate.check()
        gate.check()
        assert probe.calls == 2
