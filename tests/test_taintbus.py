"""Tests for the cross-server shared taint bus (taintbus.SharedTaint)."""

from __future__ import annotations

import time

from airlock.enforce.taintbus import SharedTaint


def test_taint_is_visible_to_a_peer(tmp_path):
    d = tmp_path / "ctx"
    a = SharedTaint(d, label="serverA")
    assert a.is_tainted() is False
    a.taint("saw untrusted content")
    assert a.is_tainted() is True
    # A DIFFERENT proxy instance sharing the same directory sees A's taint...
    c = SharedTaint(d, label="serverC")
    assert c.is_tainted() is True
    # ...and can attribute which server raised it.
    assert "serverA" in {s.get("label") for s in c.sources()}


def test_taint_writes_at_most_one_marker_per_instance(tmp_path):
    d = tmp_path / "ctx"
    a = SharedTaint(d, label="x")
    a.taint("1")
    a.taint("2")
    a.taint("3")
    assert len(list(d.glob("*.taint"))) == 1  # monotonic: one marker per process, no spam


def test_dead_proxy_marker_expires_after_ttl(tmp_path):
    """A marker from a proxy that has EXITED (dead pid) and is older than the ttl self-expires,
    so a stale session's taint (past a restart) does not gate a fresh one."""
    import json
    import os
    import subprocess
    import sys

    d = tmp_path / "ctx"
    d.mkdir(parents=True)
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    dead_pid = proc.pid  # exited + reaped: not a live process
    m = d / "t-dead.taint"
    m.write_text(json.dumps({"label": "x", "pid": dead_pid, "ts": "2020-01-01T00:00:00+00:00"}))
    old = time.time() - 10
    os.utime(m, (old, old))  # mtime well past the ttl
    a = SharedTaint(d, label="peer", ttl=0.5)
    assert a.is_tainted() is False  # dead pid + expired mtime -> not fresh, no gate
    assert a.sources() == []


def test_live_proxy_taint_persists_past_ttl(tmp_path):
    """H7: while the tainting proxy is ALIVE, its taint does not evaporate after the ttl, so a
    long-lived session does not silently lose cross-server gating mid-session."""
    d = tmp_path / "ctx"
    a = SharedTaint(d, label="x", ttl=0.02)
    a.taint()
    time.sleep(0.1)  # well past the ttl
    c = SharedTaint(d, label="peer")
    assert c.is_tainted() is True  # a's pid (this test process) is alive -> still fresh


def test_missing_directory_is_not_tainted(tmp_path):
    a = SharedTaint(tmp_path / "does-not-exist", label="x")
    assert a.is_tainted() is False
    assert a.sources() == []


def test_session_tainted_promotes_shared_to_local(tmp_path):
    from airlock.enforce.proxy import _SessionState, _session_tainted

    d = tmp_path / "ctx"
    st = _SessionState()
    assert _session_tainted(st) is False  # no shared bus, local clean
    st.shared = SharedTaint(d, label="me")
    assert _session_tainted(st) is False  # bus empty
    SharedTaint(d, label="peer").taint("untrusted")  # a peer server taints the context
    assert _session_tainted(st) is True  # gate now sees it
    assert st.tainted is True  # promoted to local (monotonic), so no more bus reads


def test_default_no_context_is_local_only():
    from airlock.enforce.proxy import _SessionState, _session_tainted

    st = _SessionState()
    assert st.shared is None  # default: single-server, no cross-server bus, no filesystem IO
    assert _session_tainted(st) is False
