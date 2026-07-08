"""Regression tests for the second full audit, Batch 5 (cross-server taint bus).

H7 (liveness, not fixed TTL from first taint), H8 (0700 dir + deletion detection fails
closed), L3 (bus read error / tamper fails CLOSED in gating modes), L5 (hot-path short-circuit).
"""

from __future__ import annotations

import os
import stat

from airlock.enforce.taintbus import SharedTaint


# --- H8: deletion of markers by a same-uid process is detected + fails closed ----------


def test_h8_marker_deletion_is_detected_and_fails_closed(tmp_path):
    d = tmp_path / "ctx"
    a = SharedTaint(d, label="A")
    a.taint("saw untrusted content")
    c = SharedTaint(d, label="C")
    assert c.is_tainted() is True
    # a hostile same-uid process deletes the markers to clear the taint it raised
    for p in d.glob("*.taint"):
        p.unlink()
    # the high-water anchor still records that taint was raised within the window -> fail closed
    assert c.is_tainted() is True


def test_h8_context_dir_is_0700(tmp_path):
    d = tmp_path / "ctx"
    SharedTaint(d, label="A").taint()
    mode = stat.S_IMODE(os.stat(d).st_mode)
    assert mode == 0o700  # no cross-user read/enumerate/delete


# --- L3: a bus read error fails CLOSED in gating modes, OPEN otherwise ------------------


def test_l3_unreadable_dir_fails_closed_when_gating(tmp_path):
    # The real L3 scenario: the context dir is present-but-unreadable (attacker chmod 000,
    # markers + anchor physically intact). pathlib.glob() swallows EACCES on Darwin, so
    # is_tainted must probe with iterdir() and fail CLOSED in gating mode.
    if os.getuid() == 0:
        import pytest
        pytest.skip("permission checks are bypassed as root")
    d = tmp_path / "ctx"
    SharedTaint(d, label="A").taint()  # dir exists + marker + .hwm anchor
    os.chmod(d, 0)
    try:
        assert SharedTaint(d, label="C", fail_closed=True).is_tainted() is True   # fail closed
        assert SharedTaint(d, label="C", fail_closed=False).is_tainted() is False  # fail open
    finally:
        os.chmod(d, 0o700)  # restore so tmp_path cleanup works


def test_l3_missing_dir_is_clean_not_error(tmp_path):
    # a not-yet-created context is genuinely clean, even in fail-closed mode
    assert SharedTaint(tmp_path / "nope", fail_closed=True).is_tainted() is False


# --- L5: is_tainted short-circuits on the first fresh marker ----------------------------


def test_l5_is_tainted_short_circuits(tmp_path, monkeypatch):
    d = tmp_path / "ctx"
    # many markers present
    for i in range(50):
        SharedTaint(d, label=f"s{i}").taint()
    c = SharedTaint(d, label="C")
    stats = {"n": 0}
    real_fresh = SharedTaint._is_fresh

    def counting(self, p):
        stats["n"] += 1
        return real_fresh(self, p)

    monkeypatch.setattr(SharedTaint, "_is_fresh", counting)
    assert c.is_tainted() is True
    assert stats["n"] == 1  # returned on the first fresh marker, did not scan all 50
