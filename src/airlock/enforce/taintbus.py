"""Cross-server shared taint: the lethal trifecta is emergent across servers, so enforce it
across servers at runtime.

An agent connects to many MCP servers at once, each fronted by its own `airlock proxy`
PROCESS. Each process has a per-session taint flag, but the danger is emergent: an injection
carried by server A's untrusted content can drive an exfil sink on a SEPARATE server C. The
single-server proxy cannot see that - A's taint lives in A's process, C's gate reads only C's
process. `compose.py` flags this trifecta STATICALLY; this closes it at RUNTIME.

The mechanism is a small, local, append-only taint bus shared by every proxy that was given
the same `--taint-context` directory (`airlock init` gives all servers in one client config
the same one). When any proxy enforces untrusted content it drops a marker file into the
directory; before any proxy forwards a side-effecting call, its action gate also consults the
bus, so untrusted content read via server A gates a side-effecting call to server C.

Design and its threat model (hardened after the second audit - H7/H8/L3/L5):
  * $0 and local. A directory of tiny marker files. No network, no daemon, no lock service.
  * Multi-writer safe with no coordination: each marker is a uniquely-named file (mkstemp), so
    concurrent proxies never clobber each other. Taint is monotonic, so races are benign.
  * Liveness, not a fixed wall-clock TTL from first-taint (H7). A marker is FRESH while the
    proxy that wrote it is still alive (its recorded pid responds), OR within `ttl` of its last
    activity (the mtime, which each `taint()` refreshes). So a long-lived tainted session does
    NOT silently lose cross-server gating after `ttl`; only a marker from a proxy that has EXITED
    self-expires after `ttl` (with a 24h hard cap to bound pid-recycling).
  * Fail-CLOSED for the gate on a bus error (L3). Historically every filesystem error degraded
    to "not tainted", but for the CROSS-server case the gating server has no local taint, so
    "degrade to local taint" was fail-OPEN. When constructed with `fail_closed=True` (the
    approve/block action modes), a bus READ error or a present-but-malformed marker makes
    `is_tainted()` return True, so the operator's gating contract is not silently dropped.
  * Deletion-aware (H8). The context dir is created 0700 (no cross-user read/enumerate/delete),
    and a monotonic high-water file records that taint was raised; if the live markers regress
    below it within the window, `is_tainted()` fails CLOSED (a same-uid process that `rm`s the
    markers to clear its own taint does not succeed). Honest residual: a same-uid attacker with
    code execution can delete the whole directory (including the anchor); that is inherent to a
    $0 local store, and the signed flight-recorder ledger still attests what flowed after the
    fact.
  * O(1)-ish hot path (L5). `is_tainted()` short-circuits on the first fresh marker instead of
    stat-ing the whole directory, and prunes opportunistically on the read path too.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

# A marker from an exited proxy self-expires after `ttl`; this hard cap bounds a marker whose
# recorded pid has been RECYCLED by an unrelated process (which would otherwise read as "alive"
# forever), so the directory cannot grow without bound.
_HARD_MAX_AGE = 86_400.0  # 24h
_HWM_NAME = ".hwm"  # monotonic high-water anchor for deletion detection


def _pid_alive(pid: int) -> bool:
    """True if a process with this pid exists (best-effort; same-user by construction)."""
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but not ours (shouldn't happen same-uid); treat as alive
    except (OSError, OverflowError, ValueError):
        return False  # a corrupt / out-of-range pid is not a live process
    return True


class SharedTaint:
    """A directory-backed, liveness-scoped, monotonic taint flag shared across proxy processes."""

    def __init__(
        self,
        directory: str | Path,
        label: str = "",
        ttl: float = 3600.0,
        fail_closed: bool = False,
    ) -> None:
        # label: which upstream server THIS proxy fronts, recorded on the marker so the audit
        # trail (and a cross-server gate decision) can attribute which server raised the taint.
        self.dir = Path(directory)
        self.label = label or ""
        self.ttl = float(ttl)
        # fail_closed: in a gating action mode (approve/block) the cross-server signal is
        # load-bearing, so a bus read error / tampered marker must fail CLOSED, not open (L3).
        self.fail_closed = bool(fail_closed)
        self._marker_path: str | None = None  # this process's marker, for refresh + cleanup

    # --- write side -------------------------------------------------------------------

    def taint(self, reason: str = "") -> None:
        """Record that this proxy saw untrusted content. Writes one marker then refreshes its
        mtime on every later call (a liveness heartbeat, H7). Best-effort."""
        try:
            self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                self.dir.chmod(0o700)  # tighten a pre-existing dir too (H8)
            except OSError:
                pass
            if self._marker_path is not None:
                try:
                    os.utime(self._marker_path, None)  # heartbeat: keep this taint fresh
                except OSError:
                    self._marker_path = None  # marker vanished; fall through to rewrite
                if self._marker_path is not None:
                    self._bump_hwm()
                    return
            self._prune()
            fd, path = tempfile.mkstemp(prefix="t-", suffix=".taint", dir=str(self.dir))
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(
                    {
                        "label": self.label,
                        "reason": str(reason)[:200],
                        "pid": os.getpid(),
                        "ts": datetime.now(timezone.utc).isoformat(),
                    },
                    fh,
                )
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            self._marker_path = path
            self._bump_hwm()
        except (OSError, ValueError):
            pass  # best-effort: the proxy's own local taint still applies

    # --- read side --------------------------------------------------------------------

    def is_tainted(self) -> bool:
        """True if any peer proxy in this context has seen untrusted content and the taint is
        still live. Short-circuits on the first fresh marker (L5). On a bus read error or a
        detected deletion, returns `fail_closed` (True in the gating modes, L3/H8)."""
        try:
            if not self.dir.exists():
                return False  # nothing raised yet: genuinely clean, not an error
        except OSError:
            return self.fail_closed
        # Probe access to the dir: a present-but-inaccessible context dir must fail CLOSED in
        # gating mode, not silently read as empty (audit L3). os.access checks BOTH bits:
        # R_OK to list entries and X_OK (search) to stat the marker files inside. Checking only
        # readability missed chmod 0400 (read bit kept, search bit stripped), where iterdir()
        # succeeds but the per-file stat() then raises EACCES that _is_fresh used to swallow.
        if not os.access(self.dir, os.R_OK | os.X_OK):
            return self.fail_closed
        try:
            markers = [p for p in self.dir.iterdir() if p.suffix == ".taint"]
        except OSError:
            return self.fail_closed
        for p in markers:
            try:
                if self._is_fresh(p):
                    return True  # short-circuit: one fresh marker is enough (L5)
            except OSError:
                return self.fail_closed  # e.g. EACCES on stat (TOCTOU after the access probe)
        # No fresh marker. If the high-water anchor says taint WAS raised and the tainting
        # proxy is still around (within the window OR its pid is still alive), the markers were
        # DELETED rather than expiring: fail closed (H8). A legitimately-exited-and-expired
        # taint has a stale anchor with a dead pid and does not trip this.
        if self._deletion_suspected():
            return True
        return False

    def sources(self) -> list[dict]:
        """The (fresh) marker records, for attributing WHICH server(s) raised the taint."""
        out: list[dict] = []
        try:
            for p in self._iter_markers():
                if not self._is_fresh(p):
                    continue
                try:
                    out.append(json.loads(p.read_text(encoding="utf-8")))
                except (OSError, ValueError):
                    continue
        except OSError:
            return out
        return out

    # --- internals --------------------------------------------------------------------

    def _iter_markers(self):
        return self.dir.glob("*.taint")

    def _is_fresh(self, p: Path) -> bool:
        """A marker is fresh while its writing proxy is alive, or within ttl of last activity.

        A vanished marker (raced with expiry/prune) is simply not-fresh, but a PERMISSION error
        propagates so `is_tainted` can fail CLOSED rather than silently treat an unreadable but
        present marker as not-fresh (audit L3 round-3)."""
        try:
            st = p.stat()
        except FileNotFoundError:
            return False  # marker vanished: not fresh
        # any other OSError (notably EACCES on an inaccessible dir) propagates to is_tainted
        age = time.time() - st.st_mtime
        if age <= self.ttl:
            return True
        if age > _HARD_MAX_AGE:
            return False
        pid = self._marker_pid(p)
        return pid is not None and _pid_alive(pid)

    @staticmethod
    def _marker_pid(p: Path) -> int | None:
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
            pid = rec.get("pid")
            return int(pid) if isinstance(pid, int) else None
        except (OSError, ValueError, TypeError):
            return None

    def _bump_hwm(self) -> None:
        """Record that taint is currently raised, for deletion detection. Stores this proxy's
        pid so the anchor stays authoritative while the tainting proxy is alive, closing the
        'delete the markers then wait out the ttl while the proxy idles' bypass (H8)."""
        try:
            (self.dir / _HWM_NAME).write_text(
                json.dumps({"ts": time.time(), "pid": os.getpid()}), encoding="utf-8"
            )
        except OSError:
            pass

    def _deletion_suspected(self) -> bool:
        """True if the high-water anchor says taint was raised and the tainting proxy is still
        around - within the ttl OR its pid still alive - but no live marker remains, i.e. the
        markers were DELETED rather than expiring naturally. A hard-age cap bounds a recycled
        pid so an exited proxy's taint still self-expires."""
        try:
            rec = json.loads((self.dir / _HWM_NAME).read_text(encoding="utf-8"))
            ts = float(rec.get("ts", 0))
            pid = rec.get("pid")
        except (OSError, ValueError, TypeError):
            return False
        age = time.time() - ts
        if age > _HARD_MAX_AGE:
            return False  # bound recycled-pid false positives
        if age <= self.ttl:
            return True
        return isinstance(pid, int) and _pid_alive(pid)

    def _prune(self) -> None:
        """Remove markers that are neither fresh nor within the hard cap, so the directory
        stays small and a stale session's taint does not gate a fresh one."""
        try:
            for p in self._iter_markers():
                try:
                    if not self._is_fresh(p):
                        p.unlink()
                except OSError:
                    continue
        except OSError:
            pass
