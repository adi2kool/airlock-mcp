"""Command line entry point.

  airlock scan     TARGET [--http] [--format human|json|sarif] [--sarif PATH]
                            [--judge on|off|auto]
  airlock scan-source PATH [--format human|json|sarif] [--sarif PATH]
  airlock audit    TARGET [--http] [--format human|json|sarif] [--sarif PATH]
  airlock guard    TARGET [--http] [--origin author|user|external|derived]
  airlock baseline TARGET [--http] --out PATH
  airlock drift    TARGET [--http] --baseline PATH
  airlock lock     TARGET [--http] --out PATH [--require-signature] [--keyid ID]
  airlock report   LEDGER [--format human|json|html] [--out PATH] [--key PATH]
  airlock verify-log LEDGER [--key PATH] [--format human|json]
  airlock redteam  [--format human|json]
  airlock compose  TARGET [TARGET ...] [--http] [--format human|json]
  airlock prevalence MANIFEST [--format human|json] [--anonymize] [--allow-remote]
  airlock prevalence-source MANIFEST [--format human|json] [--anonymize]
  airlock keygen   [--private PATH] [--public PATH] [--jwks PATH] [--kid ID]
  airlock init     [--client claude-desktop|cursor|claude-code|all] [--dry-run]
                            [--on-action ...] [--on-egress ...] [--no-lock] [--launcher CMD]
  airlock proxy    TARGET [--http] [--exec CMD ...] [--assume-origin ...] [--infer] [--require-signature]
                            [--key PATH] [--key-alg hmac-sha256|ed25519] [--keystore PATH]
                            [--on-action annotate|approve|block]
                            [--on-egress annotate|redact|block] [--explain]
                            [--taint-context DIR] [--taint-ttl SECONDS]
                            [--audit-log PATH] [--audit-key PATH] [--lock PATH]
                            [--approval-webhook URL] [--approval-timeout SECONDS]

TARGET is a path to a stdio MCP server script, or an HTTP URL when --http is given.
`keygen` generates an Ed25519 keypair (and optional JWKS) for content and audit-trail
signing;
`scan` detects injection in prompts and resources (and proposes sanitized rewrites);
`scan-source` statically extracts a server's declared tool/prompt descriptions from its
source tree and scans them without executing the code (the safe path for untrusted servers);
`audit` flags capabilities a server advertises but does not exercise; `guard` reads
the server's provenance and runs the client enforcer, showing injected content
demoted to data or quarantined and never instruction-eligible; `baseline` and
`drift` capture and compare a hashed snapshot of the server surface to catch rug
pulls; `redteam` runs the adaptive-attack harness against our own defense and reports
attack success under naive versus adaptive attackers plus the residual risk; `compose`
analyzes a set of servers together and flags when they jointly enable the lethal
trifecta (private-data access plus untrusted content plus an exfiltration path);
`prevalence` runs the Phase C study over a manifest of servers (local install,
scan-only, license-gated) and reports how widespread injectable surface is;
`init` detects your MCP client config (Claude Desktop / Cursor / Claude Code) and wraps every
server behind the proxy in one command, pinning each surface into a lockfile in the same pass;
`proxy` runs an enforcing proxy that fronts a server (a script TARGET, an `--http` URL, or any
command via `--exec`) and applies the client contract to everything it emits, so an unmodified
client is protected end to end (add `--explain` for a live decision stream); `report` renders a
proxy audit trail (the flight recorder) as a readable summary, JSON, or a self-contained HTML page.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from airlock.enforce.middleware import context_requires_approval, enforce
from airlock.models import Origin, Report, Severity, Trust, severity_rank
from airlock.provenance.tagger import tag_meta
from airlock.report import render_human, render_json, render_sarif
from airlock.scan.client import connect, fetch_targets
from airlock.scan.detectors.judge import Judge
from airlock.scan.detectors.patterns import scan_targets
from airlock.scan.drift import capture_surface, diff_surfaces, make_baseline, surface_hash
from airlock.scan.leastpriv import audit_session
from airlock.scan.remediate import propose_remediations


async def _run_scan(target: str, is_http: bool, judge: Judge) -> Report:
    report = Report(target=target)
    async with connect(target, is_http) as (session, init_result):
        targets, tool_names, errors = await fetch_targets(session, init_result)
    report.items_scanned = len(targets)
    report.errors = errors

    findings = scan_targets(targets, tool_names)

    report.judge_requested = judge.mode != "off"
    report.judge_available = judge.available()
    if report.judge_available:
        for item in targets:
            judged = judge.judge(item)
            if judged:
                report.judge_used = True
                findings.extend(judged)

    report.findings = findings
    report.remediations = propose_remediations(targets)
    return report


async def _run_audit(target: str, is_http: bool) -> Report:
    report = Report(target=target)
    async with connect(target, is_http) as (session, init_result):
        report.leastpriv = await audit_session(session, init_result)
    return report


async def _run_scan_memory(target: str, is_http: bool, judge: Judge) -> Report:
    from airlock.scan.memory import fetch_memory_entries

    report = Report(target=target)
    async with connect(target, is_http) as (session, _init):
        targets, read_tools, errors = await fetch_memory_entries(session)
    report.items_scanned = len(targets)
    report.errors = errors
    # Reuse the injection detectors over the stored entries. No tool_names for the shadowing
    # detector here: memory entries are data, not tool declarations.
    findings = scan_targets(targets, [])
    report.judge_requested = judge.mode != "off"
    report.judge_available = judge.available()
    if report.judge_available:
        for item in targets:
            judged = judge.judge(item)
            if judged:
                report.judge_used = True
                findings.extend(judged)
    report.findings = findings
    return report


def _target_missing(args: argparse.Namespace) -> bool:
    return not args.http and not Path(args.target).exists()


def _emit(report: Report, args: argparse.Namespace) -> int:
    if args.format == "json":
        print(render_json(report))
    elif args.format == "sarif":
        print(json.dumps(render_sarif(report), indent=2))
    else:
        print(render_human(report))

    if args.sarif:
        Path(args.sarif).write_text(json.dumps(render_sarif(report), indent=2))

    # Exit 1 when any finding is at or above WARNING (CI-friendly).
    if severity_rank(report.worst_severity) >= severity_rank(Severity.WARNING):
        return 1
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    if _target_missing(args):
        print(f"error: target script not found: {args.target}", file=sys.stderr)
        return 2
    judge = Judge(mode=args.judge)
    try:
        report = asyncio.run(_run_scan(args.target, args.http, judge))
    except Exception as exc:  # noqa: BLE001 - connection/protocol failure
        print(f"error: could not scan target: {exc}", file=sys.stderr)
        return 3
    return _emit(report, args)


def _cmd_audit(args: argparse.Namespace) -> int:
    if _target_missing(args):
        print(f"error: target script not found: {args.target}", file=sys.stderr)
        return 2
    try:
        report = asyncio.run(_run_audit(args.target, args.http))
    except Exception as exc:  # noqa: BLE001 - connection/protocol failure
        print(f"error: could not audit target: {exc}", file=sys.stderr)
        return 3
    return _emit(report, args)


def _cmd_scan_memory(args: argparse.Namespace) -> int:
    if _target_missing(args):
        print(f"error: target script not found: {args.target}", file=sys.stderr)
        return 2
    judge = Judge(mode=args.judge)
    try:
        report = asyncio.run(_run_scan_memory(args.target, args.http, judge))
    except Exception as exc:  # noqa: BLE001 - connection/protocol failure
        print(f"error: could not scan memory: {exc}", file=sys.stderr)
        return 3
    return _emit(report, args)


async def _run_guard(target: str, is_http: bool, assume_origin: Origin):
    async with connect(target, is_http) as (session, _init):
        targets, _tools, errors = await fetch_targets(session)
    rows = []
    for item in targets:
        from airlock.enforce.middleware import parse_provenance

        if parse_provenance(item.meta) is not None:
            # The server tagged this item: enforce its real, on-the-wire provenance.
            e = enforce(item.text, item.meta)
            source = "wire"
        else:
            # No provenance: simulate a tagging server at the assumed origin so the
            # enforcer still has something to act on. A conforming client would treat
            # this as missing -> untrusted (fail closed) regardless.
            body, meta = tag_meta(item.text, assume_origin)
            e = enforce(body, meta)
            source = f"assumed:{assume_origin.value}"
        rows.append((item, e, source))
    return rows, errors


def _cmd_guard(args: argparse.Namespace) -> int:
    if _target_missing(args):
        print(f"error: target script not found: {args.target}", file=sys.stderr)
        return 2
    assume_origin = Origin(args.origin)
    try:
        rows, errors = asyncio.run(_run_guard(args.target, args.http, assume_origin))
    except Exception as exc:  # noqa: BLE001 - connection/protocol failure
        print(f"error: could not guard target: {exc}", file=sys.stderr)
        return 3

    print(f"airlock guard: {args.target}")
    print(
        "reading provenance from the wire; untagged items assumed "
        f"origin={assume_origin.value}, then enforcing the contract"
    )
    if errors:
        print(f"errors: {len(errors)}")
        for err in errors:
            print(f"  ! {err}")
    print("")

    quarantined = demoted = instruction_eligible = 0
    for item, e, source in rows:
        if e.disposition is Trust.QUARANTINED:
            quarantined += 1
        elif not e.instruction_allowed:
            demoted += 1
        if e.instruction_allowed:
            instruction_eligible += 1
        flags = f"  [{', '.join(e.flags)}]" if e.flags else ""
        print(
            f"  {item.surface} {item.identifier} ({source}): {e.disposition.value}  "
            f"instruction_allowed={e.instruction_allowed}{flags}"
        )

    print("")
    print(
        f"{len(rows)} item(s): {quarantined} quarantined, {demoted} demoted to data, "
        f"{instruction_eligible} instruction-eligible"
    )
    approval = context_requires_approval([e for _, e, _ in rows])
    print(f"action gating: side-effecting actions require human approval = {approval}")
    # Exit 1 if any item was quarantined or demoted (untrusted content was present).
    return 1 if (quarantined or demoted) else 0


async def _capture(target: str, is_http: bool) -> dict:
    async with connect(target, is_http) as (session, init):
        return await capture_surface(session, getattr(init, "instructions", None))


def _cmd_baseline(args: argparse.Namespace) -> int:
    if _target_missing(args):
        print(f"error: target script not found: {args.target}", file=sys.stderr)
        return 2
    try:
        surface = asyncio.run(_capture(args.target, args.http))
    except Exception as exc:  # noqa: BLE001 - connection/protocol failure
        print(f"error: could not capture baseline: {exc}", file=sys.stderr)
        return 3
    baseline = make_baseline(surface)
    Path(args.out).write_text(json.dumps(baseline, indent=2, ensure_ascii=False))
    counts = {k: len(v) for k, v in surface.items()}
    print(f"baseline written to {args.out}")
    print(f"surface: {counts['tools']} tools, {counts['prompts']} prompts, "
          f"{counts['resources']} resources  hash={baseline['hash'][:16]}...")
    return 0


def _cmd_lock(args: argparse.Namespace) -> int:
    from airlock.lockfile import generate_lock

    if _target_missing(args):
        print(f"error: target script not found: {args.target}", file=sys.stderr)
        return 2
    try:
        surface = asyncio.run(_capture(args.target, args.http))
    except Exception as exc:  # noqa: BLE001 - connection/protocol failure
        print(f"error: could not capture surface: {exc}", file=sys.stderr)
        return 3
    lock = generate_lock(
        surface, require_signature=args.require_signature, allowed_keyids=args.keyid or []
    )
    Path(args.out).write_text(json.dumps(lock, indent=2, ensure_ascii=False))
    counts = {k: len(v) for k, v in surface.items()}
    print(f"trust lockfile written to {args.out}")
    print(
        f"pinned: {counts['tools']} tools, {counts['prompts']} prompts, "
        f"{counts['resources']} resources  hash={lock['surface_hash'][:16]}...  "
        f"require_signature={lock['require_signature']}"
    )
    return 0


def _cmd_verify_log(args: argparse.Namespace) -> int:
    from airlock.ledger import ledger_tip, verify_chain

    # --print-tip: emit the current (count, tip-hash) so an operator can anchor it out-of-band
    # and later detect truncation of the most recent entries with --expect-count/--expect-tip.
    if getattr(args, "print_tip", False):
        tip = ledger_tip(args.ledger)
        if tip is None:
            print(f"error: cannot read a tip from {args.ledger}", file=sys.stderr)
            return 2
        count, tip_hash = tip
        print(json.dumps({"entries": count, "tip": tip_hash}) if args.format == "json"
              else f"{count} {tip_hash}")
        return 0
    key = None
    if args.key:
        try:
            key = Path(args.key).read_bytes()
        except OSError as exc:
            print(f"error: could not read key {args.key}: {exc}", file=sys.stderr)
            return 2
    res = verify_chain(
        args.ledger, public_key=key,
        expected_entries=getattr(args, "expect_count", None),
        expected_tip=getattr(args, "expect_tip", None),
    )
    if args.format == "json":
        print(json.dumps({
            "ok": res.ok, "entries": res.entries, "signed": res.signed,
            "reason": res.reason, "first_broken_seq": res.first_broken_seq,
            "unsigned": res.unsigned,
        }, indent=2))
    else:
        print(f"ledger {args.ledger}: {'INTACT' if res.ok else 'BROKEN'}  "
              f"({res.entries} entries, {res.signed} signed)")
        print(f"  {res.reason}")
        if res.unsigned:
            # M2: an unsigned/keyless-verified chain is only tamper-EVIDENT against accidental
            # corruption, never against someone who can write the file. Say so, don't let
            # "INTACT" read as tamper-proof.
            print("  WARNING: UNSIGNED - keyless chain. 'INTACT' means no accidental corruption,"
                  " NOT tamper-proof: anyone who can write the file can rewrite an entry and"
                  " relink the chain. Run the proxy with --audit-key and verify with --key.")
        if not res.ok and res.first_broken_seq is not None:
            print(f"  first broken at seq {res.first_broken_seq}")
    return 0 if res.ok else 1


def _cmd_report(args: argparse.Namespace) -> int:
    from airlock.ledger_report import build_report, render_html, render_human, render_json

    if not Path(args.ledger).exists():
        print(f"error: ledger not found: {args.ledger}", file=sys.stderr)
        return 2
    key = None
    if getattr(args, "key", None):
        try:
            key = Path(args.key).read_bytes()
        except OSError as exc:
            print(f"error: could not read key {args.key}: {exc}", file=sys.stderr)
            return 2
    rep = build_report(
        args.ledger, public_key=key,
        expected_entries=getattr(args, "expect_count", None),
        expected_tip=getattr(args, "expect_tip", None),
    )
    if args.format == "json":
        out = render_json(rep)
    elif args.format == "html":
        out = render_html(rep)
    else:
        out = render_human(rep)
    if getattr(args, "out", None):
        try:
            Path(args.out).write_text(out, encoding="utf-8")
        except OSError as exc:
            print(f"error: could not write {args.out}: {exc}", file=sys.stderr)
            return 2
        print(f"wrote {args.format} report to {args.out}", file=sys.stderr)
    else:
        print(out)
    # Non-zero exit on a broken chain, so `report` can gate CI like verify-log.
    return 0 if rep.chain.ok else 1


def _pin_upstream(command: str, cargs: list[str], lockpath: Path) -> bool:
    """Launch a stdio server via `command cargs...`, capture its surface, and write a trust
    lockfile pinning it. Best-effort: returns False (and warns) if the server cannot be
    launched, so onboarding still wraps it, just without a rug-pull pin."""
    from airlock.lockfile import generate_lock
    from airlock.scan.client import connect
    from airlock.scan.drift import capture_surface

    async def _cap() -> dict:
        async with connect(command, False, stdio_command=command, stdio_args=cargs) as (session, init):
            return await capture_surface(session, getattr(init, "instructions", None))

    try:
        surface = asyncio.run(_cap())
        lock = generate_lock(surface)
        lockpath.parent.mkdir(parents=True, exist_ok=True)
        lockpath.write_text(json.dumps(lock, indent=2, ensure_ascii=False), encoding="utf-8")
        return True
    except Exception as exc:  # noqa: BLE001 - a server that will not launch is still wrapped
        print(f"    (could not pin {command}: {_root_cause(exc)}; wrapping without a lock)",
              file=sys.stderr)
        return False


def _cmd_init(args: argparse.Namespace) -> int:
    import os
    import shlex

    from airlock import onboard

    clients = onboard.CLIENTS if args.client == "all" else (args.client,)
    # Explicit --config paths are a deliberate opt-in for project-local configs (which are
    # never auto-discovered, so a cloned repo can't get its checked-in servers wrapped/launched
    # just by running init in it). When given, they REPLACE auto-discovery.
    if args.config:
        found = []
        for raw in args.config:
            p = Path(raw).expanduser()
            if p.is_file():
                found.append(("custom", p))
            else:
                print(f"! --config {raw}: not a file; skipping", file=sys.stderr)
    else:
        found = onboard.discover(
            clients, Path.home(), sys.platform, Path.cwd(), os.environ.get("APPDATA")
        )
    if not found:
        print("no MCP client config found (looked for Claude Desktop / Cursor / Claude Code; "
              "pass --config PATH for a project-local config).", file=sys.stderr)
        return 1

    launcher = shlex.split(args.launcher) if args.launcher else ["airlock"]
    base_flags: list[str] = []
    if args.on_action:
        base_flags += ["--on-action", args.on_action]
    if args.on_egress:
        base_flags += ["--on-egress", args.on_egress]
    audit_dir = Path(args.audit_dir).expanduser() if args.audit_dir else Path.home() / ".airlock" / "audit"
    lock_dir = Path(args.lock_dir).expanduser() if args.lock_dir else Path.home() / ".airlock" / "locks"
    taint_base = Path.home() / ".airlock" / "taint"

    total_wrapped = 0
    for client, path in found:
        try:
            original_text = path.read_text(encoding="utf-8")
            doc = json.loads(original_text)
        except (OSError, ValueError) as exc:
            print(f"! {client}: cannot read {path} ({exc}); skipping", file=sys.stderr)
            continue
        servers = onboard.read_servers(doc)
        print(f"{client}: {path}")
        if not servers:
            print("  (no mcpServers; nothing to do)")
            continue

        # Phase 1: pin each wrappable stdio server by launching it once (best-effort, real run
        # only). This EXECUTES the upstream, so it is opt-in (--pin): the default path never runs
        # an unvetted server and relies on the baked --pin-on-start instead (pin on first proxied
        # start, behind the trust boundary).
        locks: dict[str, Path] = {}
        if args.pin and not args.no_lock and not args.dry_run:
            for name, spec in servers.items():
                if onboard.is_wrapped(spec, launcher):
                    continue
                if isinstance(spec, dict) and spec.get("command") and not spec.get("url"):
                    # Sanitize the server name before it becomes a path component: a hostile
                    # config key must not traverse or escape the lock dir.
                    lp = lock_dir / f"{onboard.safe_component(name)}.lock"
                    if _pin_upstream(spec["command"], list(spec.get("args") or []), lp):
                        locks[name] = lp

        # One shared cross-server taint context per config: every server in THIS client gets
        # the same directory, so untrusted content read via one gates a side-effecting call to
        # another. The id is derived from the config path so different clients do not share taint.
        ctx_dir = None if args.no_shared_taint else taint_base / onboard.taint_context_id(str(path))

        def flags_for(name, _spec):
            f = list(base_flags)
            if not args.no_audit:
                # Sanitize the name for the same reason: the baked --audit-log path is opened
                # (mkdir + append) at proxy runtime, so a traversing name would write outside.
                f += ["--audit-log", str(audit_dir / f"{onboard.safe_component(name)}.jsonl")]
            if ctx_dir is not None:
                f += ["--taint-context", str(ctx_dir)]
            if name in locks:
                f += ["--lock", str(locks[name])]
            elif not args.no_lock:
                # Not eagerly pinned (the default): pin on first PROXIED start instead, so the
                # rug-pull defense still applies without init ever executing the upstream.
                f += ["--pin-on-start"]
            return f

        plans = onboard.plan_servers(servers, launcher, flags_for)
        wrapped = 0
        for p in plans:
            if p.action == "skip-wrapped":
                print(f"  = {p.name}: already wrapped")
            elif p.action == "skip-unwrappable":
                print(f"  ! {p.name}: no command or url; left unchanged")
            else:  # wrap
                servers[p.name] = p.new_spec
                pinned = " +pinned" if p.name in locks else ""
                print(f"  + {p.name}: wrapped{pinned}")
                wrapped += 1
                total_wrapped += 1

        if wrapped and not args.dry_run:
            backup = path.with_name(path.name + ".airlock.bak")
            if not backup.exists():
                backup.write_text(original_text, encoding="utf-8")
            if not args.no_audit:
                audit_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
            print(f"  wrote {path}  (backup: {backup.name})")

    if args.dry_run:
        print(f"\ndry run: {total_wrapped} server(s) would be wrapped. Re-run without --dry-run to apply.")
    else:
        print(f"\ndone: wrapped {total_wrapped} server(s). "
              f"Restart the client, then `airlock report <audit>.jsonl` to see what it stops. "
              f"Restore any config from its .airlock.bak backup.")
    return 0


def _cmd_drift(args: argparse.Namespace) -> int:
    if _target_missing(args):
        print(f"error: target script not found: {args.target}", file=sys.stderr)
        return 2
    try:
        baseline = json.loads(Path(args.baseline).read_text())
    except Exception as exc:  # noqa: BLE001
        print(f"error: could not read baseline {args.baseline}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(baseline, dict):
        print(f"error: baseline {args.baseline} is not a valid baseline object", file=sys.stderr)
        return 2

    old_surface = baseline.get("surface", {})
    # Detect tampering of the baseline file itself.
    if surface_hash(old_surface) != baseline.get("hash"):
        print("error: baseline hash does not match its surface (baseline file altered)",
              file=sys.stderr)
        return 2

    try:
        new_surface = asyncio.run(_capture(args.target, args.http))
    except Exception as exc:  # noqa: BLE001
        print(f"error: could not capture current surface: {exc}", file=sys.stderr)
        return 3

    print(f"airlock drift: {args.target}")
    if surface_hash(new_surface) == baseline.get("hash"):
        print("no drift: server surface is unchanged since the baseline")
        return 0

    changes = diff_surfaces(old_surface, new_surface)
    print(f"DRIFT DETECTED: {len(changes)} change(s) since the baseline")
    for c in changes:
        detail = f"  {c.detail}" if c.detail else ""
        print(f"  [{c.kind.upper()}] {c.category[:-1]} {c.name}{detail}")
    return 1


async def _run_compose(targets: list[str], is_http: bool):
    from airlock.compose import capture_surface

    surfaces = []
    errors: list[str] = []
    for target in targets:
        try:
            async with connect(target, is_http) as (session, init):
                name = getattr(getattr(init, "serverInfo", None), "name", None) or Path(target).name
                surfaces.append(await capture_surface(session, name))
        except Exception as exc:  # noqa: BLE001 - one bad server should not abort the set
            errors.append(f"{target}: {exc}")
    return surfaces, errors


def _cmd_compose(args: argparse.Namespace) -> int:
    from airlock.compose import analyze_composition, render_human, render_json

    missing = [t for t in args.targets if not args.http and not Path(t).exists()]
    if missing:
        print(f"error: target script(s) not found: {', '.join(missing)}", file=sys.stderr)
        return 2
    try:
        surfaces, errors = asyncio.run(_run_compose(args.targets, args.http))
    except Exception as exc:  # noqa: BLE001
        print(f"error: could not analyze composition: {exc}", file=sys.stderr)
        return 3
    report = analyze_composition(surfaces, errors=errors)
    if args.format == "json":
        print(render_json(report))
    else:
        print(render_human(report), end="")
    # Exit 1 when the composition enables the lethal trifecta (CI-friendly).
    return 1 if report.trifecta_enabled else 0


def _cmd_keygen(args: argparse.Namespace) -> int:
    import os

    from airlock.provenance.integrity import generate_ed25519_keypair

    private, public = generate_ed25519_keypair()
    # Create the private key at 0600 ATOMICALLY (O_CREAT with mode), so it is never even
    # briefly group/world-readable - a write-then-chmod leaves a window at the default umask.
    fd = os.open(args.private, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, private)
    finally:
        os.close(fd)
    try:
        os.chmod(args.private, 0o600)  # tighten in case the file pre-existed with looser perms
    except OSError:
        pass
    Path(args.public).write_bytes(public)
    print(f"wrote Ed25519 private key -> {args.private} (keep secret, mode 0600)", file=sys.stderr)
    print(f"wrote Ed25519 public key  -> {args.public} (publish / share for verification)", file=sys.stderr)
    if args.jwks:
        from airlock.enforce.keys import jwks_document

        Path(args.jwks).write_text(json.dumps(jwks_document([(args.kid, public)]), indent=2))
        print(f"wrote JWKS (kid={args.kid})   -> {args.jwks} (serve at .well-known or pass --keystore)",
              file=sys.stderr)
    print(
        "the tagging server signs content with the private key (sig_alg=ed25519, "
        f"keyid={args.kid!r}); the enforcer or proxy verifies with the public key "
        "(--key PUBLIC --key-alg ed25519 --require-signature, or --keystore JWKS)"
    )
    return 0


def _cmd_proxy(args: argparse.Namespace) -> int:
    from airlock.enforce.proxy import ProxyPolicy, run_proxy

    # --exec fronts an arbitrary command as the upstream; a plain TARGET fronts a python
    # script or (with --http) an HTTP URL. Exactly one source of the upstream is required.
    exec_cmd = getattr(args, "exec", None) or None
    if exec_cmd:
        if args.http:
            print("error: --exec fronts a stdio command; do not combine it with --http",
                  file=sys.stderr)
            return 2
    else:
        if not getattr(args, "target", None):
            print("error: proxy needs a TARGET (a server path, or an --http URL) or --exec CMD",
                  file=sys.stderr)
            return 2
        if _target_missing(args):
            print(f"error: upstream server not found: {args.target}", file=sys.stderr)
            return 2
    key = None
    if args.key:
        # The algorithm of a directly-configured --key must be declared, never inferred
        # from the item. An Ed25519 PUBLIC key silently treated as an HMAC secret is a
        # signature-forgery foot-gun (algorithm confusion), so require --key-alg here.
        if args.key_alg is None:
            print(
                "error: --key requires --key-alg {hmac-sha256|ed25519} (the algorithm the "
                "key is for). For an Ed25519 public key use --key-alg ed25519, or prefer "
                "--keystore JWKS which is Ed25519 by construction.",
                file=sys.stderr,
            )
            return 2
        try:
            key = Path(args.key).read_bytes()
        except OSError as exc:
            print(f"error: could not read key {args.key}: {exc}", file=sys.stderr)
            return 2
    key_resolver = None
    if args.keystore:
        from airlock.enforce.keys import KeyStore

        try:
            key_resolver = KeyStore.from_file(args.keystore).resolve
        except (OSError, ValueError) as exc:
            print(f"error: could not read keystore {args.keystore}: {exc}", file=sys.stderr)
            return 2
    if args.require_signature and not (args.key or args.keystore):
        # Without a key there is nothing to verify against, so every trusted item is
        # downgraded to untrusted. Warn rather than silently neutralize the server.
        print(
            "warning: --require-signature without --key/--keystore cannot verify any "
            "signature, so ALL trusted content is downgraded to untrusted (data only). "
            "Provide a key to actually authenticate trusted labels.",
            file=sys.stderr,
        )
    audit_key = None
    if getattr(args, "audit_key", None):
        try:
            audit_key = Path(args.audit_key).read_bytes()
        except OSError as exc:
            print(f"error: could not read audit key {args.audit_key}: {exc}", file=sys.stderr)
            return 2
    lock = None
    if getattr(args, "lock", None):
        from airlock.lockfile import load_lock

        try:
            lock = load_lock(args.lock)
        except (OSError, ValueError) as exc:
            print(f"error: could not read lockfile {args.lock}: {exc}", file=sys.stderr)
            return 2
    approval_resolver = None
    if getattr(args, "approval_webhook", None):
        from airlock.enforce.broker import webhook_resolver

        approval_resolver = webhook_resolver(args.approval_webhook, args.approval_timeout)
    # Live drift default: with a checked-in lock, block a mid-session rug pull by default;
    # under TOFU (--pin-on-start), default to taint-only (non-destructive). --on-drift wins.
    drift_mode = getattr(args, "on_drift", None)
    if drift_mode is None:
        drift_mode = "block" if lock is not None else "taint"
    # --dlp-optional: enable opt-in egress detectors (us_ssn / email / phone) by name.
    egress_optional: tuple[str, ...] = ()
    if getattr(args, "dlp_optional", None):
        from airlock.enforce.dlp import OPTIONAL_DETECTORS

        requested = [n.strip() for n in args.dlp_optional.split(",") if n.strip()]
        unknown = [n for n in requested if n not in OPTIONAL_DETECTORS]
        if unknown:
            print(f"error: unknown --dlp-optional detector(s): {', '.join(unknown)}. "
                  f"Choose from: {', '.join(sorted(OPTIONAL_DETECTORS))}.", file=sys.stderr)
            return 2
        egress_optional = tuple(requested)
    policy = ProxyPolicy(
        assume_origin=Origin(args.assume_origin) if args.assume_origin else None,
        verify_key=key,
        require_signature=args.require_signature,
        infer=args.infer,
        trust_inferred=args.trust_inferred,
        key_resolver=key_resolver,
        action_mode=args.on_action,
        key_alg=args.key_alg or "hmac-sha256",
        audit_log=getattr(args, "audit_log", None),
        audit_sign_key=audit_key,
        audit_keyid=getattr(args, "audit_keyid", None),
        lock=lock,
        approval_resolver=approval_resolver,
        approval_timeout=getattr(args, "approval_timeout", 300.0),
        pin_on_start=getattr(args, "pin_on_start", False),
        drift_mode=drift_mode,
        sampling_mode=getattr(args, "on_sampling", "frame"),
        elicitation_mode=getattr(args, "on_elicitation", "frame"),
        egress_mode=getattr(args, "on_egress", "annotate"),
        egress_optional=egress_optional,
        taint_context=getattr(args, "taint_context", None),
        taint_ttl=getattr(args, "taint_ttl", 3600.0),
    )
    # --explain: stream every enforcement decision to stderr live. Zero core change - it
    # just surfaces the airlock.proxy/enforce INFO logs the proxy already emits at each
    # decision, formatted for a human. stdout stays pure MCP; the stream goes to stderr.
    if getattr(args, "explain", False):
        import logging

        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("[airlock] %(message)s"))
        for name in ("airlock.proxy", "airlock.enforce"):
            lg = logging.getLogger(name)
            lg.setLevel(logging.INFO)
            lg.addHandler(handler)
            lg.propagate = False
    stdio_command = exec_cmd[0] if exec_cmd else None
    stdio_args = exec_cmd[1:] if exec_cmd else None
    label = args.target or (" ".join(exec_cmd) if exec_cmd else "")
    # The proxy speaks MCP over stdio; nothing may print to stdout here. Status and
    # errors go to stderr only.
    print(f"airlock proxy: fronting {label} (stdio); enforcing the client contract",
          file=sys.stderr)
    try:
        asyncio.run(run_proxy(label, args.http, policy, stdio_command, stdio_args))
    except KeyboardInterrupt:
        return 0
    except Exception as exc:  # noqa: BLE001 - connection/protocol failure
        print(f"error: proxy failed: {_root_cause(exc)}", file=sys.stderr)
        return 3
    return 0


def _root_cause(exc: BaseException) -> str:
    """Flatten an ExceptionGroup (anyio task groups wrap failures) to the most specific
    message, so an operator sees the real cause (e.g. a lock violation) not 'errors in a
    TaskGroup'. Prefers a LockViolationError if one is present."""
    from airlock.enforce.proxy import LockViolationError

    leaves: list[BaseException] = []

    def walk(e: BaseException) -> None:
        if isinstance(e, BaseExceptionGroup):
            for sub in e.exceptions:
                walk(sub)
        else:
            leaves.append(e)

    walk(exc)
    for e in leaves:
        if isinstance(e, LockViolationError):
            return str(e)
    return "; ".join(str(e) for e in leaves) or str(exc)


def _cmd_redteam(args: argparse.Namespace) -> int:
    import logging

    from airlock.redteam.adaptive import render_human, render_json, run_all, summarize

    # The enforcer logs quarantines/downgrades at WARNING; those are the expected
    # outcome of every attack here, so silence them for a clean report.
    logging.getLogger("airlock.enforce").setLevel(logging.ERROR)

    results = run_all()
    summary = summarize(results)
    if args.format == "json":
        print(render_json(results, summary))
    else:
        print(render_human(results, summary))
    # Exit 1 only if a non-residual attack reached the instruction path (a real
    # regression in the defense). Documented residual successes do not fail the run.
    return 0 if summary.defense_holds else 1


def _cmd_scan_source(args: argparse.Namespace) -> int:
    from airlock.scan.source import scan_source_report

    root = Path(args.path)
    if not root.exists():
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2
    try:
        report = scan_source_report(root)
    except Exception as exc:  # noqa: BLE001 - surface a clean error, never a traceback
        print(f"error: could not scan source: {exc}", file=sys.stderr)
        return 2
    return _emit(report, args)


def _cmd_prevalence(args: argparse.Namespace) -> int:
    from airlock.prevalence import (
        load_manifest,
        render_study,
        render_study_json,
        run_study,
    )

    try:
        specs = load_manifest(args.manifest)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: could not load manifest: {exc}", file=sys.stderr)
        return 2
    study = asyncio.run(run_study(specs, allow_remote=args.allow_remote, timeout=args.timeout))
    if args.format == "json":
        print(render_study_json(study, anonymize=args.anonymize))
    else:
        print(render_study(study, anonymize=args.anonymize))
    return 0


def _cmd_prevalence_source(args: argparse.Namespace) -> int:
    from airlock.prevalence.acquire import load_source_manifest, run_source_study
    from airlock.prevalence.harness import render_study, render_study_json

    try:
        specs = load_source_manifest(args.manifest)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: could not load manifest: {exc}", file=sys.stderr)
        return 2
    study = run_source_study(specs)
    if args.format == "json":
        print(render_study_json(study, anonymize=args.anonymize))
    else:
        print(render_study(study, anonymize=args.anonymize))
    return 0


def build_parser() -> argparse.ArgumentParser:
    from airlock import __version__

    parser = argparse.ArgumentParser(prog="airlock", description="MCP trust-boundary tooling")
    parser.add_argument("--version", action="version", version=f"airlock {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan an MCP server's prompts and resources")
    scan.add_argument("target", help="stdio server script path, or an HTTP URL with --http")
    scan.add_argument("--http", action="store_true", help="treat TARGET as a streamable HTTP URL")
    scan.add_argument(
        "--format",
        choices=["human", "json", "sarif"],
        default="human",
        help="output format (default: human)",
    )
    scan.add_argument("--sarif", metavar="PATH", help="also write a SARIF file to PATH")
    scan.add_argument(
        "--judge",
        choices=["on", "off", "auto"],
        default=None,
        help="optional local-model judge (default: env AIRLOCK_JUDGE or auto)",
    )
    scan.set_defaults(func=_cmd_scan)

    audit = sub.add_parser(
        "audit", help="flag capabilities a server advertises but does not exercise"
    )
    audit.add_argument("target", help="stdio server script path, or an HTTP URL with --http")
    audit.add_argument("--http", action="store_true", help="treat TARGET as a streamable HTTP URL")
    audit.add_argument(
        "--format",
        choices=["human", "json", "sarif"],
        default="human",
        help="output format (default: human)",
    )
    audit.add_argument("--sarif", metavar="PATH", help="also write a SARIF file to PATH")
    audit.set_defaults(func=_cmd_audit)

    scan_memory = sub.add_parser(
        "scan-memory",
        help="scan an MCP memory server's STORED entries for injection (calls its recall "
        "tools and runs the detectors over what is persisted)",
    )
    scan_memory.add_argument("target", help="stdio server script path, or an HTTP URL with --http")
    scan_memory.add_argument("--http", action="store_true", help="treat TARGET as a streamable HTTP URL")
    scan_memory.add_argument(
        "--format", choices=["human", "json", "sarif"], default="human",
        help="output format (default: human)",
    )
    scan_memory.add_argument("--sarif", metavar="PATH", help="also write a SARIF file to PATH")
    scan_memory.add_argument(
        "--judge", choices=["on", "off", "auto"], default=None,
        help="optional local-model judge (default: env AIRLOCK_JUDGE or auto)",
    )
    scan_memory.set_defaults(func=_cmd_scan_memory)

    guard = sub.add_parser(
        "guard", help="read a server's provenance and run the client enforcer over it"
    )
    guard.add_argument("target", help="stdio server script path, or an HTTP URL with --http")
    guard.add_argument("--http", action="store_true", help="treat TARGET as a streamable HTTP URL")
    guard.add_argument(
        "--origin",
        choices=[o.value for o in Origin],
        default="external",
        help="origin to assume for items the server did not tag (default: external)",
    )
    guard.set_defaults(func=_cmd_guard)

    baseline = sub.add_parser(
        "baseline", help="capture a hashed baseline of a server's full surface"
    )
    baseline.add_argument("target", help="stdio server script path, or an HTTP URL with --http")
    baseline.add_argument("--http", action="store_true", help="treat TARGET as a streamable HTTP URL")
    baseline.add_argument("--out", required=True, metavar="PATH", help="write the baseline JSON here")
    baseline.set_defaults(func=_cmd_baseline)

    drift = sub.add_parser(
        "drift", help="detect changes to a server's surface since a baseline (rug pull)"
    )
    drift.add_argument("target", help="stdio server script path, or an HTTP URL with --http")
    drift.add_argument("--http", action="store_true", help="treat TARGET as a streamable HTTP URL")
    drift.add_argument("--baseline", required=True, metavar="PATH", help="baseline JSON to compare against")
    drift.set_defaults(func=_cmd_drift)

    lock = sub.add_parser(
        "lock", help="pin a server's surface into a trust lockfile the proxy enforces"
    )
    lock.add_argument("target", help="stdio server script path, or an HTTP URL with --http")
    lock.add_argument("--http", action="store_true", help="treat TARGET as a streamable HTTP URL")
    lock.add_argument("--out", required=True, metavar="PATH", help="write the airlock.lock JSON here")
    lock.add_argument("--require-signature", action="store_true",
                      help="record that the proxy must require signed content from this server")
    lock.add_argument("--keyid", action="append", metavar="ID",
                      help="restrict verification to this keyid (repeatable)")
    lock.set_defaults(func=_cmd_lock)

    init = sub.add_parser(
        "init",
        help="detect your MCP client config and wrap every server behind the enforcing proxy",
    )
    init.add_argument(
        "--client", choices=["claude-desktop", "cursor", "claude-code", "all"], default="all",
        help="which client's config to wrap (default: all detected)",
    )
    init.add_argument(
        "--config", metavar="PATH", action="append", default=None,
        help="wrap an explicit config file (repeatable). Use this for a PROJECT-LOCAL config "
        "(e.g. ./.mcp.json): those are never auto-discovered, since running init inside an "
        "untrusted repo must not pick up its checked-in servers.",
    )
    init.add_argument(
        "--launcher", metavar="CMD", default=None,
        help="how the rewritten config invokes airlock (default: 'airlock'; e.g. "
        "'uvx airlock-mcp' or 'python -m airlock.cli')",
    )
    init.add_argument("--on-action", choices=["annotate", "approve", "block"], default=None,
                      help="bake this action-gate mode into every wrapped server (default: annotate)")
    init.add_argument("--on-egress", choices=["annotate", "redact", "block"], default=None,
                      help="bake this egress-DLP mode into every wrapped server (default: annotate)")
    init.add_argument("--pin", action="store_true",
                      help="eagerly LAUNCH each server once during init to pin its surface into a "
                      "lockfile. Off by default: init otherwise never executes an upstream and "
                      "instead bakes --pin-on-start, so each server is pinned on its first proxied "
                      "run. Only use --pin for configs whose servers you already trust to launch.")
    init.add_argument("--no-lock", action="store_true",
                      help="bake no rug-pull protection at all (no --pin-on-start, no lockfile)")
    init.add_argument("--no-shared-taint", action="store_true",
                      help="do not give this client's servers a shared cross-server taint context "
                      "(each proxy then gates only on its own server's untrusted content)")
    init.add_argument("--no-audit", action="store_true",
                      help="do not bake an --audit-log path into wrapped servers")
    init.add_argument("--audit-dir", metavar="DIR", default=None,
                      help="where wrapped servers write audit trails (default: ~/.airlock/audit)")
    init.add_argument("--lock-dir", metavar="DIR", default=None,
                      help="where pinned lockfiles are written (default: ~/.airlock/locks)")
    init.add_argument("--dry-run", action="store_true",
                      help="show what would change without writing anything")
    init.set_defaults(func=_cmd_init)

    report = sub.add_parser(
        "report",
        help="render a proxy audit trail (flight recorder) as a readable summary or HTML",
    )
    report.add_argument("ledger", help="path to the audit-trail JSONL file (from proxy --audit-log)")
    report.add_argument(
        "--format", choices=["human", "json", "html"], default="human",
        help="output format: human (terminal summary + timeline), json, or html "
        "(self-contained page for a screenshot / shared proof / compliance reviewer)",
    )
    report.add_argument("--out", metavar="PATH", help="write the report to PATH instead of stdout")
    report.add_argument("--key", metavar="PATH",
                        help="Ed25519 public key to verify entry signatures for the chain badge")
    report.add_argument("--expect-count", type=int, default=None, metavar="N",
                        help="fail if the log has fewer than N entries (detects truncation of "
                        "the most recent entries; anchor with verify-log --print-tip)")
    report.add_argument("--expect-tip", metavar="HASH", default=None,
                        help="fail if the log's tip entry-hash differs from HASH (detects "
                        "truncation/divergence of the newest entries)")
    report.set_defaults(func=_cmd_report)

    verify_log = sub.add_parser(
        "verify-log", help="verify the hash chain (and signatures) of a proxy audit trail"
    )
    verify_log.add_argument("ledger", help="path to the audit-trail JSONL file")
    verify_log.add_argument("--key", metavar="PATH", help="Ed25519 public key to verify entry signatures")
    verify_log.add_argument("--print-tip", action="store_true",
                            help="print the current tip as '<count> <hash>' and exit, to anchor "
                            "out-of-band (then --expect-count/--expect-tip detects truncation)")
    verify_log.add_argument("--expect-count", type=int, default=None, metavar="N",
                            help="fail if the log has fewer than N entries (detects truncation of "
                            "the most recent entries, which a bare hash chain cannot)")
    verify_log.add_argument("--expect-tip", metavar="HASH", default=None,
                            help="fail if the log's tip entry-hash differs from HASH (a previously "
                            "anchored tip); catches truncation/divergence of recent entries")
    verify_log.add_argument("--format", choices=["human", "json"], default="human",
                            help="output format (default: human)")
    verify_log.set_defaults(func=_cmd_verify_log)

    redteam = sub.add_parser(
        "redteam",
        help="run the adaptive-attack harness against our own defense and report residual risk",
    )
    redteam.add_argument(
        "--format",
        choices=["human", "json"],
        default="human",
        help="output format (default: human)",
    )
    redteam.set_defaults(func=_cmd_redteam)

    compose = sub.add_parser(
        "compose",
        help="analyze a set of servers together for the lethal trifecta (cross-server)",
    )
    compose.add_argument(
        "targets",
        nargs="+",
        help="two or more stdio server script paths, or HTTP URLs with --http",
    )
    compose.add_argument("--http", action="store_true", help="treat TARGETs as streamable HTTP URLs")
    compose.add_argument(
        "--format",
        choices=["human", "json"],
        default="human",
        help="output format (default: human)",
    )
    compose.set_defaults(func=_cmd_compose)

    scan_source = sub.add_parser(
        "scan-source",
        help="statically scan a server's SOURCE tree for injectable declared strings "
        "(tool/prompt descriptions) without executing it",
    )
    scan_source.add_argument("path", help="path to a source directory or extracted package")
    scan_source.add_argument(
        "--format", choices=["human", "json", "sarif"], default="human",
        help="output format (default: human)",
    )
    scan_source.add_argument("--sarif", metavar="PATH", help="also write a SARIF report to PATH")
    scan_source.set_defaults(func=_cmd_scan_source)

    prevalence = sub.add_parser(
        "prevalence",
        help="Phase C study: scan a manifest of servers and report injection prevalence "
        "(local install, scan-only, license-gated)",
    )
    prevalence.add_argument(
        "manifest", help="path to a study manifest JSON (see docs/phase-c-methodology.md)"
    )
    prevalence.add_argument(
        "--format", choices=["human", "json"], default="human",
        help="output format (default: human)",
    )
    prevalence.add_argument(
        "--anonymize", action="store_true",
        help="replace server names with pseudonyms, for aggregate publication before "
        "coordinated disclosure",
    )
    prevalence.add_argument(
        "--allow-remote", action="store_true",
        help="permit non-loopback HTTP targets (only under authorization; off by default, "
        "the study is local-only)",
    )
    prevalence.add_argument(
        "--timeout", type=float, default=90.0, metavar="SECONDS",
        help="per-server enumeration timeout; a slow/hanging server is recorded failed "
        "and the study continues (default: 90)",
    )
    prevalence.set_defaults(func=_cmd_prevalence)

    prevalence_source = sub.add_parser(
        "prevalence-source",
        help="static prevalence sweep: download npm/PyPI packages (no install/execution) "
        "and scan their source for injectable declared strings",
    )
    prevalence_source.add_argument(
        "manifest", help="path to a source-sweep manifest JSON (packages + ecosystems)"
    )
    prevalence_source.add_argument(
        "--format", choices=["human", "json"], default="human",
        help="output format (default: human)",
    )
    prevalence_source.add_argument(
        "--anonymize", action="store_true",
        help="replace package names with pseudonyms for aggregate publication",
    )
    prevalence_source.set_defaults(func=_cmd_prevalence_source)

    proxy = sub.add_parser(
        "proxy",
        help="run an enforcing proxy that fronts a server and applies the client contract",
    )
    proxy.add_argument("target", nargs="?", default=None,
                       help="upstream stdio server script path, or an HTTP URL with --http "
                       "(omit when using --exec)")
    proxy.add_argument("--http", action="store_true", help="treat TARGET as a streamable HTTP URL")
    proxy.add_argument(
        "--assume-origin",
        choices=[o.value for o in Origin],
        default=None,
        help="tag untagged upstream content at this origin (default: fail closed as untrusted)",
    )
    proxy.add_argument(
        "--require-signature",
        action="store_true",
        help="downgrade trusted content that lacks a valid signature (needs --key)",
    )
    proxy.add_argument("--key", metavar="PATH", help="signing key file for signature verification (requires --key-alg)")
    proxy.add_argument(
        "--key-alg",
        choices=["hmac-sha256", "ed25519"],
        default=None,
        help="the algorithm --key is for: hmac-sha256 (shared secret) or ed25519 (raw "
        "public key). Required with --key; bound to the key so a public key is never "
        "accepted as an HMAC secret. Ignored for --keystore (always ed25519).",
    )
    proxy.add_argument("--keystore", metavar="PATH", help="JWKS file mapping keyid -> Ed25519 public key")
    proxy.add_argument(
        "--infer",
        action="store_true",
        help="classify untagged upstream content with a local model instead of blanket "
        "fail-closed framing (needs a model server; see AIRLOCK_INFER_URL)",
    )
    proxy.add_argument(
        "--trust-inferred",
        action="store_true",
        help="allow inferred 'author' content to be instruction-eligible (off by default; "
        "the operator's risk)",
    )
    proxy.add_argument(
        "--on-action",
        choices=["annotate", "approve", "block"],
        default="annotate",
        help="what to do when a side-effecting tool call is made after untrusted content "
        "has entered the session: annotate (forward, default), approve (hold for human "
        "approval), or block (refuse). approve/block do not forward the call upstream.",
    )
    proxy.add_argument(
        "--on-sampling",
        choices=["frame", "block"],
        default="frame",
        help="how to handle a server-initiated sampling (createMessage) request - the "
        "channel where an upstream pushes text into the client's own LLM: frame (enforce "
        "the messages as data and relay to the client, default) or block (refuse, no LLM "
        "call). Both enforce and record; block also stops credit-drain.",
    )
    proxy.add_argument(
        "--on-elicitation",
        choices=["frame", "block"],
        default="frame",
        help="how to handle a server-initiated elicitation request (a server-controlled "
        "prompt to the user): frame (enforce and relay a form elicitation, default) or "
        "block (decline). URL-mode elicitation is always declined (phishing vector).",
    )
    proxy.add_argument(
        "--on-egress",
        choices=["annotate", "redact", "block"],
        default="annotate",
        help="egress DLP: what to do when an OUTBOUND call to an exfil-capable tool carries "
        "a secret or high-confidence PII (AWS/GitHub/Slack/Google token, private key, JWT, "
        "Luhn-valid card, SSN) in its arguments: annotate (forward, record; default), redact "
        "(replace the secret in the forwarded arguments) or block (refuse; the secret never "
        "leaves). Only exfil-capable tools are scanned.",
    )
    proxy.add_argument(
        "--dlp-optional", metavar="NAMES", default=None,
        help="also enable these opt-in egress detectors (comma-separated: us_ssn, email, "
        "phone). Off by default because their shape collides with benign business data (an "
        "email is legitimate in a send_email arg); enable only where outbound args carry them.",
    )
    proxy.add_argument(
        "--explain",
        action="store_true",
        help="print a live, human-readable stream of every enforcement decision to stderr "
        "(content demoted to data, side-effect calls gated, egress secrets redacted/blocked, "
        "surface drift) as it happens - a proof-of-value view while the proxy runs",
    )
    proxy.add_argument(
        "--taint-context", metavar="DIR",
        help="cross-server enforcement: a directory shared with the other proxies fronting this "
        "client's servers. Untrusted content seen by ANY of them taints the whole context, so a "
        "side-effecting call to a DIFFERENT server is gated too (the lethal trifecta stopped at "
        "runtime, not just flagged). `airlock init` sets this up automatically.",
    )
    proxy.add_argument(
        "--taint-ttl", type=float, default=3600.0, metavar="SECONDS",
        help="how long a cross-server taint marker stays live (default: 3600), so a past "
        "session's taint self-expires instead of gating forever",
    )
    proxy.add_argument(
        "--audit-log", metavar="PATH",
        help="append a signed, hash-chained provenance audit trail (JSONL) to PATH (the flight recorder)",
    )
    proxy.add_argument(
        "--audit-key", metavar="PATH",
        help="Ed25519 private key (from keygen --private) to sign each audit-trail entry",
    )
    proxy.add_argument("--audit-keyid", metavar="ID", default=None,
                       help="key id to record on signed audit-trail entries")
    proxy.add_argument(
        "--lock", metavar="PATH",
        help="enforce a trust lockfile: refuse to start if the upstream surface drifted from the pin",
    )
    proxy.add_argument(
        "--pin-on-start",
        action="store_true",
        help="with no --lock, pin the first surface seen (trust-on-first-use) so a "
        "mid-session rug pull is still caught",
    )
    proxy.add_argument(
        "--on-drift",
        choices=["taint", "block"],
        default=None,
        help="what to do when the upstream surface drifts from the pin AFTER startup (a "
        "live rug pull): taint (forward but gate later side effects) or block (withhold "
        "the mutated definitions and refuse a call to a drifted tool). Default: block with "
        "--lock, taint with --pin-on-start.",
    )
    proxy.add_argument(
        "--approval-webhook", metavar="URL",
        help="in --on-action approve, POST each gated call to URL for a human approve/deny decision",
    )
    proxy.add_argument(
        "--approval-timeout", type=float, default=300.0, metavar="SECONDS",
        help="how long to wait for an approval decision before failing closed (default: 300)",
    )
    proxy.add_argument(
        "--exec", nargs=argparse.REMAINDER, default=None, metavar="CMD",
        help="front an ARBITRARY command as the upstream stdio server instead of a script "
        "TARGET (everything after --exec is the command, e.g. --exec npx -y @scope/server). "
        "This is how `airlock init` wraps Node/uv/binary servers. Put all other proxy flags "
        "BEFORE --exec.",
    )
    proxy.set_defaults(func=_cmd_proxy)

    keygen = sub.add_parser(
        "keygen", help="generate an Ed25519 keypair for content signing (sig_alg=ed25519)"
    )
    keygen.add_argument("--private", default="airlock_ed25519.key", metavar="PATH",
                        help="write the private key here (default: airlock_ed25519.key)")
    keygen.add_argument("--public", default="airlock_ed25519.pub", metavar="PATH",
                        help="write the public key here (default: airlock_ed25519.pub)")
    keygen.add_argument("--jwks", metavar="PATH", help="also write a JWKS document with the public key")
    keygen.add_argument("--kid", default="airlock-1", metavar="ID", help="key id for the JWKS (default: airlock-1)")
    keygen.set_defaults(func=_cmd_keygen)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
