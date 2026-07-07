# MCP injection prevalence: findings v1

Status: aggregate, anonymized, v1. A local security scan of open-source MCP servers for
injectable content in their declared surface. It names no server as vulnerable (none was
found). Read alongside `docs/phase-c-methodology.md` (scope and safety) and
`docs/positioning.md` (what the tool is).

## Summary

We examined **~1,000 real open-source MCP servers / packages** for injectable declared
surface (tool descriptions, tool parameter descriptions, prompts, resources), and found
**zero with an injectable finding at WARNING or ERROR severity.** The bulk of the corpus was
scanned **statically, without executing any code**. The exercise also did something as
valuable as the number: run against real-world data at scale, it exposed and let us fix three
scanner **false-positive** classes that a curated sample had hidden.

This is a **precision and specificity result, not a scare statistic.** It establishes that
open-source MCP servers overwhelmingly do not ship injection in their declared surface, and
that the detector is accurate on real data.

## Update (v2, July 2026): new-feature validation and an audit

After adding three enforcement surfaces (sampling/elicitation, live rug-pull detection,
memory provenance), the whole tool was re-validated against the **seven official MCP
reference servers** (`study/reference_servers_manifest.json`), each installed and run
locally over stdio. Aggregate, and naming only the reference servers (no vulnerability was
found in any).

- **Injection scan holds on real data.** 7/7 servers, **182 declared items scanned, 0
  injectable findings** at any severity, with the post-audit code. A real-server scan
  completes in single-digit milliseconds (everything, the largest, at ~44 ms).
- **Memory taxonomy on a real knowledge graph.** Against `server-memory`, the classifier
  correctly labeled its write and read tools; `scan-memory` called only the reads and found
  nothing. The run also surfaced a real gap (`create_relations` slipped past both the
  memory-write and destructive-verb classifiers, so the action gate would not have held it),
  which was fixed and re-verified across all nine tools without over-matching benign tools -
  the same way the breadth sweep let real data expose classifier gaps a curated sample hid.
- **Composition.** Run together the seven servers cover all three legs of the lethal
  trifecta (`compose` flags it, severity error); a deployment observation, not a per-server
  flaw.
- **Drift specificity.** Baselining a stable live server and re-checking produced an
  identical surface hash and zero drift - no false rug-pull alarm - while the detector still
  catches a genuine mid-session mutation in the fixtures.

The new code was first put through an **adversarial performance + security audit** (nine
dimensions, three-skeptic verification): 19 confirmed findings, **all fixed and
regression-tested**, including a critical action-gate mutual-exclusion bug a refactor had
introduced. Full suite after fixes: **307 tests, red-team holds (56 attacks, two documented
residuals), detector benchmark PASS.**

## The breadth sweep (static, no execution)

The headline corpus. Package names were discovered via the npm registry search API (PyPI's
search blocks automated queries, so this pass is npm; a PyPI pass is future work).

- **1,186** npm packages matching "mcp" discovered.
- **992 scanned**, **192 skipped** (no resolvable OSS license; conservatively not analyzed),
  **2 failed** (malformed/unavailable release).
- **0** packages with an ERROR- or WARNING-level injectable finding. **Prevalence: 0%.**
- 12 NOTE-level informational findings remained, all benign author documentation (for
  example a batch tool describing that it replaces its single-call sibling), correctly
  down-ranked by the tool-surface rule and never counted as injection.

Each package was fetched from the registry and its **source scanned in memory**: nothing was
installed, built, or executed; the archive was never extracted to disk; downloads were
restricted to the registry CDNs; decompression was bounded against bombs. Reproducible via
`study/breadth_manifest.json` and `blindspot prevalence-source`.

### What the first pass got wrong, and what it taught us

A first pass over the 992 produced one "ERROR" and a scatter of WARNINGs. Every one was a
false positive, verified individually:

- the "ERROR" was a security-review tool's own **test fixtures** (files named
  `vulnerable-server`), not shipped surface;
- the `hidden_unicode` warnings were the **emoji variation selector** (`U+FE0F`) and the
  **soft hyphen** (`U+00AD`) in ordinary descriptions;
- the `homoglyph` warnings were a **Greek delta** used as a math symbol (`Δt`).

Curated servers and fixtures never triggered these; real data did. We fixed all three
(benign incidental invisibles no longer flagged unless part of a genuine payload; homoglyphs
require an actual Latin look-alike; test/fixture/example files are skipped) and re-ran the
full sweep to the clean 0% above. Genuine-attack detection is unchanged (calibration:
precision 1.000, recall 0.938, fpr 0.000; the adaptive red-team still holds).

## The dynamic runs (servers actually run)

Alongside the static sweep, 28 servers were installed, run, and enumerated live (7 official
reference servers + 21 community servers): **0 with an ERROR-level finding** across more than
1,300 declared items. Those runs also validated the tool-surface false-positive suppression
on real servers (four benign patterns correctly down-ranked instead of misflagged).

## What this shows, and what it does not

- **Shows:** across ~1,000 real MCP servers/packages, injectable declared surface is
  essentially absent; the local, no-execution pipeline works at scale; and the detector's
  precision survives contact with real-world unicode and real-world code layout.
- **Does not show:** that injection is impossible or that hosted/proprietary servers are
  clean. It measures declared surface in open-source packages, not runtime behavior.

## Limitations

- **npm-only breadth.** PyPI's search API is not openly queryable, so the 992 are npm
  packages; a PyPI pass is future work. The dynamic runs include PyPI servers.
- **Declared surface, statically.** Static extraction is approximate (it resolves literals,
  f-strings, concatenation, `%`/`.format()`/`.join()`, and module constants, and skips
  test/fixture files); a description assembled fully at runtime, or in a non-source manifest,
  is out of scope. A dynamic run (`blindspot scan`) covers what static analysis cannot.
- **License-gated denominator.** 192 packages were skipped because no OSS license resolved
  from registry metadata; a curated manifest with declared licenses would scan more.
- **Local detection only.** These runs used pattern and invisible-unicode detection without
  the optional model judge.

## Reproduce

```bash
# static breadth sweep (download + scan, no execution)
uv run blindspot prevalence-source study/breadth_manifest.json --anonymize --format json

# dynamic runs
uv run blindspot prevalence study/reference_servers_manifest.json
uv run blindspot prevalence study/community_manifest.json --anonymize --format json
```

## Disclosure

This report names no server as vulnerable, because none was found. Any future named finding
follows coordinated disclosure (`docs/phase-c-methodology.md`), gated on the Phase D
prerequisites (a published repository URL, a monitored security contact, and a written
disclosure policy). Aggregate, anonymized results like this one need none of that.
