# Performance review (Phase B)

Goal of this pass: confirm the enforcement hot path is cheap, that every regex-bearing
path is linear-time (no ReDoS), and that memory stays bounded on large inputs.

Method: local microbenchmarks (Python 3.13, single machine, warm cache, 5–50 reps after
warmup). Numbers are indicative, not a formal benchmark; the shape (linear vs
super-linear) is the point, not the absolute constants. Reproduce with the harness under
`benchmark/` and the perf notes below.

## Enforcement hot path

`enforce()` on an untagged body (the common proxy case: demote to a framed data block) is
dominated by the invisible-unicode sanitizer pass plus a hash. Its cost has **two regimes**,
because the sanitizer takes an ASCII fast path (`str.isascii()` short-circuit) and only walks
the string character-by-character when it contains non-ASCII code points:

| body size | ASCII body (common) | non-ASCII body (worst case) |
| --------- | ------------------- | --------------------------- |
| 1 KB      | ~0.2 µs             | ~0.34 ms                    |
| 10 KB     | ~0.2 µs             | ~3.4 ms                     |
| 100 KB    | ~0.2 µs             | ~37 ms                      |
| 1 MB      | ~0.2 µs             | ~0.37 s                     |

Both regimes are **cleanly linear** in body size (10× the input ≈ 10× the time). Pure-ASCII
content — English, JSON, code, base64 — is effectively free (~0.2 µs regardless of size): the
fast path returns the body untouched, since no code point below U+0080 is ever an invisible/
format/tag character. Content with any non-ASCII byte pays the full per-character scan
(~0.34–0.36 µs/byte, i.e. ~340–360 µs/KB — measured on an Apple-silicon dev host) that strips
every Cf/Cs/variation-selector/tag character and decodes tag-smuggled ASCII. That scan runs
synchronously, and the proxy caps a single enforced item at `_MAX_ENFORCE_CHARS` (1 MB), so a
worst-case 1 MB non-ASCII item is ~0.37 s of CPU. Multiple content blocks in one response no
longer add without bound: `_MAX_ENFORCE_CHARS_PER_RESPONSE` (2 MB) caps the TOTAL sanitized
bytes per response — past it, remaining blocks are forwarded framed-as-untrusted (taint only,
no sanitizer), so the worst-case synchronous cost of any one response is ~0.7 s, not unbounded.
Memory is ~1× the input on the ASCII path and up to ~9× on the non-ASCII path (the sanitizer
accumulates surviving characters before `"".join`).

The signed/verify path (trusted content with a signature, which re-sanitizes and re-hashes)
carries the same sanitizer regime plus the signature check, and is only engaged when a key
is configured.

> Earlier revisions of this file quoted ~1.8 µs / ~0.6 GB/s for the 1 KB row as the single
> hot-path number, and a later revision quoted ~270 µs/KB / ~0.3 s for the non-ASCII 1 MB
> case. Both were optimistic: the ASCII figure only ever held for ASCII bodies, and the
> non-ASCII regime is ~340–360 µs/KB (~30 % higher than the ~270 quoted), so 1 MB non-ASCII is
> ~0.37 s, not ~0.3 s. The numbers above are the honest, re-measured values.

## Linear-time guarantees (ReDoS)

Two quadratic ReDoS defects were found and fixed in the scanner in earlier sessions
(sessions 8 and 11). This pass re-checked the scanner and the regexes added since
(`enforce/proxy.py` `_DESTRUCTIVE_ACTION`, and `compose.py` `_normalize`, which now splits
camelCase). All stay linear on adversarial input:

- Scanner exfil detector on a whitespace-free `http://…` run followed by a verb (the shape
  that used to backtrack): ~7.5 / ~30 / ~62 ms at 10 / 40 / 80 KB — linear in input size.
- `_normalize` + `_DESTRUCTIVE_ACTION` on a pathological alternating-case run (maximizes
  camelCase-split work): ~1.6 / ~17 / ~177 ms at 10 / 100 / 1000 KB — a clean 10× per 10×.
- `_is_side_effecting` on a 100 KB adversarial tool name+description: ~140 ms, linear. Real
  tool names are a handful of characters, so this is microseconds in practice.

No pattern exhibited super-linear growth.

## Memory

`enforce()` on a 1 MB untrusted body peaks at ~1.0 MB of Python allocation (≈1× the input).
No quadratic buffering. The proxy holds one upstream item at a time; it does not accumulate
the session's content.

## Proxy added latency

The proxy's added cost per item is the `enforce()` call above (tens of microseconds for the
untagged ASCII path). When a signing key is configured, each audit-ledger append additionally
Ed25519-signs the entry: ~90 µs/entry (the signer object is built once per ledger, not per
append), so a signed flight recorder adds ~0.1 ms per enforced item on top of `enforce()`.
End-to-end proxy latency is dominated by the upstream MCP round-trip, which the proxy does
not change. In the `approve`/`block` action-gating modes a per-session lock
serializes tool calls to make gating race-free; this adds no measurable latency to a normal
sequential agent flow and only reduces concurrency for operators who opted into strict
gating (a deliberate safety-over-throughput trade). `annotate` (the default) takes a no-op
lock and keeps full concurrency.

## LLM inference / judge cost (opt-in)

The deterministic fast path above is the default. When `--infer` or `--judge on` is enabled,
per-item latency is dominated by the model round-trip (local Ollama: typically hundreds of
ms to seconds depending on model and hardware; a remote free tier depends on the network).
Both features are fail-safe: with no model reachable they fall back to the deterministic
behavior and add no blocking latency. Operators who need throughput should leave inference
off and rely on the structural framing, which is the guarantee regardless.
