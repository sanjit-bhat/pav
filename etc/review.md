# Review of the persistent-merkle branch

2026-08-23. An independent pass over everything on `pers` since `main`
(f726c3a..777b552): the requirements in `etc/`, the code in `merkle/`, the
benches in `etc/bench/`, and the proof tree. The lens throughout is the one
that matters for this project: the code has to be verified quickly, so
simplicity is worth more than any constant factor.

Checked directly this session: all Go tests pass (`merkle`, `ktcore`,
`alicebob`), goose regeneration is clean (`perennial-cli goose` produces no
diff), `crashtest/run.sh` exists and matches worklog §12's table, and the Rocq
proof build was run to its first failure. Not checked: the measurements
themselves (different box; the structural counts' harness logic was read
instead), and the local `~/akd-bench` / `~/tulip` patches, which live outside
this repo.

## 1. Verdict

The design and the Go code are good, and the work log is unusually honest —
it records its own reversals, crash-tests its own claims, and flags its own
measurement artifacts. The library is ~500 lines of new Go, readable in one
sitting, with adversarial tests that cover the one genuinely subtle soundness
point (worklog §1.1).

The one significant gap: **the branch breaks the proof build and does not say
so.** `proof/proof/` was never updated; the manual proofs still spec the old
API, so CI's `proof` job fails. The design doc's framing sentence was "the
simplest thing that meets those needs *while staying verifiable in
Perennial*", and right now the branch is behind `main` on verification —
proofs that compiled there no longer do. Worklog §8 ("what is not done") and
§13 (the requirements table) both omit this. Everything §13 marks "met" is met
in unverified code.

That gap is recoverable, and §4 below argues two small code changes would make
the recovery cheaper. But it is the first thing to fix in the log's own
accounting, and the main cost item the worklog does not price.

## 2. Requirements, checked against the code

Worklog §13's table is accurate as far as it goes. Spot-checks that back its
"met" rows:

- **R1** — `merkle/store.go` is real out-of-core support: `PathKeys` /
  `PathNeeds` / `LoadPath` / `Evict`, with `TestReplicaLoop` exercising the
  whole loop (warm from tape, serve, evict, digest never moves). The resident
  bound (§14: 40x tree growth, 2x heap growth) follows from the code shape.
- **R2/R3** — the §12 correction is right and the crash test is re-runnable.
  The failure it found (mutable node keys make records-then-HEAD unsafe on a
  single-version store) is real, and the fix is in the harness where it
  belongs, since the library does not own storage.
- **R5** — `ApplyUpdate` + `Evict` genuinely replace AKD's blanket flush, and
  the self-check against the old digest means a replica trusts the tape
  publisher, not its store.
- **R8** — the tape is produced inline in `Update`; the auditor consumes it in
  `auditor.go:getNextDig` with no per-insert loop left.

Two amendments to the table:

- **Add a row zero: "stays verifiable in Perennial" — not met.** See §3.
  This is the design doc's own premise, not a new requirement.
- **R6's fork-freedom** is marked as resting on the store's atomic step; note
  that on the recommended topology (§9: Tulip commit + local read stores) the
  contended HEAD write is the only fork defense, and nothing on the branch
  tests two writers. Fine to leave, but it belongs on a what-is-not-done list.

The four untouched protocol requirements (R9, R10, R13, R14) match the design
doc's own §7 split; leaving them out of a storage-layer change was the right
scoping call.

## 3. The verification gap, precisely

What the branch did to the proof tree: `proof/code/` was regenerated twice
("regoose merkle" commits) and `proof/generatedproof/ktcore.v` once.
`proof/proof/` — the 14k lines of manual specs and proofs — has zero commits.

Measured, not inferred: `make proof/merkle_proof/code.vo` in the `pav` opam
switch compiles `theory.v` and `serde.v` cleanly and fails in
`merkle_proof/code.v` at line 600 — inside `wp_put`, at the exact semantic
change this branch made (`put` now errors on a duplicate label instead of
replacing the value). So the pure layer (`is_cut_tree`, `pure_put'`,
`cut_cut_reln`, all of `theory.v`) survives untouched, and the breakage starts
at the wp-spec layer and flows downstream:

| file | lines | state |
|---|---|---|
| `merkle_proof/theory.v` | 1097 | compiles as-is |
| `merkle_proof/code.v` | 1738 | broken: `put`, `find`/`prove` (new `err` return), `Map.Put` (no more `updProof`), `Map.Prove` (4-tuple), old `wp_VerifyUpdate` gone from the code |
| `ktcore_proof/serde.v` | 2253 | broken where it specs `AuditProof` (struct changed) and the deleted `UpdateProof` |
| `auditor_proof/*` | ~2000 | broken: `getNextDig` now calls the batched `VerifyUpdate` |
| `server_proof/server.v` | 1784 | broken: `doWork` calls `Map.Update`, proof still applies `wp_Map_Put` |
| new, unspecified | — | `update.go` (205 lines), `store.go` (301 lines) |

The obligations divide by value:

1. **Repair `code.v` for the changed API** — mostly mechanical: `put`'s
   duplicate branch, threading `err` through `find`/`prove`, shrinking
   `Map.Put`'s postcondition. `find`-errors-on-cut was anticipated by the
   design doc (§3.3 item 2: "`put` already does exactly this ... the spec
   shape exists").
2. **`Map.Update` + `ApplyUpdate`/`VerifyUpdate`** — the security-critical
   piece. Worklog §1.1's attack (a `leaf(label, hash)` tape lets a malicious
   server relocate a committed key) is exactly the class of bug only this
   proof pins down for sure; the prose argument and the tamper test are good
   evidence but the auditor's headline theorem is broken until this exists.
   The wish is one sentence — "there is a tree hashing to `hashOld` such that
   the returned map is that tree plus exactly the batch" — and both sides
   reuse `put`, so the intended proof shape (tape parse relates to
   `is_cut_tree`, then n × `wp_put`) is already in the house style.
3. **`LoadPath`/`Evict`/`Records`/`StoreKey`** — needed only for a verified
   out-of-core *server*, which the branch (correctly) did not attempt. The
   design doc feared the gluing lemma (§3.3, §9.1); the code makes it one node
   deep — `loadPath` grafts a single decoded record under a cut whose hash it
   just checked — so the feared blow-up should not materialize.
4. **Serde/auditor/server re-proofs** — follow the ktcore struct change; the
   new `AuditProof` is flatter than the old one (three slices and a sig), so
   these should shrink.

Items 1–2 restore a compiling, verified system whose auditor accepts the new
proof format. Items 3–4 are the price of ever moving `server/` out of core,
which is separately scoped work (worklog §8, first bullet).

## 4. Two code changes that would make the proofs cheaper

Both are in `update.go`, both shrink specs rather than code, and both are
worth doing *before* writing the specs they simplify.

**4.1 Make `Update` two-pass: serialize, then insert.** The verifier is
already two-pass — `tapeToTree`, then `putAll` — but the prover interleaves:
`update()` (update.go:45) emits tape and mutates in one recursion, calling
`putAll` at the frontier and re-hashing inner nodes on the way up. Proving
that function requires an invariant relating the partially-mutated tree, the
tape prefix emitted so far, and the remaining batch. Split it into a pure pass
that serializes the covering sub-tree (the exact inverse of `tapeToTree`, so
its spec is "parse ∘ serialize = id" against `is_cut_tree`) and a second pass
that is just `putAll` from the root — n applications of the existing `wp_put`,
identical to the verifier's own structure. Cost: one extra in-memory descent
over the covering sub-tree, noise against the measured 123 ms/epoch. The Go
gets slightly simpler too: no error threading through tape emission.

**4.2 Stop reordering the caller's slices.** `Update` documents that it
"reorders both slices in place" (update.go:33), and `server.doWork` then
stores the reordered slices in the `AuditProof`. Soundness doesn't care —
`putAll` is order-independent — but every spec from `Map.Update` through the
serde layer to the auditor must now carry "a permutation of the batch"
through. With 4.1 the insertion pass doesn't need partitioned order at all,
and the serialize pass can partition a private copy of the slice *headers*
(two ~1 MB allocations per 46k epoch, dead at epoch end). Then `Update`'s spec
leaves the caller's slices untouched and the permutation clause disappears
from three packages' worth of statements.

Neither change touches the tape format, the storage keys, or any measured
number.

## 5. Design review: was something better missed?

I looked for a better design and did not find one. Specific checks:

- **Child hashes in the inner record** (the branch's one change to design A)
  is strictly good: the parent record is rewritten whenever a child's hash
  changes anyway, so carrying the hashes costs zero extra writes, halves
  probes per level, and deletes the non-membership second hop. The measured
  1.97x (§11.4) confirms it. AKD not doing this is AKD's loss.
- **The tape** is the right proof format for this protocol: position implied
  by shape (0.70x AKD's bytes), soundness delegated to the `put` both sides
  run, and the verifier's output doubling as the replica cache-warm stream
  (§3) is the kind of reuse that only shows up when the design is actually
  simple.
- **The rejected-alternatives table** (§15.1) holds up. Nibble grouping and
  path compression are correctly priced in verification currency, not just
  bytes. Content addressing correctly dies on "hash keys are not computable".
- **The §9 topology conclusion** (Tulip for the durable commit, a local LSM
  per read replica, warmed by the tape) is the sound reading of §2's
  measurement — ~83k point reads/s cannot feed a 190k-lookup/s replica,
  whatever tree sits on top. Note it is a *recommendation recorded in a log*,
  not a decision anyone has made; it should graduate into
  `persistent-server-design.md` or an ADR, since it reverses the doc's §0
  ("fix on Tulip unless there is a significant performance problem" — there
  is one, and it is measured).

Minor design notes, none blocking:

- `StoreKey` reads bits low-to-high within a byte (store.go:57's comment), so
  within-byte trie order is not lexicographic order. Harmless for the
  clustering claims (those are whole-byte-prefix arguments) and for
  correctness (keys are only ever point-probed), but it would surprise anyone
  adding a range scan by trie prefix later — e.g. for GC. One comment line
  where the bit order is chosen would cover it.
- `decodeNode` accepts an unbounded leaf value (the record's remainder). The
  store is liveness-trusted so this is at worst a memory-pressure vector, but
  a length cap is one line.
- After an `Update` error the map's inner hashes above the failure point are
  stale. Both callers discard on error (`server` asserts, `ApplyUpdate`
  returns nil), so this only needs a sentence in the doc comment — and the
  spec, when written, should surrender `own_Map` on the error path rather
  than promise anything.

## 6. Code-level findings

No correctness bugs found. What was specifically checked:

- **Tape soundness**: a leaf placed at a position inconsistent with its label
  cannot hash to an honest digest (leaf hashes pin the full label; digests
  are trusted inductively from the empty epoch-0 tree). The `leaf`-carries-
  value argument (§1.1) is correct and `TestUpdateTamper` covers it directly,
  along with bit-flips, altered labels/values, and short/repeated batches.
- **Duplicate handling**: repeats within a batch and against the map both
  error (`put`'s exact-match branch), and `doWork`'s version check makes the
  server's `std.Assert(!err)` safe up to VRF collisions — the same trust the
  old `Put` assert carried.
- **Malicious-tape resource bounds**: `tapeToTree` checks depth before
  recursing and consumes at least one byte per frame, so parse is linear and
  stack-bounded.
- **`LoadPath`**: hash-checks every grafted record against the cut it
  replaces, refuses records outside the probed window, and terminates (each
  graft either finishes the path or descends).
- **Empty-batch epoch**: `Update([])` yields a one-cut tape; the auditor
  verifies `hashOld = hashNew`. No special case needed, and none written.

## 7. Smaller items

- **`alicebob` flakes on `main` and gates CI's `go-test` job** (~50% per the
  worklog's own 20-run sample). The diagnosis (1 ms `epochTime`, exact-epoch
  assert, §8) makes the fix a one-liner in a test-only constant. "Not this
  work's to change" is defensible, but a coin-flip CI will tax every future
  branch including the proof-repair one; fix it on `main` first.
- Worklog §6 repeats the "`Map.Update` parallelizes trivially" paragraph
  twice, back to back.
- `ktcore/serde.out.go` regenerated cleanly and the CI serde check passes;
  the deleted `UpdateProof` type left no dead code behind.
- The bench modules each carry their own `go.mod`, keeping Pebble and Tulip
  out of the verified module's dependency tree. Right call.

## 8. Suggested order

1. Decide §4's two changes (two-pass `Update`; no in-place reorder). They are
   small, and they change what gets specified — do them before any spec work.
2. Repair `merkle_proof/code.v` for the changed API, then prove
   `Update`/`ApplyUpdate` and re-prove serde/auditor/server. That restores a
   verified system end-to-end with the batched proof format — the point where
   this branch is unambiguously ahead of `main` rather than trading
   verification for speed.
3. Deflake `alicebob` on `main`.
4. Add the verification row to worklog §13 (or land 2 and mark it met), so
   the log's accounting matches its own standard of honesty.
5. Promote §9's topology recommendation into the design doc, and only then
   scope the out-of-core `server/` work (uid rows, hashchain, `LoadPath`
   specs) against the store it will actually run on.
