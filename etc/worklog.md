# Persistent-server work log

Running log for the work of turning `merkle` into something that meets
`persistent-server-design.md`'s requirements at
`akd-workload-measurements.md`'s workload, at performance comparable to AKD.
Newest entry last. Every number here was measured on the box described in
§0.1 unless it says *(est.)*.

## 0. State of play

Design A is built, in `merkle/update.go` and `merkle/store.go` — about 500
lines, with `merkle/merkle.go` slightly *smaller* than before. It is faster than
AKD on every axis measured except one, and the exception is 9%.

At 1M leaves, epochs of 46k, both against an in-memory store, one thread. Times
are medians of three runs; every count was identical across runs.

| | AKD | \vkt |
|---|---|---|
| insert incl. audit proof | 51.8 us, 23.7 probes | **13.0 us, 7.94 probes** |
| lookup | 29.9 us, 42.2 probes, ~21 round trips | **13.2 us, 25.8 probes, 1 round trip** |
| audit proof | 255 B/insert | **178 B/insert** |
| records written per insert | **7.05** | 7.71 |

AKD here is `~/akd` `main`, and §4 explains why rather than its
`no-key-serialization` branch: that branch removes key serialization from the
storage interface, which is exactly the work a *persistent* store cannot skip.
It is the right baseline for an in-memory ceiling and the wrong one here.

Both microsecond columns are dominated by each system's in-process store, not by
its tree: of \vkt's 13.0 us to insert, **3.0 us is `Update` including the audit
tape** and 10.0 us is the harness store's own lookups and copies.

Against a live 3-replica Tulip, at the measured 46k-per-30 s workload: **8.3 s
per epoch** (7.7–10.5 over five runs), of which the tree is 6 us of 180 us per
insert.

Four things did most of the work, and three of them are simplifications:

1. **One proof per epoch, not per insert** (§1). The tape.
2. **An inner record carries its children's hashes** (§3), so a path fetch is
   one probe per level and answers membership *and* non-membership with the
   proof, in one round trip. This is the change to the doc's design A.
3. **`ApplyUpdate` + `Evict`** (§3), so the audit proof a replica already
   downloads *is* its cache-warming stream.
4. **HEAD written last** (§5), so the atomic step of an epoch commit is one key
   under MVCC — no transaction over the batch, which the doc reserves for
   design B.

Read next: §7 for the scaling and the 10^10 extrapolation, §9 for where the
storage should live, §8 for what is not done.

### 0.1 The box, the toolchains, how to reproduce

A 9-core, 21 GB OrbStack Linux VM (aarch64) on an M1 Pro MacBook Pro with 32 GB.
Everything — both systems, all six Tulip replicas, paxos, and the clients — runs
on it, often at once, so absolute latencies are floors with a lot of contention
in them and the structural counts are the durable part.

Go 1.27.0, Rust 1.98.0, both the latest stable as of 2026-08-22 and both a bump
from what was installed (1.26.4 / 1.96.1). Go 1.27 rejects the empty package
pattern that `packages.Load` passed to `go list`, which is the one source change
the bump needed (`serde/compiler.go`).

```sh
# \vkt. PAV_BENCH_SEED sets the tree size; the store benches seed out of core,
# so the ceiling is the store rather than the 730 B/leaf resident tree.
PAV_BENCH_SEED=1000000 go test -count=1 ./merkle/ -run TestBenchMerk -v -timeout 90m

# AKD: seed, batch, epochs, threads (0 = sequential), use_txn.
# CACHE=1 turns on its TimedCache, AUDIT=1 adds append-only proof generation.
cd ~/akd-bench && AUDIT=1 LOOKUPS=2000 ./target/release/akd-bench 1000000 46000 5 0 1

# Tulip on its own, and the persistent server on Tulip.
cd etc/bench/tulipbench && go build . && ./tulipbench -keys 20000 -probes 64
cd etc/bench/ktbench   && go build . && ./ktbench -seed 1000000 -batch 46000 -warm 16
```

`~/tulip` has one local patch, `keyToGroup` (§2, finding 4). `~/akd` is on
`main` (§4.0). `~/akd-bench` has a counting `Database` wrapper plus lookup and
audit phases added for §4.

Baselines, both at a 1M-leaf tree, single-threaded, no storage:

| | us/insert |
|---|---|
| AKD `batch_insert_nodes`, 46k batches, in-memory db, no cache | 37.9 |
| \vkt `Map.Put`, one at a time, incl. per-insert proof | 5.95 |

AKD's harness is `~/akd-bench` against `AsyncInMemoryDatabase` +
`StorageManager::new_no_cache`, i.e. AKD's in-memory ceiling, on `main` (see
§4.0 for why not the `no-key-serialization` branch). It does *not* produce an
audit proof; \vkt's `Put` does.

## 1. Batched epoch update (commit `ba8c4e6`)

The epoch is the unit of update, so it is now the unit of proof.
`Map.Update(labels, vals)` inserts the whole batch in one descent and returns a
single **tape**: the DFS pre-order (child0 first) serialization of the smallest
sub-tree covering the batch, with everything off it replaced by an opaque cut.
Four instructions — `split`, `empty`, `cut(hash)`, `leaf(label, val)`.

### 1.1 Why there is a fourth instruction, and why it carries the value

Split / cut / empty is not enough. When an inserted label lands where the old
tree already has a *single* leaf, that leaf gets pushed deeper, and **how much
deeper depends on its own label** — the two diverge at their first differing
bit. A cut carrying only a hash cannot say where the leaf ends up, so the
verifier cannot rebuild the new sub-tree. Hence `leaf`. It is not a rare case:
a path terminates at an empty slot or at a leaf roughly equally often, so
`leaf` covers about half the insertions.

Carrying the leaf's **value**, not just its hash, is a soundness requirement
rather than a convenience, and the reason is worth writing down.

A sub-tree holding one leaf hashes to that leaf's hash, at any depth — \vkt
compresses single-leaf sub-trees. So if the tape said `leaf(label, hash)`, the
*old* digest the verifier computes would be that `hash` **whatever label the
tape claimed**. A malicious server could therefore name the wrong label: the old
digest still matches the one the auditor already trusts, but the new tree places
the existing leaf at a position derived from the lie. That silently relocates a
key the server had already committed to, and the auditor signs it.

Shipping the value closes it: the verifier recomputes `H(leafTag, label, val)`
and matches it against the old digest, so collision resistance pins both the
label and the value. The cost is ~65 B on about half the insertions, against
~600 B/insert of cut hashes — under 5%.

The verifier rebuilds the tape into a tree, hashes it for the old digest, runs
**the same `put` the server ran**, and hashes again for the new digest. So the
tape only has to say where the old tree stopped; `put` decides everything else,
on both sides. That is the whole correctness argument, and it reuses the
existing `put`, `is_cut_tree`, and `pure_put'` rather than adding a second
notion of what an update is.

`put` now errors on a duplicate label instead of overwriting it. Every caller
already required freshness (`Map.Put` asserted `!inMap`; the verifiers put into
shells where the label is provably absent), and the batch verifier needs it to
make the update append-only. It also deletes a branch.

Measured, 1M-leaf tree, 46k-insertion epochs, 10 epochs:

| | |
|---|---|
| apply + prove | **2.67 us/insert** (123 ms/epoch) |
| verify | 4.15 us/insert |
| proof | **178 B/insert** |

vs. 6.05 us/insert one-at-a-time. Two thirds of the old cost was generating a
separate ~1.1 KB non-membership proof per insert.

The 178 B is at this tree size, not AKD's. Proof size is dominated by cut
hashes, and cuts per insertion is `~log2(N/B)`: 4.4 here, ~17.7 at
`N = 10^10, B = 46k`, giving ~620 B/insert *(est.)* against AKD's measured
906–1006 B/insert. Same shape, ~35% smaller, because a cut is 32 B of hash
with its position implied by the tape, where AKD ships a 49 B `AzksElement`
with an explicit `NodeLabel`.

## 2. Tulip, measured (§8's first question)

`~/tulip` @ `63e1e4d`, whole deployment in one process, loopback, so these are
protocol floors. Harness: `etc/bench/tulipbench`. 1 group x 3 replicas, 20k
keys preloaded, keys 33 B and values 65 B (a merkle node record).

| | p50 | p99 | per key |
|---|---|---|---|
| read 1 key, 1 read-only txn | 93 us | **403 ms** | 93 us |
| 64-key path, 1 txn, sequential reads | 1.9 ms | 8.3 ms | 30–75 us |
| 64-key path, 64 concurrent txns | **787 us** | **404 ms** | 12–35 us |
| write 1000 keys, 1 txn | 702 us | 6.4 ms | **1.1 us** |

Aggregate read throughput, 64 client goroutines: **~83,000 reads/s**, and it
did not move when sharded to 2 groups (~79k) — this box is CPU-saturated with
replicas, paxos, and clients in one process.

Four findings, in decreasing order of how much they hurt:

1. **Reads are ~90x more expensive than writes, per key.** 93 us against 1.1 us.
   That inverts the assumption behind ruling out design B: paging trades write
   volume for read fan-out, and on *this* substrate that trade is favourable,
   not ruinous. It does not resurrect B on its own — B's 3.2 TB/day is still
   real — but it moves the optimum toward *some* grouping. See §3.
2. **The p99 is a 400 ms cliff**, `params.NS_RESEND_READ`. One lost message and
   the read waits out the resend timer; batch 64 probes and ~1-3% of *batches*
   inherit it. This is a constant, not a design property, but it means "p99 =
   max over 64 probes" is much worse than the doc's phrasing suggests.
3. **No batched read primitive.** `Txn.Read` is one round trip per key and a
   `Txn` is not concurrency-safe, so a path probe is either N sequential round
   trips or N whole txn objects. The concurrent form is ~2.5x better at p50 and
   much worse at p99.
4. **`keyToGroup` is `len(key) % ngroups`**, so every merkle node key — all one
   length by construction — lands in one group. Patched locally in `~/tulip` to
   an FNV-1a of the key. Sharding then works, but did not raise throughput on a
   single box.

Also confirmed from the source, not measured: no version GC, no log compaction,
memory-resident replicas, no range scan.

**Consequence.** At ~83k point reads/s and 12–93 us each, the read path cannot
go through Tulip one merkle node at a time: a lookup wants ~35–56 probes and a
46k-insertion epoch wants ~1.3M. The design pressure is therefore **probes per
operation**, and that is the number to report against AKD, since it is the one
metric that does not depend on whose storage configuration you believe.

*Caveat on every wall-clock number below §2: the first pass of these runs was
taken while the host laptop was throttling. Everything was re-measured with the
host awake; the CPU numbers did not move (\vkt 6.05 -> 6.01 us, AKD 40.1 -> 38.9
us), and the Tulip numbers did. Structural counts — probes, hits, writes, bytes
— are unaffected by any of it, which is the argument for leading with them.*

## 3. Out-of-core maps: design A, and one change to it (commit `25ccadb`)

A node's storage key is its position in the trie: the label prefix it covers
with the deeper bits zeroed, then the depth. Two things follow.

Every node on `label`'s path is a prefix of `label`, so a whole path's keys are
computable before any I/O. That is the doc's design A. Value-major ordering also
clusters the *deep* keys — the key at depth `d` shares `label`'s first `d/8`
bytes — though not the shallow ones, which the doc overstates (§10).

The change: **an inner node's record holds its two children's hashes**, where
AKD's names its children but does not carry their hashes. So the path's records
already contain every sibling hash a proof needs, and the record at the deepest
existing prefix *is* the blocking leaf when there is one. One batch read answers
membership and non-membership alike, with the proof, and **never needs the
second hop §2.1 budgets for**. It also halves the probes, because AKD must fetch
both children at every level.

Unloaded sub-trees are cut nodes, which the tree already had, so this is not a
new data structure. `LoadPath` grafts records in and checks each one's hash
against the cut it replaces, which makes the store **trusted for liveness only**
— the self-verification the doc treats as design B's dividend, for free, because
an inner record's hash is derived from the two hashes it already contains.
`find` errors on a cut instead of panicking, which is what lets an operation say
which record it needs.

Three further pieces, all aimed at probes rather than CPU (commit `87f9d68`):

- `PathNeeds` returns the first cut on a path and the keys from there down, so a
  map that already holds the top of the tree does not re-read it.
- `Evict` / `EvictPath` replace a sub-tree, or one path, with a cut, bounding
  what a map holds without changing its digest.
- `ApplyUpdate` is `VerifyUpdate` keeping the tree it built. Every node the
  epoch changed is in it, so **a replica holding only the epoch's audit proof
  ends up holding the new tree's top, self-checked against the digest.** The
  proof the server already publishes is therefore also the cache-warming stream.
  This is §4.7's replicated-log replica, bounded by an eviction depth instead of
  being a full copy, and it needs nothing new on the wire.

### 3.1 The probe bound is two different numbers

A leaf sits at depth `log2(N) + Geom(1/2)`, so a probe bound of `log2(N) +
slack` leaves a `2^-slack` tail to a second read. Measured at 1M leaves, the two
callers want different slack, because their retries cost different things:

| slack | epoch probes/insert | lookup probes/op |
|---|---|---|
| 1 | **7.73** | 28.14 |
| 2 | 7.94 | 26.38 |
| 3 | 8.71 | **25.85** |
| 4 | 9.64 | 25.94 |
| 6 | 11.63 | 27.26 |

An epoch's retry is one much smaller batch read, so the writer minimizes at 1–2.
A lookup's retry is a whole extra round trip on the critical path, so the reader
minimizes at 3. Guessing 6 cost the writer 46%.

## 4. Against AKD, at the same tree sizes

Both against an in-memory store with no cache, single-threaded, counting
*records* rather than calls (AKD's own `METRIC_BATCH_GET` counts one per call,
which is not comparable). \vkt's harness is `merkle/bench_test.go`; AKD's is
`~/akd-bench`, extended with a counting `Database` wrapper and a lookup and
audit phase.

### 4.0 Which AKD

`~/akd` has a `no-key-serialization` branch (`688fbd1`) that replaces the
`Database` trait's byte-string keys with a typed `IndexKey` enum and a cheap
hasher, dropping a heap `Vec<u8>` and a SipHash per storage operation. It was
built for a different comparison: AKD's **in-memory ceiling**, where the "store"
is an in-process `DashMap` and serializing a key is pure overhead.

It is the wrong baseline for this one. A persistent store is byte-keyed — you
cannot hand a Rust enum to a KV — so producing a byte key per record is work the
persistent path genuinely does, in both systems. \vkt pays it too: `StoreKey`
builds a 34-byte key for every probe, and those bytes are what the harness store
and Tulip are keyed by. So **`main` is the like-for-like baseline**, and the
branch bounds how much of AKD's CPU is attributable to that one interface
choice. Both are in the table in §6.

Structural counts are identical on the two branches, so §7's scaling is
unaffected by the choice.

**N = 1M, epochs of 46k insertions**, medians of three runs, AKD on `main`:

| | AKD | \vkt |
|---|---|---|
| insert, us/op | 37.92 | **12.96** (9.97 store + **2.99 tree**) |
| insert, probes/op | 13.24 | **7.94** |
| insert, hits/op | 13.24 | **5.27** |
| insert, writes/op | **7.05** | 7.71 |
| audit proof, B/insert | 255.0 | **178.4** |
| audit proof, extra probes/insert | 10.41 | **0** |
| audit proof, extra us/insert | 13.88 | **0** |
| membership, us/op | 29.86 | **13.20** |
| membership, probes/op | 42.21 | **25.81** |
| membership, round trips | ~21, dependent | **1** |
| non-membership, probes/op | 45.07 | **0 extra** |

The audit-proof row is the one to look at twice. \vkt's is smaller *and* free:
`Update` emits the tape during the descent it was already making, so it adds no
traversal and no storage read. AKD's `get_append_only_proof` is a second walk
over the tree that re-reads 10.4 records per insertion.

**N = 4M:**

| | AKD | \vkt |
|---|---|---|
| insert, us/op | 73.05 | 4.99 tree |
| insert, probes/op | 18.82 | 9.92 |
| audit proof, B/insert | 341.8 | 238.9 |
| membership, probes/op | 45.67 | 27.83 |
| membership, us/op | 39.56 | 12.20 |

Reading the two together: both scale in `log2(N)`, AKD at ~2 probes per level
and \vkt at ~1, and \vkt's audit proof is ~0.70x AKD's at both sizes. \vkt's
`Update` produces the proof *inline*, during the descent it was already making;
AKD's `get_append_only_proof` is a second traversal that re-reads the tree.

The one column AKD wins is writes/insert, by 9%.

Extrapolating the per-level slopes to the measured deployment size
`N = 10^10` *(est.)*: membership ~40 probes for \vkt against ~68 for AKD;
insert ~24 against ~41; audit proof ~620 B/insert against the 906–1006 B/insert
measured on the live log.

## 5. End to end on Tulip, at the etc/ workload

`etc/bench/ktbench`: the design-A map against a real 3-replica Tulip deployment,
whole thing in one process on the 9-core VM, so the storage layer and the tree
compete for the same cores. 1M-leaf tree, epochs of **46,000** insertions, which
is `akd-workload-measurements.md`'s median epoch.

```
epoch:  180 us/insert (load 123, update+tape 6, write 47)
        7.93 probes  5.24 hits  7.67 writes  165 B tape   |  8.3 s/epoch
lookup: mean 623 us  p50 440 us  p99 1639 us  11.1 probes  7.7 hits
```

**7.7–10.5 s/epoch over five runs, against the measured 30 s cadence**, on a
laptop running the entire storage system in the same process. The tree is 6 us
of the 180; Tulip is the other 174. Which is the point: the merkle work is not the cost, and the
number to optimize is probes.

Warming the map from the epoch tape, then evicting below depth 16, takes a
lookup from 24.1 probes to 10.2, and at the smaller sizes where the noise is
lower, the mean lookup from 1474 us to 460 us.

Two things this harness had to do that are worth recording:

- **Read a whole batch at one timestamp.** `Txn.Read` is one round trip per key
  and a `Txn` is not concurrency-safe, so a path is either N sequential round
  trips or N separate transactions — and N separate transactions is not a
  snapshot. Going at the group coordinators directly (`Attach(ts)` then
  concurrent `Read(ts, key)`) is a read-only transaction at `ts` with no prepare
  and no commit: cheaper *and* the consistency §2.1 actually wants. It needs a
  pool of coordinators, though — one per group serializes the batch on that
  coordinator's lock and condvar, and was 3x slower than a transaction per key
  until pooled.
- **Reserve a timestamp site for reads.** `getTimestamp` rounds to a multiple of
  `N_TXN_SITES` plus the site id, so a reader that uses site 0 collides with
  writer 0 and aborts its transaction. Intermittent, and it looks like a bug in
  the epoch commit rather than in the reader.

### 5.1 One caveat, observed once

One `ktbench` run wedged for 22 minutes with the process at 8% CPU — blocked,
not spinning — and had to be killed. Every other run of the same command
finished in about a minute. Not reproduced, so not diagnosed, but a read that
never returns and never resends is a different failure from the 400 ms cliff in
§2, and worth knowing about before trusting Tulip with a serving path.

## 6. AKD in its best configurations

A self-built baseline of someone else's system invites "you configured it
wrong", so here is AKD in three configurations, same workload, N = 1M, epochs
of 46k. The `insert` column excludes the audit proof; `total` adds it.

| AKD configuration | insert us | audit us | **total us** | probes/insert | lookup us | lookup probes |
|---|---|---|---|---|---|---|
| `main`, no cache, 1 thread (AKD's own bench setting) | 37.92 | 13.88 | **51.8** | 23.7 | 29.86 | 42.21 |
| `main`, **cache on**, 1 thread | 58.36 | 28.19 | **86.6** | **0.4** | 33.98 | 0.33 |
| `main`, no cache, **8 threads** | 17.44 | 4.11 | **21.6** | 23.7 | 31.91 | 42.21 |
| `no-key-serialization`, no cache, 1 thread | 25.64 | 9.04 | 34.7 | 23.7 | 20.01 | 42.21 |
| `no-key-serialization`, no cache, 8 threads | 10.68 | 2.90 | 13.6 | 23.7 | 21.88 | 42.21 |
| \vkt, no cache, 1 thread | 12.96 | 0 | **13.0** | **7.94** | 13.20 | 25.81 |

Two things worth being precise about.

**The cache row is not a deployment.** With no byte limit the `TimedCache` holds
the entire 1M-leaf tree, so probes go to ~0 — but that is R1 turned off. At the
10^10 leaves the audit log implies, a bounded cache over a tree four orders
larger has a low hit rate and you pay for both the misses and the bookkeeping.
And the bookkeeping is not free: turning the cache on *raised* CPU by 54% on
insert and 103% on audit-proof generation. So the two rows bracket AKD rather
than one of them being the fair one, and \vkt is ahead of both.

**The 8-thread rows are AKD's best wall-clock.** On the like-for-like `main`,
21.6 us/insert against \vkt's 13.0 on one core. Strip the storage interface too
and AKD reaches 13.6 us on eight cores, which ties \vkt on one. That last pair
is the cleanest statement of where the design lands: **same wall clock, one
eighth the CPU, a third of the storage operations, a twenty-first of the round
trips — and against an AKD that has been given an interface a persistent
deployment cannot have.** `Map.Update` parallelizes trivially (partition the
batch at the top few levels; the sub-trees are disjoint), but there is no reason
to spend verification budget on it while one core already keeps up. `Map.Update` parallelizes trivially — partition the batch
at the top few levels and the sub-trees are disjoint — but there is no reason
to spend the verification budget on that yet.

Lookups do not parallelize within one lookup in either system, so that column is
like-for-like: 13.2 us and 1 round trip against 30–34 us and ~21 dependent ones,
or 20–22 us with AKD's storage interface replaced.

## 7. Scaling, and what it says about 10^10

Four tree sizes each, same 46k-insertion epochs, no cache, one thread. Every
structural cost in both systems is linear in `log2(N)`, so the slopes
extrapolate.

| N | \vkt memb probes | AKD memb probes | \vkt insert probes | AKD insert probes | \vkt audit B/ins | AKD audit B/ins | \vkt writes/ins | AKD writes/ins |
|---|---|---|---|---|---|---|---|---|
| 1M | 25.81 | 42.21 | 7.95 | 13.24 | 178.5 | 255.0 | 7.72 | 7.05 |
| 2M | 26.79 | 43.89 | 8.94 | 15.97 | 207.3 | 296.6 | 8.67 | 7.97 |
| 4M | 27.83 | 45.67 | 9.92 | 18.82 | 238.9 | 341.8 | 9.63 | 8.93 |
| 8M | 28.77 | 47.64 | 10.93 | 21.71 | 271.4 | 387.5 | 10.63 | 9.90 |
| 16M | 29.83 | — | 11.92 | — | — | — | 11.62 | — |
| **slope, per doubling** | **1.01** | **1.81** | **0.99** | **2.85** | **31.0** | **44.2** | **0.98** | **0.95** |

The slopes are the design, stated numerically. \vkt pays one probe per level
because an inner record carries both child hashes; AKD pays two, and its insert
path pays closer to three. \vkt's audit proof grows by one 32 B cut hash per
level plus a fraction of a byte of opcode; AKD's by one 49 B `AzksElement`.
Write volume is the one place they are the same, and AKD is ~9% ahead. That gap
has a precise cause. Seeding 1M leaves produces **2,441,724 records**, i.e.
1.4417 inner nodes per leaf — `1/ln 2`, the classic figure for an uncompressed
binary trie. `put` materializes one inner node per bit along a shared path,
where a path-compressed trie would collapse each such chain into one node and
have exactly `N-1`. So \vkt stores ~22% more records than it strictly must, and
rewrites ~9% more of them per insert.

Fixing it does not require touching the hash structure — a unary chain is
determined by its endpoints, so one *record* could stand for a chain while the
hashing stays binary, which is §3.4's hash-unit rule again. It is not worth it
here: 0.44 records per leaf, against a record format that stops being "a node"
and a gluing argument that stops being one node deep. Recorded because it is the
one column where AKD is ahead and it is nice to know exactly why.

Extrapolated to `N = 10^10`, the size the depth profile in
`akd-workload-measurements.md` §5 implies, i.e. 10.3 doublings past 8M *(est.)*:

| | AKD | \vkt |
|---|---|---|
| membership, probes | ~66 | **~39** |
| membership, round trips | ~24, dependent | **1** |
| insert, probes | ~51 | **~21** |
| audit proof | **~856 B/insert** | **~590 B/insert** |
| writes/insert | ~20 | ~21 |

**The audit-proof column is a calibration, not just a projection.** The same
extrapolation applied to AKD gives ~856 B/insert, against the **906–1006
B/insert measured directly off the live WhatsApp log** (§3 of the measurements
note). So the method lands within ~10% of ground truth on the one row where
ground truth exists, which is the reason to believe the \vkt row.

At 46k insertions per 30 s epoch and `N = 10^10`: ~950k records written per
epoch, ~66 MB, **~190 GB/day** — against the design note's 392 GB/day estimate
for one record per node, which assumed 150 B records where these are ~70 B.

## 8. What is not done

- **`server/server.go` still holds a resident `*merkle.Map`.** The library can
  now live behind a store, and `etc/bench/ktbench` is a working persistent
  server against Tulip, but the verified server package was left on the in-core
  path. That is §4.3's small-deployment mode, which the design note keeps
  deliberately; moving the *verified* server out of core also means persisting
  the uid rows and the hashchain, which is a protocol-and-proof change rather
  than a merkle one.
- **R9 (marker versions) and R14 (pagination)** are untouched. Both are §7
  protocol changes, on the client and the security proof, not storage.
- **The writer does not keep its map warm across epochs.** It builds a fresh
  `NewCut(dig)`, so `Records` is exactly the changed set with no bookkeeping. A
  warm writer would save the deduped top-of-tree probes — ~28% of its reads at
  `N = 10^10, B = 46k` *(est.)* — at the cost of a dirty bit on every node,
  which the invariant would then have to mention. The writer is not the
  bottleneck (10 s of a 30 s epoch), so this is not the place to spend it.

- **`Map.Update` is single-threaded.** It parallelizes trivially — partition the
  batch at the top few levels and the sub-trees are disjoint — and AKD's 8-thread
  row is the thing to beat if that ever matters. It does not yet: \vkt on one
  core is already 6x AKD on eight.
- **`alicebob`'s end-to-end test is timing-flaky and fails about half the time**,
  which makes `just ci` unreliable. Pre-existing and unrelated to this work:
  9/20 failures on pristine `main`, 11/20 here, and it is no better on an idle
  box than a loaded one. The cause is that `epochTime` is **1 ms**
  (`alicebob.go:19`) while the test sleeps `2 * epochTime` and then *asserts an
  exact epoch number* — 2 ms of slack against Go timer slop in a VM. Raising
  `epochTime` fixes it; left alone because it is not this work's to change.

## 9. Where the storage should live, given the numbers

The goal said to fix on Tulip unless there is a significant performance problem.
There is one, and it is only on the read path. Splitting it out:

**The write path is fine on Tulip.** A 46k-insertion epoch commits in 9.6–12.8 s
against the 30 s cadence, on a laptop running all six replicas, paxos, and the
client in one process. Batched writes are 1.1 us/key. And under MVCC the atomic
step is one key — HEAD, written last — so nothing about the epoch commit needs a
transaction over the batch. That is the requirement Tulip actually earns its
place on (§3.3's "correct operation" theorem).

**The read path is not.** Tulip serves ~83k point reads/s on this box, and a
lookup wants ~16 probes at `N = 10^10` with a map warmed to depth 20. That is
~5k lookups/s per deployment, against R4's target of ~190k/s per replica. Three
orders of magnitude of the gap is the substrate, not the tree: the same lookup
costs **13.2 us of CPU against an in-process store**, and most of that is the
store: proof generation from a resident tree is 2.9 us. Next to `VRF Prove`'s
143.7 us. So served locally,
the tree is ~7% of a lookup, which is exactly R4's "the tree's job is not to add
round trips".

So: **Tulip for the durable epoch commit; a local store per read replica.** That
is §4.7's replicated-log topology, and the two pieces this work adds make it
cheap rather than a new subsystem:

- the epoch tape is already the log entry, already published for auditors,
  already ~600 B/insert, and already self-verifying;
- `ApplyUpdate` turns it into the replica's warm top, and `Evict` bounds what
  the replica keeps, so a replica is not obliged to hold the full 0.3–7 TB copy
  §4.7 assumes. It holds the top and reaches for the rest.

The doc's §4.7 table says a private store costs "hours" to spin up a new
replica. That stands, and it is the real argument against; it is an argument
about bulk loading, not about the steady state.

## 10. What building it reversed

In the design note's own §10 spirit, so the reversals are not mistaken for
oversights. Each is against a claim stated in `persistent-server-design.md` or
`akd-workload-measurements.md`.

- **"AKD's batch-shared encoding is more efficient per update, not less"**
  (measurements §3, comparing AKD's 906–1006 B/insert against \vkt's ~1.1 KB
  per-update non-membership proof). Reversed. That compared a *batched* proof
  against an *unbatched* one. Batching \vkt gives ~590 B/insert at 10^10
  *(est.)*, **0.66x AKD**, because a cut is 32 B of hash with its position
  implied by the tape's shape where an `AzksElement` is 49 B with an explicit
  `NodeLabel`. This was the note's argument for not spending effort here; the
  effort turned out to be one function.

- **"Non-membership needs a second hop"** (design §2.1). No. Put the children's
  hashes in the parent's record and the blocking leaf sits at a prefix of `L`
  like everything else, so one batch read answers both. This also halves the
  probes, since AKD's two-probes-per-level is exactly the cost of *not* doing it.

- **"Immutable-then-CAS ... available only in design B, since it needs immutable
  keys"** (design §2.3). Design A gets the same O(1) atomic step. A reader
  pinning a timestamp does the same work as a key that never changes: write the
  nodes in any order, write HEAD last, and a reader that took HEAD at `ts` sees
  exactly the versions committed by `ts`. No transaction over the batch, and the
  §2.3 "the atomic step is O(B)" caveat goes away.

- **Self-verification is design B's dividend** (design §2.2). Design A has it
  too, for free. An inner record's hash is derived from the two hashes it
  already carries, so checking it against the cut it replaces is one compare.
  The store is trusted for liveness only either way.

- **"~64 probes per path"** (design §2.1, §3.1). Measured: `log2(N) + slack`
  with slack 2–3, so ~36 at 10^10, and ~16 for a replica warmed to depth 20.
  The slack is not a free parameter either — §3.1 shows the writer and the
  reader minimize at different values, and guessing 6 costs the writer 46%.

- **"~300 B/label" of storage** (design §3.1, from ~2N nodes at ~150 B).
  Measured 2.44 records per label at 65–73 B, so **~165 B/label**. The 2.44 is
  itself higher than it needs to be — see §7's `1/ln 2`.

- **"a tuned AKD would also be at 1–3 round trips ... the honest difference is
  probes per lookup"** (design §3.5). The honest difference is probes, and it is
  2x on lookup and ~2.9x on insert, structurally, because of the record format.
  A tuned AKD closes the round trips and not the probes.

- **"Under value-major ordering all 64 probes land in a narrow range near `L`"**
  (design §2.1). Only the deep ones do. The key at depth `d` shares `L`'s first
  `d/8` bytes, so keys below depth `D` fall in a range of relative width
  `2^-8*(D/8)` — tight from depth 24 on — but depth 0 is all zeros and the
  shallow keys are scattered across the keyspace. It happens not to matter,
  because the shallow keys are the top of the tree, which is exactly what a
  warm map holds and does not probe for. Stated as written, though, the claim
  is false.

- **§8's first question, "what does a 64-key `batch_get` cost on Tulip? This
  single number decides A vs. B."** Answered — 12–35 us/key in parallel, ~83k
  reads/s aggregate — but it decides something else. B was already ruled out on
  write volume, and what the number actually says is that **no per-node
  distributed KV can serve the read path**, whichever of A or B is on top of it
  (§9).

## 11. On disk

Everything above puts the tree in memory: the harness store is a Go map, and
Tulip's replicas are `map[string]*tuple.Tuple` with no disk backing (§5 of the
design note says as much). The target stores state to disk, so `etc/bench/
diskbench` runs the same out-of-core map against **Pebble**, an on-disk LSM —
§5.1's "embedded LSM, sorted, block-cached", and the substrate the note predicts
design A wins on. It seeds entirely out of core, in batches, the way a writer
does, and measures lookups from a **cold OS page cache** at a sweep of block
cache sizes.

### 11.1 One fsync per epoch

The epoch commit writes node records with no fsync and then HEAD with one. That
is sound for the reason in §5: nothing reads the records until HEAD names the
digest they add up to, so a crash before the HEAD write leaves records no reader
can reach. **The durability cost of an epoch is therefore one fsync, O(1) in the
batch**, and measurement agrees — 300k-leaf tree, varying the epoch:

| insertions per epoch | us/insert | probes/insert | tape B/insert | s/epoch | **HEAD fsync** |
|---|---|---|---|---|---|
| 1,000 | 81.5 | 12.29 | 291 | 0.08 | **3.66 ms** |
| 20,000 | 41.5 | 7.96 | 150 | 0.83 | **3.98 ms** |
| 100,000 | 32.8 | 5.72 | 89 | 3.28 | **2.56 ms** |

Two things fall out. The fsync is flat across a 100x change in batch size, as
the design says it must be. And **everything else gets cheaper per insertion as
the epoch grows**, because probes, writes, and proof bytes are all `log2(N/B)`
per insertion — the top of the tree is shared across the batch, so a bigger
epoch amortizes more of it. AKD's measured 46k-insertion epochs are near the
knee; the design would rather they were larger.

### 11.2 An epoch, and a lookup, with the tree on disk

5M leaves seeded entirely out of core in 500k batches: **25.8M record writes,
2.6 GB written, 1.9 GB on disk after compaction**, 6m21s. Then the etc/ workload
— epochs of 46,000 — and 2,000 lookups.

| | |
|---|---|
| epoch | **8.8 s** (191 us/insert: 183 load, 5 update+tape, 3 write) |
| | 10.75 probes, 7.50 hits, 9.96 writes, 242 B tape per insert |
| epoch durability | **one fsync, 2.3 ms** |
| lookup, page cache warm | p50 **71 us**, p99 133 us |
| lookup, `MemoryMax=512M` so the 1.9 GB tree cannot be cached | p50 **67 us**, mean 88, p99 346 |
| | 27.00 probes, 24.0 hits, 1.56 KB read |

**8.8 s per epoch against the 30 s cadence, with the tree on a disk.** The tree's
own CPU is 5 us of the 191; the rest is the LSM. And a lookup barely notices
losing the page cache — p50 67 us under a memory limit that can hold a quarter
of the tree, against 71 us with all of it cached. That is the value-major key
doing its job: a path's deep probes land in a handful of blocks, so the working
set per lookup is a few blocks rather than 27 scattered ones.

### 11.3 Key order is worth 21–59%, at identical probe counts

The design note argues for value-major keys against AKD's length-major
`[type][label_len BE][label_val]` and does not measure it. `-lenmajor` moves the
depth to the front of the key and changes nothing else: same tree, same records,
**same 27.00 probes and 24.0 hits per lookup**. Only where the keys land in the
sorted keyspace differs.

| | value-major | length-major | |
|---|---|---|---|
| epoch, us/insert | 191.4 | 233.1 | **+22%** |
| epoch, s | 8.81 | 10.72 | +22% |
| lookup p50, page cache warm | 71 us | 91 us | **+28%** |
| lookup p50, `MemoryMax=512M` | 67 us | 102 us | **+52%** |
| lookup mean, `MemoryMax=512M` | 88 us | 140 us | +59% |
| lookup p99, `MemoryMax=512M` | 346 us | 551 us | +59% |
| on disk | 1.88 GB | 1.98 GB | +6% |

Reproduced across two independent seedings, which agreed to within 2%.

Two things worth taking from this. The claim is **confirmed and it is not small**
— a key layout decision, with the probe count held exactly fixed, is worth a
fifth of the epoch and half the lookup latency. And **the gap widens as the
cache shrinks**: 28% when the tree is fully cached, 52% when it is not, which is
the regime a 10^10-leaf directory is permanently in. Length-major sorts a path's
nodes by depth, so the 27 records of one lookup are spread over 27 regions of
the keyspace; value-major puts the deep ones together.
