# Persistent-server work log

Running log for the work of turning `merkle` into something that meets
`persistent-server-design.md`'s requirements at
`akd-workload-measurements.md`'s workload, at performance comparable to AKD.
Newest entry last. Every number here was measured on the box described in
§0 unless it says *(est.)*.

## 0. The box, and the baselines

aarch64, 9 cores, 21 GB RAM, Linux (OrbStack). Go 1.27.0, Rust 1.98.0 — both
the latest stable as of 2026-08-22, and both a bump from what was installed
(1.26.4 / 1.96.1). Go 1.27 rejects the empty package pattern that
`packages.Load` passed to `go list`, which is the one source change the bump
needed (`serde/compiler.go`).

Baselines, both at a 1M-leaf tree, single-threaded, no storage:

| | us/insert |
|---|---|
| AKD `batch_insert_nodes`, 46k batches, in-memory db, no cache | 40.1 |
| \vkt `Map.Put`, one at a time, incl. per-insert proof | 6.05 |

AKD's harness is `~/akd-bench` against `AsyncInMemoryDatabase` +
`StorageManager::new_no_cache`, i.e. AKD's in-memory ceiling, and it does *not*
produce an audit proof; \vkt's `Put` does. So the 6.6x is if anything
understated.

## 1. Batched epoch update (commit `ba8c4e6`)

The epoch is the unit of update, so it is now the unit of proof.
`Map.Update(labels, vals)` inserts the whole batch in one descent and returns a
single **tape**: the DFS pre-order (child0 first) serialization of the smallest
sub-tree covering the batch, with everything off it replaced by an opaque cut.
Four instructions — `split`, `empty`, `cut(hash)`, `leaf(label, val)`.

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
computable before any I/O, and value-major ordering puts them next to each
other. That is the doc's design A.

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

**N = 1M, epochs of 46k insertions:**

| | AKD | \vkt |
|---|---|---|
| insert, us/op | 38.85 | **3.45** |
| insert, probes/op | 13.24 | **7.95** |
| insert, hits/op | 13.24 | **5.27** |
| insert, writes/op | **7.05** | 7.72 |
| audit proof, B/insert | 255.0 | **178.5** |
| audit proof, extra probes/insert | 10.41 | **0** |
| audit proof, extra us/insert | 12.97 | **0** |
| membership, us/op | 29.23 | **9.00** |
| membership, probes/op | 42.21 | **25.81** |
| membership, round trips | ~21, dependent | **1** |
| non-membership, probes/op | 45.07 | **0 extra** |

**N = 4M:**

| | AKD | \vkt |
|---|---|---|
| insert, us/op | 73.05 | 3.94 |
| insert, probes/op | 18.82 | 13.62 |
| audit proof, B/insert | 341.8 | 238.9 |
| membership, probes/op | 45.67 | 29.24 |
| membership, us/op | 39.56 | 11.76 |

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
epoch:  233 us/insert (load 163, update+tape 6, write 65)
        7.93 probes  5.24 hits  7.67 writes  165 B tape   |  10.7 s/epoch
lookup: mean 680 us  p50 563 us  p99 2158 us  10.24 probes  6.67 hits
```

**10.7–12.8 s/epoch against the measured 30 s cadence**, on a laptop running the
entire storage system in the same process. The tree is 6 us of the 233; Tulip
is the other 227. Which is the point: the merkle work is not the cost, and the
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
| no cache, 1 thread (AKD's own bench setting) | 38.85 | 12.97 | **51.8** | 23.7 | 29.23 | 42.21 |
| **cache on**, 1 thread | 57.47 | 28.67 | **86.1** | **0.4** | 35.57 | 0.33 |
| no cache, **8 threads** | 16.54 | 3.90 | **20.4** | 23.7 | 30.98 | 42.21 |
| \vkt, no cache, 1 thread | 3.45 | 0 | **3.45** | **7.95** | 9.00 | 25.81 |

Two things worth being precise about.

**The cache row is not a deployment.** With no byte limit the `TimedCache` holds
the entire 1M-leaf tree, so probes go to ~0 — but that is R1 turned off. At the
10^10 leaves the audit log implies, a bounded cache over a tree four orders
larger has a low hit rate and you pay for both the misses and the bookkeeping.
And the bookkeeping is not free: turning the cache on *raised* CPU by 48% on
insert and 121% on audit-proof generation. So the two rows bracket AKD rather
than one of them being the fair one, and \vkt is ahead of both.

**The 8-thread row is AKD's best wall-clock**, and the right thing to compare
against a future parallel `Update`. \vkt is 6x faster than it on one core, so
~47x in CPU-seconds. `Map.Update` parallelizes trivially — partition the batch
at the top few levels and the sub-trees are disjoint — but there is no reason
to spend the verification budget on that yet.

Lookups do not parallelize within one lookup in either system, so that column is
like-for-like: 9.00 us and 1 round trip against 29–36 us and ~21 dependent ones.
