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
