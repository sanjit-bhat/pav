# A persistent \vkt server: requirements, and a design ladder

Aug 2026. What does a KT directory server need in order to run at Meta scale,
and what is the *simplest* thing that meets those needs while staying verifiable
in Perennial on top of the existing in-memory \vkt server (`~/pav`) and Tulip
(`mit-pdos/tulip`)?

Citations are `file:line` into `~/akd` (f14dcfa), `~/pav` (602b9f2),
`~/akd-bench`, and `sec27/data/*` for measured numbers. **[V]** = checked
against the primary source this session. Numbers I derive are *(est.)*.
§10 lists the things this draft reverses relative to earlier ones.

> **Design A was subsequently built and measured. See `worklog.md`** — its §0
> for what it costs against AKD, and its §10 for the seven claims below that
> building it reversed, including the second hop in §2.1, the O(B) atomic step
> in §2.3, and the "do not bother shrinking the append-only proof" conclusion.

---

## 0. Recommendation

**Build design A. Design B is ruled out by measurement (§1.5).**

**A — label-addressed nodes with a batched prefix probe (§2.1).** Keep AKD's
one-node-per-record layout, but key each node `[label_val][label_len]` and fetch
a whole Merkle path with a *single* `batch_get` over the ~64 prefixes of the
target label, which are computable before any I/O. Read at the epoch's timestamp
so the path is consistent. This is ~50 lines on top of the existing Merkle code,
adds no data structure, and costs 1–3 round trips per operation.

**B — paged, content-addressed pages (§2.2).** Cut the tree into pages, key each
page by its own hash, keep every internal page resident, and turn the 64 probes
into 1. It buys a 64x reduction in per-lookup request fan-out and costs a page
format, a resident index, a refresh path, and a GC job. **Kept for the record but
not recommended**: at the measured 46k insertions per 30 s epoch it rewrites
~1.13 GB per epoch, 3.2 TB/day, ~8x one-record-per-node (§1.5). Paging trades
write volume for read fan-out, and this workload cannot afford the trade. It
would become viable again only at a far lower update rate or a far larger epoch.

Both share one epoch-commit invariant (§2.3), one story for which epoch a replica
serves (§2.4), and one rule about client-controlled work (§2.5).

**Where the storage lives: Tulip for the durable epoch commit, a local store per
read replica.** This reverses fixing on Tulip throughout, and measurement decided
it rather than preference (worklog §9). Tulip's write path is fine — a
46k-insertion epoch commits in 9.6–12.8 s against a 30 s cadence, and under MVCC
the atomic step is one key, so nothing about the commit needs a transaction over
the batch. Its read path is not: ~83k point reads/s, against a lookup that wants
~16 probes at 10^10 leaves, is ~5k lookups/s per deployment against R4's ~190k.
That gap is the substrate and not the tree — the same lookup costs 13.2 us of CPU
against an in-process store, of which proof generation is 2.9 us, next to `VRF
Prove`'s 143.7 us. So this is §4.7's replicated-log topology, and design A makes
it cheap rather than a new subsystem: the epoch tape is already the log entry
(published for auditors, self-verifying, ~600 B/insert), and `ApplyUpdate` +
`Evict` turn it into the replica's warm top, so a replica holds the top of the
tree and reaches for the rest instead of the full 0.3–7 TB copy §4.7 assumes.
§4.7's objection stands unchanged: a *new* replica is bulk loading, and that is
hours.

Four changes worth making that are **not** storage changes (§7): log-spaced
back-pointers over epoch digests, marker versions, freshness measured against the
auditor rather than a clock, and paginating every client-sized reply.

The thing this draft said to measure first — what a 64-key `batch_get` costs on
Tulip (§8) — was measured: 93 us per read, no batch primitive, and that is where
the read-path conclusion above comes from (worklog §2).

---

## 1. Requirements

AKD's public repo is a library plus a MySQL reference backend
(`examples/src/mysql_demo/`); WhatsApp runs it against an internal store and
publishes audit blobs to CloudFront
(`examples/src/whatsapp_kt_auditor/mod.rs:22`). Nearly every non-obvious
mechanism in that library is a concession to one of the requirements below, so
the code reads as a requirements document.

**R1. Out-of-core tree.** The tree lives behind a `Database` trait with
`get`/`batch_get`/`set`/`batch_set` (`akd/src/storage/mod.rs:93`), never as a
resident object. Three record types: `Azks` (the root pointer), `TreeNode`,
`ValueState` (`storage/types.rs:19`). Scale: \vkt measures 730 B/key resident
(`data/serv-mem.txt`, 345M keys -> 251 GB), so 3B users at a few key versions
each is ~10^10 labels ~ 7 TB — an order of magnitude past one machine *(est.)*.

**R2. Crash-atomic epoch publication.** A reader must never see an epoch number
whose nodes are not all present. AKD encodes this as commit *order*:
`transaction_priority` puts `Azks` last, "so that any concurrent storage readers
will not see an increase in the current epoch until every other record for the
new epoch has been written" (`storage/types.rs:203`), inside one storage
transaction with rollback (`directory.rs:216-259`), which MySQL maps to one
`START TRANSACTION` (`mysql.rs:674-716`).

**R3. No torn reads against a publish in flight.** Nodes are keyed by label with
no epoch (`tree_node.rs:109`), so a publish mutates rows readers are using. AKD's
fix is two versions per row, `TreeNodeWithPreviousValue` (`tree_node.rs:81`),
resolved by target epoch (`:137`). It is a *one-epoch* window: two epochs ahead
and the read fails `NotFound` (`:144-154`). At the measured 30 s cadence (§1.5)
that is a ~1 minute tolerance — generous, not fragile, which is a correction to
what I first claimed on the strength of `server.go:127`'s "~1 second".

**R4. Read throughput, and it is proof-generation bound.** Every message send is
a lookup. AKD spends its effort here: a TTL+bytes node cache
(`cache/high_parallelism.rs`, 30 s default, `cache/mod.rs:18`), path preloading
(`append_only_zks.rs:653`), a greedier variant behind a feature flag (`:607`),
multicore fan-out sized from `available_parallelism` (`:205-269`), and batched
lookups (`directory.rs:373`). Cost model, measured: VRF Prove 143.7 us against
Merkle Prove 1.707 us (`figs/merkle-vrf.tex`). So a lookup is ~290 us of VRF and
~3 us of tree work: **the tree's job is not to add round trips**, and read
scaling is CPU scaling.

**R5. Cache coherence across epochs.** Because node keys carry no version, a
cached node can silently go stale, so AKD polls `Azks` and on any epoch change
**flushes the whole cache** under a lock that also blocks proof generation
(`directory.rs:630-684`, `:37`). At the measured 30 s cadence (§1.5) this is far
less severe than I first said — and the cache's own 30 s item lifetime
(`cache/mod.rs:18`) expires entries at about the same rate anyway, so the flush
is close to a no-op. The criticism that survives is structural, not quantitative:
keys carrying no version is *why* a blanket flush is the only safe move.

**R6. Writes batched into epochs; one writer.** `publish` takes a vector, dedups
labels, produces one epoch (`directory.rs:104`); \vkt drains a work queue on a
timer (`server.go:158`). Read replicas are a separate type over the same storage
(`ReadOnlyDirectory`, `directory.rs:851`). Nothing *enforces* single-writer:
two publishers both read epoch `e` and write `e+1` (`directory.rs:121`), which is
a fork — a security failure, not a liveness one.

**R7. Bulk read APIs.** `get_user_state_versions` resolves a slice of usernames
in one query via a temp table (`storage/mod.rs:124`, `mysql.rs:1038`), because
publish needs every user's current version before it can pick labels
(`directory.rs:138`).

**R8. Audit proofs are bulk, immutable, out-of-band.** `get_append_only_proof`
walks the tree per epoch transition (`append_only_zks.rs:881-940`), chunked into
blobs named `epoch/prev_hash/curr_hash` (`local_auditing.rs:58-137`), served from
a CDN, not from the serving path.

**R9. History proofs bounded independent of version count.** `key_history`
returns the requested range plus *marker versions* — powers of two and the
skiplist `[1,2,4,16,256,2^16,2^32]` (`directory.rs:528`,
`akd_core/src/utils.rs:13-98`). \vkt is in the Theta(k) regime instead:
`Client.Get` calls `getHistory(uid, 0)` (`client/client.go:58`) and the server
proves every version (`server.go:196`).

**R10. Plaintext deletion without touching the tree.**
`tombstone_value_states` overwrites stored values with a `TOMBSTONE`
(`storage/manager/mod.rs:428`) while the tree keeps the commitment. The tree is
append-only forever.

**R11. Operational plumbing.** Connection-pool health checks and background
refresh, 300 s tier timeouts, tunable multi-row insert depth
(`mysql.rs:37,62,117,213`), per-operation counters and timers
(`storage/manager/mod.rs:40-166`), pluggable VRF key storage. Not architectural,
but it says the storage layer is the thing that pages, so it must be observable.

**R12. Not visible in the code; I would add these.**
- *Writer failover that cannot fork.* R6's gap. Signing epoch `e` twice with
  different content is precisely the misbehavior clients are built to detect.
- *Signing only after durability.* Sign, crash, recover with a different batch
  for the same epoch, and the server has forked itself.
- *Geo-distributed reads*, which means tolerating replica staleness — forbidden
  today by R3.
- *A tunable reader-staleness window.* Not for historical proofs; see §2.3.
- *Bulk backfill*, a different profile from steady state.
- *Bounded, explicit RAM*, not "a TTL cache and hope".

**R13. Monotonic reads per client session.** Created by the multi-replica
requirement itself. `Client` carries `lastEp` and sends it as `prevEpoch`
(`client/client.go:31,187`); the server errors if `prevEpoch >= numEps`
(`server.go:78`) and `CallHistory` turns that into `BlameServFull`
(`rpc.go:88`). With one server a client's epoch cannot regress, so this never
fires; with N replicas at different epochs it fires whenever a client moves from
a fresher replica to a staler one, and an honest lagging replica is
indistinguishable from a faulty one. Equal epochs are fine (`extLen = 0`, and
`getNextEp` reuses the client's own digest, `client/client.go:216-235`); only
*behind* is fatal.

**R14. No client-supplied parameter may control server work.** `prevEpoch` and
`prevVerLen` are untrusted and today size the reply directly. `Audit(0)` returns
`audits[1:]` — every update proof ever published (`server.go:102`).
`History(uid, 0, 0)` returns `chain.Prove(1)`, a `bytes.Clone` of every digest in
history (`hashchain.go:31`), plus one membership proof per version. Both are
survivable as slice copies from RAM and become storage traffic once persistent.
What makes this tractable: **erroring a lying client costs nothing**, because a
client's `BlameServFull` is its own local conclusion and is not transferable —
only `Evid`, two conflicting signatures, is evidence anyone else acts on
(`ktcore/evidence.go:11`). The goal is "never error an *honest* client".

---

## 1.5 Measured deployment parameters

Full measurements, method, and the decoded blobs are in
**`akd-workload-measurements.md`** (all **[V]**, 2026-08-20, against the live
log). The parameters this note consumes:

| | measured |
|---|---|
| epoch cadence | **30 s** (p99 60 s; ~1% of ticks slip and catch up at ~2 s) |
| insertions per epoch | **~46,000** median; 31k–64k over the diurnal cycle; 225k at the observed peak |
| tree size | ~10^10 leaves, from the depth profile |
| audit proof | 44 MB median per epoch; 109 GB/day; ~1 KB per insertion, near-optimal |
| label distribution | uniform within ±3% |
| top of tree | every node above depth ~17 is rewritten **every epoch** |

Two of these overturn earlier drafts of this note. The cadence is 30 s rather
than the "~1 second" in `server/server.go:127`, which deflates the R3 and R5
criticisms and demotes §7.1. And `B ≈ 46k` rather than the ~1,000 I assumed,
which **rules out design B** (§2.2) on write volume: 3.2 TB/day of page rewrites
against 392 GB/day for one record per node.

---

## 2. The design ladder

### 2.0 The invariant both designs share

> The durable state is a pure function of the committed epoch sequence; every
> mutation is one atomic step that advances the epoch pointer; and nothing
> derived from an uncommitted epoch may leave the writer.

Everything below is a consequence. The last clause is R12's sign-after-durable:
the signature lives inside the epoch record and is only ever served by reading it
back.

### 2.1 Design A: label-addressed nodes, batched prefix probe

Keep one record per Merkle node, as AKD does. Three changes.

**Key each node by the prefix it represents, value-major.** AKD already keys by
`NodeLabel { label_val, label_len }` (`tree_node.rs:109`) but serializes it
`[type][label_len BE][label_val]`, which sorts by *length* first and scatters one
label's prefixes across the keyspace. Use `[label_val][label_len]` instead.

**Fetch a path in one round trip.** Every node on the path to label `L` is a
prefix of `L`, so all candidate keys are computable from `L` before any I/O:
prefix of length `i` for `i` in `0..D_max`, and with uniform labels
`D_max ~ 2*log2 N`, so ~64 probes. One `batch_get` returns the ~30 that exist.
No walking, no index, no page format. Under value-major ordering all 64 probes
land in a narrow range near `L`, so a sorted engine serves them from a handful of
blocks — **that is paging, done by the storage engine rather than by us.**

Non-membership needs a second hop: the blocking leaf's key is its own full
label, not a prefix of `L`, but the deepest existing ancestor records its
children's labels (`left_child`/`right_child`, `tree_node.rs:241`), so one extra
fetch gets it. Membership is 1 round trip, non-membership 2, and a \vkt Get needs
both, so 2–3 in total, and the two probes are independent so they overlap.

**Get consistency from MVCC, not from a data-model hack.** Read every probe at
the epoch's timestamp. Tulip supports exactly this: `tuple.ReadVersion(ts)`
returns the newest version at or before `ts` over a version list that is never
truncated, and a slow-path read makes the replica promise not to accept
conflicting prepares in the interval **[V]**. So R3 needs no `previous_node`, no
write-ordering rule, and imposes no one-epoch reader window.

What this costs: ~64 key probes per path. On a sharded store where each key is a
request and a quorum read, that is 64x the request fan-out of design B and sets
p99 at the max over 64 requests. Whether that matters is an empirical question,
and it is the escalation trigger.

### 2.2 Design B: paged, content-addressed pages

Only if A's fan-out is what hurts. One sentence: **keep an index in RAM to turn
those 64 probes into 1.**

Cut the tree into *pages*, each a horizontal band of the trie. An internal page
holds its children's hashes; a leaf page holds the `(label, val)` entries under
its prefix. Store each page under a key containing **its own hash**, and never
modify it: an epoch that inserts B labels writes new pages along B paths, and
pages whose contents did not change keep their hash and are shared across epochs
for free. Keep every internal page resident, so finding a leaf page is
pointer-following in RAM and only the last hop is I/O.

`merkle.go` already has the node type for a page boundary — a cut node
(`merkle/merkle.go:25`) — and the Rocq theory is built around it: `is_cut_tree`,
`is_cutless_path`, `cut_cut_reln` (`merkle_proof/theory.v:295,322,371`), with
`pure_put'`/`find'`/`to_map'` already depth-parametric (`:613,52,84`) **[V]**.

Two page-format details, and they pull in opposite directions:

- *Internal pages: derive the inner hashes.* They are resident and refreshed by
  replay, so derivation happens once at cold start.
- *Leaf pages: store them.* Their inner hashes are on the critical path of every
  Get. Deriving costs `~2k` hashes per page load — ~77 us at `k = 128` against
  ~290 us of VRF — whereas stored hashes turn a load into a parse plus a gather
  of the `~log k` siblings actually needed, ~2 us. Price: 2x leaf bytes and 2x
  leaf write amplification, the right trade when CPU is the bottleneck.

Self-verification falls out: a page's hash is checked against the key it was
fetched under, so the store is untrusted for integrity. That is a dividend of
content addressing, not a reason for it — the reasons are that entries never
expire (§4.1) and that the parent's cut hash is the pointer, so no version index
is needed. Checking costs nothing extra, since the root hash must be computed to
build the tree and the key *is* that hash. What it buys is that an in-process
cache, a memcache tier, or a CDN in front of the store needs no proof of its own.

**GC is mandatory here**, and the mechanism to copy is Jellyfish Merkle's
stale-node index (§6): when epoch `e+1` supersedes page `P`, append
`(e+1, P_key)` at write time; pruning through `X` is "delete every entry with
`stale_since <= X`". No derivation from manifests, no walking.

### 2.3 Epoch commit, shared by A and B

The writer drains its work queue on the epoch timer as today
(`server.go:158`), then:

1. Read what the batch touches — leaf pages or path nodes, plus the `uid` rows
   for the batch. All keys are computable up front, so one concurrent round trip.
   (This is R7's bulk read, falling out of the key structure rather than needing
   a temp-table query.)
2. Apply the batch in memory, collecting the `updProof`s `merkle.Map.Put`
   already returns; produce the new digest, link, and signature.
3. Commit. Two shapes:
   - **Transaction:** one txn over `{read HEAD as a fence, write the new nodes or
     pages, write the B uid rows, write the epoch record, write HEAD}`. Simple,
     and it is what I would use with Tulip. The atomic step is O(B).
   - **Immutable-then-CAS:** write the new pages first (unreachable until
     published, so unordered and non-transactional), then CAS `HEAD`. The atomic
     step is O(1) in batch size, which bounds commit latency and the number of
     Paxos groups involved regardless of B. Available only in design B, since it
     needs immutable keys.

Either way:

- **Crash safety is one sentence.** The durable state is a function of the
  committed epoch; a crash before the commit leaves either nothing or unreachable
  garbage. No WAL of our own, no write-ordering discipline (R2), no
  previous-value trick (R3), and no recovery path distinct from startup.
- **Writer failover cannot fork.** Both writers contend on `HEAD`; one loses and
  leaves no trace. No lease, no leader election, no fencing token — and the
  failure mode of a store with a broken CAS is two signed links for one epoch,
  which is detectable server misbehavior the blame framework already covers.
- **Retention is a GC window sized in seconds, not history.** Nothing in the
  protocol ever wants a Merkle proof against a past digest: clients get
  memberships against the *latest* digest (`server.go:87-89`, checked against
  `nextEp.dig` at `client/client.go:201`), continuity comes from the hashchain,
  auditors replay stored `UpdateProof`s rather than walking an old tree, and
  `Evid` is two conflicting signatures with no Merkle proof in it
  (`ktcore/evidence.go:16`). AKD is the same — `key_history` proves against the
  current root, which is *why* latest+previous suffices for it. So the window
  exists only so that a reader mid-request still finds what it is reading. The
  difference from AKD is that ours is a tunable parameter and theirs is a fixed
  one-epoch window that errors when exceeded (R3).

### 2.4 Which epoch a replica serves

Every replica always serves the current epoch, from a short-lived `HEAD` cache.
No pinning, no routing, and nothing about staleness is visible at the interface.
Four layers, all below it:

1. **A free arithmetic pre-filter.** Epochs are rate-limited by construction:
   `getWork` waits `epochTime` before each commit (`server.go:160`), so the
   writer advances at most one epoch per `epochTime`. A replica that learned
   epoch `e_r` at `t_r` knows the true current epoch is at most
   `e_r + (now - t_r)/epochTime` plus clock slack. Above that bound the client is
   provably lying; reject with zero storage access. An honest client cannot
   exceed it, since its `prevEpoch` came from a signed record.
2. **Coalesced refresh, then a bounded wait.** Refresh `HEAD` on a timer
   (`epochTime/4`) and on demand, with on-demand refreshes single-flighted into
   at most one in-flight read shared by all waiters — so cost is O(1) reads/sec
   per replica regardless of request rate. If `prevEpoch` is plausible but ahead,
   wait for that refresh rather than answering. Honest waits are milliseconds and
   happen only at epoch boundaries; cap the wait and the waiter count.
3. **Still cannot serve: fail at the transport layer, do not reply.** No protocol
   change needed, because the two cases already have separate channels — a failed
   `c.Call` yields `BlameUnknown`, documented as "the equivalent of throwing up
   your hands" (`ktcore/blame.go:19`), while a reply with `Err: true` yields
   `BlameServFull` (`rpc.go:83-96`). `Server.History` currently conflates them,
   returning `Err` both for nonsense arguments and for being behind
   (`server.go:78`). Nonsense arguments *should* set `Err`. Being behind should
   simply not answer.
4. **Persistently behind: fail the health check** and leave the pool. That is
   where the staleness fence belongs — ops plumbing, not a reply.

**Do not add a signed timestamp.** CT-style *promises* ("included within the
MMD") are liveness commitments needing a timing model, i.e. verifying
performance. And even a plain assertion — "at time T my tree was this", as in a
tlog checkpoint — buys nothing against a malicious signer, who signs whatever `T`
it likes. It detects only an honest lagging replica, and for that case a replica
comparing itself to `HEAD` is strictly better, because `HEAD` is ground truth
while a client's clock comparison folds in skew and network delay. Freshness
decomposes with no clock anywhere:

| property | mechanism | in the theorem? |
|---|---|---|
| the key is what the tree said at epoch `e` | Merkle proof | yes, epoch-relative |
| never regress below what this client saw | `prevEpoch` + client check | yes, epoch-relative |
| an honest replica is not far behind | replica compares itself to `HEAD` | no — ops |
| a *malicious* server is not serving something old | compare against an independent party: the auditor's latest epoch | yes, party-relative |

The last row is the answer for the adversarial case, and \vkt nearly has it:
`Client.Audit` already fetches the auditor's link for the client's own epoch
(`client/client.go:107`). Requiring the auditor's *latest* epoch to be within X
of the client's is a party-to-party comparison needing no clock model. General
rule: **prefer comparisons between two values the system itself produces over
comparisons against wall-clock time.**

### 2.5 Bounded work per request

R14, discharged: paginate every reply whose size a client can name, and coalesce
every on-demand refresh. `Audit` and `History` both need a server-chosen cap with
a continuation, which is a protocol change (§7.4).

---

## 3. Numbers

### 3.1 Design A: probe fan-out

Per path: ~`2*log2 N` probes ~ 64 at 10^9 labels, of which ~30 hit, returning
~150 B each ~ 4.5 KB. Per Get (membership + non-membership): 2–3 round trips,
~128 probes, ~9 KB. Storage per label: one node per label plus internal nodes,
~2N nodes x ~150 B ~ 300 B/label, so ~300 GB at 10^9 *(est.)*. Resident: nothing
required.

### 3.2 Design B: the resident-index derivation

Let `N` = labels, `k` = labels per leaf page, `b` = band width; labels and values
are 32 B. Cut depth `D` is set by `2^D = N/k`.

- Leaf pages: `N/k` of them, `~64k` bytes each (`~128k` with stored inner
  hashes). Total leaf storage `~ 64N`, independent of `k` — 64 GB per 10^9.
- **The bottom internal level holds exactly one 32-B hash per leaf page.** It is
  a pointer array: `32N/k` bytes.
- Levels above are geometrically smaller — `32N/(k*2^b)`, then `32N/(k*2^{2b})`,
  summing to a `1/(1-2^{-b})` factor. Negligible.
- Derived inner hashes in internal pages double it.

So **resident ~ 64*N/k**, i.e.

> resident RAM ~ 4 KB x N / leaf_page_size

A hyperbola: pick the page size, read off the RAM. Note that `b` dropped out — it
appears only in a negligible correction, so **`D` (equivalently `k`, equivalently
page size) is the only real knob**; `b` decides how the index is chunked and how
many in-RAM hops a walk takes, both free. Bands need not be uniform.

| | N = 10^9 | N = 10^10 |
|---|---|---|
| target leaf page | 8 KB (`k` = 128) | 8 KB (`k` = 128) |
| leaf pages | 7.8*10^6 | 6.7*10^7 |
| **resident index** | **0.5 GB** | **4.3 GB** |
| internal levels (bands 8,8,7 / 8,8,8,2) | 3 | 4 |
| leaf storage | 64 GB | 640 GB |
| round trips per label read | 1 | 1 |
| key probes per label read | 1 | 1 |

Two things make this work, both properties of the *labels*. They are VRF outputs,
so leaf pages hold `k +/- O(sqrt k)` entries — no skew, no hot page, and fixed
bands are safe. And the index is a *pointer array*, not a tree of objects:
\vkt's pointer-based `node` layout costs 730 B/key resident
(`data/serv-mem.txt`) against 64 B of hash content, so **the resident index must
be packed bytes** or these numbers are off by 5–10x. Pleasant consequence: since
a proof *is* a packed list of sibling hashes and `newShell` already builds a
transient path-tree from exactly that (`merkle/merkle.go:284`), proof generation
is a **gather from the index**, not a tree walk; the pointer tree materializes
only along the one path being proved.

Write side, at the measured `B ~ 46,000` per 30 s epoch (§1.5): distinct pages
touched is `1 + 256 + min(B, 65536) + B + B ~ 138k`, so **~1.13 GB/epoch,
3.2 TB/day** — against ~912k nodes ~ 137 MB/epoch, 392 GB/day for one record per
node. That 8x is what rules the design out, and it is worth being explicit that
the sizing above is otherwise sound: the resident index really is 0.5–4.3 GB and
reads really are one probe. Paging fails on the write side, not the read side.

Writer CPU: `Map.Put` 8.6 us, Prove 1.7 us (`data/merkle.txt`); an insert
rewrites one leaf page and `D` path hashes above it, so ~150 us/insert including
the VRF eval *(est.)* -> ~6.6 k inserts/s single-threaded, VRF part
parallelizable. **One writer is enough** (§4.4).

Per-replica Get throughput is VRF-bound either way: ~3.4 k/s/core -> ~190 k/s on
56 threads, scaling linearly in replicas.

### 3.3 Verification scope

Design A is almost entirely reuse: the tree code and its proofs are untouched,
and the new obligations are the key encoding, the probe-set construction ("every
node on `L`'s path is a prefix of `L`", a statement about the existing `find'`),
and the epoch commit.

Design B adds:

1. **Depth-generic entry points.** `Map.Put`/`Map.Prove` hardcode depth 0
   (`merkle.go:62,123`) and `wp_put` is stated at `#(W64 0)`
   (`merkle_proof/code.v:521`), but `pure_put'`/`find'`/`to_map'` already carry
   depth. Re-state at arbitrary depth.
2. **`find` returns an error on a cut** instead of panicking (`merkle.go:196`).
   `put` already does exactly this, with the genie `not is_cutless_path t label`
   (`code.v:521-545`), so the spec shape exists — and it is what makes paging
   demand-driven: the operation tells you which page it needs.
3. **`own_PagedMap ptr m hash (store : gmap hash page)`**: a resident
   tree-with-cuts plus the invariant that gluing pages under the cuts yields a
   cutless `t` with `to_map t = m` and `is_cut_tree t hash`. The one real lemma is
   **gluing** — composition of `is_cut_tree` and of `to_map'` under a prefix;
   `cut_cut_reln` (`theory.v:371`) is its determinism half.
4. **`pagestore`**: `get(prefix, h)` returns *some* bytes and we rehash, so the
   store is trusted only for liveness; plus one atomic `HEAD` step.

Two theorems, with different dependencies, and it is worth being explicit:
**security** (clients never accept inconsistent keys) does not mention the
storage layer — pages self-verify, epoch records are signed, and a misbehaving
store can at worst fork or roll back, both of which the blame framework already
handles. **Correct operation** (an honest server serves valid proofs and is never
blamed) does need the store's atomicity and availability. That is the theorem
Tulip earns its place in.

### 3.4 What proof cost decided, and what it did not

If re-proving were free, almost nothing above would move. Immutability, the
atomic step, paging, one writer, and the transaction-vs-CAS call were all decided
by round trips, RAM, and crash/fork safety.

The **hash structure** was kept for reuse, and survives re-examination. Two
things it would be tempting to co-design and should not be:

- *Arity.* Binary nodes minimize proof bytes (~30 sibling hashes ~ 1 KB); 16-ary
  would cut depth to ~8 but inflate the proof to ~120 hashes. Depth was the
  reason to want higher arity, and both designs already solve depth — so they are
  what let us keep the proof-optimal arity.
- *Hash unit vs. storage unit.* Hashing a page as one blob would make proofs
  consist of pages, ~32 KB instead of ~1 KB. Keeping the binary structure inside
  a page and deriving it is what keeps the client's proof small. **These units
  should stay different**, and §6 shows what happens to a system that conflates
  them.

What *would* change is all client protocol, which is §7's list. So: the storage
layer's shape is set by physics; the protocol's shape was set by what was cheap
to prove. That is where a free re-proof budget goes.

One formulation I would keep even so: defining the invariant by gluing pages into
a single `tree` and reusing `is_cut_tree`/`to_map`, rather than defining
`is_paged_map` directly over the page DAG. The direct version is the more honest
model and avoids a 10^9-leaf object in the logic, but the client's verification
(`VerifyMemb` and friends) is already stated over `tree`, so gluing connects
server state to client spec without a bridge.

### 3.5 Do these match AKD?

Check the baseline first: **AKD's published numbers are its in-memory ceiling.**
The benchmark runs against `AsyncInMemoryDatabase` with
`StorageManager::new_no_cache` (`~/akd-bench/src/main.rs:56`) **[V]**, so Put
164 us and Prove 34.14 us (`figs/merkle-akd.tex`) include *zero* storage I/O.

**Throughput: comparable, and better than AKD as written.** All three designs are
dominated by the same two terms, crypto and round trips. Per Get we pay ~290 us
of VRF, ~2 us of tree work, and 1–3 round trips; AKD as implemented pays 34 us
and 10–15, because `recursive_preload_nodes` descends level by level
(`append_only_zks.rs:718`), parallelizing across a batch of lookups but never
within one. That is an implementation choice, not a structural one — the same
prefix-probe trick applies to AKD, so a tuned AKD would also be at 1–3 round
trips. Against *that*, the honest difference is probes per lookup.

**Latency: worse than in-memory \vkt by the round trips**, ~0.3–1 ms on top of
today's 787 us end-to-end Get (`data/cli.txt`). Inherent to R1.

| metric | AKD as written | AKD tuned | A | B |
|---|---|---|---|---|
| round trips / lookup | 10–15 | 1–3 | 1–3 | 1 |
| key probes / lookup | 10–15 | ~64–128 | ~64–128 | 1–2 |
| bytes / lookup | ~2 KB | ~4.5 KB | ~4.5 KB | 4–16 KB |
| bytes / insert | ~4.5 KB | ~4.5 KB | ~4.5 KB | 16–40 KB |
| required RAM | none (cache discarded each epoch) | none | none | 0.5–4.3 GB |
| p99 | epoch-boundary flush stall | max over 64 probes | max over 64 probes | single read |
| CPU / proof | 34 us | 34 us | ~2 us | ~2 us |

Two notes on making a comparison credible. A self-built baseline of someone
else's system invites "you configured it wrong", so lead with the
**config-independent structural metric**: storage operations per client
operation. AKD already instruments it — `METRIC_GET`, `METRIC_BATCH_GET`,
`METRIC_READ_TIME`, dumped by `log_metrics` (`storage/manager/mod.rs:40-166`) —
so turn on their counters and report ops-per-lookup beside seconds. And report
everything against epoch rate: at 15 s epochs AKD's flush penalty drops 15x and
so does our write volume, so a single-epoch-rate number can be made to say
almost anything.

One strategic caveat. \vkt's current position is that comparing an in-memory
server to an on-disk one would be unfair (`eval.tex`). Building either design
removes that defense, and turns a declined comparison into one we have to win.

---

## 4. Alternatives

### 4.1 AKD's layout, and where it sits

| | AKD | A | B |
|---|---|---|---|
| unit stored | one node | one node | one page |
| its key | label, length-major | label, value-major | the page's own hash |
| can a stored item change? | yes, each epoch touching it | yes, new MVCC version | never |
| publishing an epoch | one DB txn, root row last | one txn | new pages, then one pointer flip |
| readers vs. half-written epoch | a spare copy of the old value per row | MVCC read at the epoch's `ts` | old pages still exist |
| RAM | opportunistic cache, flushed entirely each epoch under a lock that blocks proofs | none needed | complete index for the epoch; entries evicted, never invalidated |
| how stale a reader may be | one epoch, then `NotFound` | a version window | a GC window |
| two writers | nothing stops them; they fork | one loses | one loses |
| trust in the store | trusted | trusted | untrusted; hash-checked |

**Why AKD looks like this.** It did *not* build a transaction protocol:
`storage::transaction::Transaction` is a `DashMap` write buffer, "a simple
in-memory transaction object to minimize data-layer operations"
(`transaction.rs:26-32`), whose `commit_transaction` hands back accumulated
records (`:93`) for MySQL to wrap in one real transaction. It exists because the
tree insert is a multi-pass in-memory computation that reads back what it just
wrote (`transaction.get`, `:138`) and should leave as one `batch_set`. Both
designs here have the same component.

So transactions *do* solve epoch publication. What they leave open is the read
side, and there are four points on that ladder, not two:

1. **Transactions only, walk the tree.** Mutable nodes keyed by label, reads in a
   snapshot transaction, epochs in one write transaction. No paging, no content
   addressing, no GC — and no `previous_node` or cache flush either. Correct, and
   far less machinery than anything else. Costs ~30 dependent round trips.
2. **AKD.** Point 1 plus a cache, which breaks the snapshot, which forces a
   2-deep manual MVCC, which bounds reader lag at one epoch (R3), plus a full
   flush per epoch because keys carry no version (R5). This is the local optimum
   you reach by adding caching to point 1 without changing the data model.
3. **Design A.** Point 1 plus MVCC snapshot reads and a batched prefix probe.
   Consistency and round trips both fixed, no new data structure.
4. **Design B.** Version in the key, so entries never expire — the cache,
   replicas, and lag window all come free, at the cost of write amplification,
   garbage, and GC.

The distinction between 3 and 4 is narrow and worth stating precisely: **MVCC
buys consistency; immutability buys cache stability across epochs.** A cached
entry under versioned keys is valid for a timestamp interval that *ends*; a page
keyed by its own hash is valid forever, because an unchanged page is literally
the same key next epoch. A replica serving the latest epoch has a continuously
advancing read timestamp, so interval-bounded entries expire every epoch and its
cache rebuilds.

Where AKD's choice is genuinely better than B: a node is the smallest possible
write unit, so no page write amplification, no garbage, no GC job — and SQL rows
are inspectable and migratable with tools that already exist.

### 4.2 Content-addressed nodes (design B at `b = 1`)

Immutable, self-verifying, pointer flip, no page format. But a read is a
pointer chase of ~30 dependent hops, because a *hash*-keyed child cannot be named
before its parent is read. That is the crucial asymmetry with design A: label
keys are computable, hash keys are not. So content addressing costs you the
prefix-probe trick, which is a real argument for A over B that has nothing to do
with page sizes.

### 4.3 Store leaves only; rebuild in RAM at startup

The fastest reads and the simplest code. Fails R1 by construction, and startup is
O(N) hashing. Keep as the small-deployment mode, since it is what `~/pav`
already is.

### 4.4 Shard the write path

Epoch commit becomes a genuine distributed transaction and the fork-freedom
argument gets much harder. §3.2 says one writer does ~6.6 k inserts/s, far past
any plausible key-update rate for 10^9 users, so this buys nothing. Documented
extension point: the CAS on `HEAD` generalizes to a K-key transaction and nothing
else changes.

### 4.5 K independent directories with K digests

Scales trivially but changes the client protocol and the security statement.
Rejected on those grounds, not on performance.

### 4.6 Per-epoch snapshots, and precomputed proofs

Full multi-version storage costs O(N) per epoch unless subtrees are shared — and
sharing subtrees *is* content addressing, so this is design B with a worse key.
Materializing one proof per label per epoch is 10^10 x ~1 KB. No.

### 4.7 Replicated log + a private store per replica

Replicate only the epoch log (the update proofs, ~1 KB/update) and let every
server apply it to its own local store. Each server becomes a deterministic
function of a log prefix — the simplest crash-safety argument available — and
reads cost **zero network round trips**. Replicas apply the log exactly as the
auditor already does (`auditor/auditor.go:56,146`), so they self-verify the
digest they serve. Not a different data layout: each replica still needs a
crash-safe local map, which is the same structure with the pointer in a file.

| | shared store | private store + log |
|---|---|---|
| per-replica capacity | index only, or nothing (A) | full copy, 0.3–7 TB |
| read round trips | 1–3 | 0 |
| new replica spin-up | seconds | hours |
| must sustain the write rate | no | yes |
| primitive needed | one atomic step | a replicated log |

Few fat replicas versus many thin ones. **This is the topology** (§0), on the
read numbers in worklog §9, so the piece of Tulip to build on for reads is
`paxos`/`txnlog` rather than `txn` — and the log entry is the epoch tape the
auditor already gets. The "full copy" row is what `Evict` softens: a replica may
hold the top of the tree and probe its local store for the rest.

### 4.8 Theta(k)-versions Get

Orthogonal to storage, but both designs multiply it: a Get of a user with k
versions is k VRF proofs and k paths. The paths are independent so it stays 1–3
round trips, but CPU is k x 143.7 us. Marker versions (R9) are the fix and belong
in §7.2.

---

## 5. Tulip: fit and gaps

Checked against `mit-pdos/tulip` (main, Aug 2026) **[V]**.

Gives us:
- Strict serializability, verified in Perennial/Rocq, so the epoch commit is a
  verified atomic step and the multi-key form is there when needed.
- **Real MVCC with reads at an arbitrary past timestamp.**
  `tuple.ReadVersion(ts)` finds the newest version at or before `ts` over a
  never-truncated version list, and a slow-path read makes the replica promise
  not to accept conflicting prepares in the interval. This is what makes design
  A's consistency free, and what makes the plaintext-rows path clean: read
  `HEAD` and the `uid` rows at one `ts`, then fetch tree records outside the
  transaction.
- Paxos-replicated durability: replicas append to an inconsistent log via
  `grove_ffi.FileAppend` and replay it in `resume()` (`replica/replica.go`).
- A `string -> string` point-read/point-write interface, which is the interface
  both designs need.

Gaps, in the order they would bite:

- **No version GC, and this one is specific to us.** `tuple.go` keeps versions in
  an append-only slice with no truncation, and `KillVersion` appends a
  not-present version rather than freeing anything. So on Tulip *nothing is ever
  reclaimed*: design B's stale-node index would correctly identify dead pages and
  deleting them would free no memory.
- **No log compaction.** The WAL grows without bound, so restart time does too.
  Together with the previous point, a Tulip-backed deployment grows monotonically
  in both RAM and restart time, at the full write-amplification rate. This is the
  clearest reason to treat Tulip as a verified reference substrate rather than a
  production one.
- **Replicas are memory-resident.** `index/index.go` is a
  `map[string]*tuple.Tuple` with no disk backing or eviction, so Tulip meets R1
  only *horizontally*: 300–640 GB sharded across replica groups. A real
  deployment, but memory-resident sharding, not out-of-core storage.
- **No range scan.** Hence every key in both designs is *computable* from a label
  or a uid — no listing, no secondary indexes.
- **`keyToGroup` is `len(key) % ngroups`** (`txn/txn.go`), a placeholder that
  puts all equal-length keys in one group. Our keys are all one length by
  construction, so this must become a hash. Small, but it is verified code.
- **Reads inside a transaction are sequential**, one round trip per `Read`, and a
  `Txn` is not concurrency-safe. Design A's 64-probe batch therefore wants either
  a batched read primitive or 64 concurrent single-key read-only transactions.
  **This is the first thing to check** — it may be the difference between A being
  cheap and A being unusable.

### 5.1 On a different store

The store's job is "a bag of records, plus one atomic step". A local file, an
embedded LSM, and a distributed KV all provide it, so both designs survive the
substitution. What changes:

- **The A-vs-B choice is entirely a property of the substrate.** Per-key request
  cost high (sharded, quorum reads): B's single probe wins. Per-key cost low
  (embedded LSM, sorted, block-cached): A wins, and wins on effort too.
- **Band width and cut depth track read latency** if you are in B. At ~1 ms per
  remote read, KB pages; at ~10 us, `b = 1` — at which point you should be in A
  instead (§4.2).
- **Range scans remove bookkeeping**, not structure: version counts by prefix
  scan, GC by scanning rather than by stale-index.
- **Large-value support sets the page cap** in B; a small value limit forces
  smaller pages, i.e. more probes, i.e. A.

What does not change under any substitution: the epoch-commit invariant (§2.0),
and keeping the hash unit smaller than the storage unit.

---

## 6. Precedents

**Tiled transparency logs** (Cox, `research.swtch.com/tlog`, 2019) **[V]** are
design B, and B should be presented as tiling applied to a map rather than as
new. A tile is a fixed-height slice, height `H`, width `2^H` — our band `b`. Only
a tile's bottom row is stored and upper rows are recomputed — our "a page is only
its children". Clients cache tiles, upper levels especially, so a proof over a
100 M-entry log costs three complete tiles plus a partial — §3.2's arithmetic.
Tiles are verified against a signed checkpoint, so storage can be a CDN — our
epoch record and `HEAD`. In production twice: the Go checksum database, and
`static-ct-api`/Sunlight, which serves whole CT logs as static tiles from object
storage.

The structural difference is the source of everything awkward in B: **a log is
append-only at the frontier, a map is not.** In a tiled log a completed tile is
frozen forever, so tiles are addressed *positionally* — the shape is a function
of the size alone, and the only churn is one partial tile per level. Our inserts
land mid-trie, so page identity must be prefix- or hash-based, a mutated page
must be republished, and that republishing is where write amplification and GC
come from. Tiling gets immutability free; B buys it.

**Trillian** **[V]**: `SubtreeProto` carries `prefix`, `depth`, `leaves`,
`internal_nodes`, `internal_node_count`. So prefix-keyed pages are production
CT/KT infrastructure. They *derive* internal hashes — "the internal nodes of the
subtree are not generally stored. However internal nodes are stored for partially
filled log subtrees" — the opposite of §2.2's conclusion for leaf pages, and the
difference is that they have no 143.7 us VRF to hide hashing behind. The
`internal_node_count` "expected size crosscheck" field hints the derive path is
fiddly enough to want a runtime assertion.

**Jellyfish Merkle Tree (Diem/Aptos)** **[V~]** is the closest match: the node
key includes a **version**; internal nodes are 16-ary over 4-bit nibbles where
each stored node is internally "a 4-level binary tree" — paging at `b = 4`, with
binary hashing inside a wider storage unit, i.e. the same hash-unit/storage-unit
split; "any subtree containing 0 or 1 leaf node will be replaced by that leaf
node or a placeholder", which is \vkt's compression; and a put returns a
`TreeUpdateBatch` plus a `StaleNodeIndex` recording that a node "becomes stale
since `stale_since_version`". Three things taken: the stale-node index (adopted,
§2.2); their choice of `b = 4` for a *local* store, which is empirical support
for §5.1; and the reminder that version-keyed nodes have **ordered** keys, so
subtree and per-epoch locality survive, whereas content-addressed keys are random
— a real cost of self-verification. Because JMT's canonical shape matches \vkt's,
its engineering is unusually transferable: first place to look for the page
format, the batch-update structure, and the pruner.

**Ethereum** is *not* this design — one node per record, content-addressed, i.e.
§4.2. Its history is the cautionary version: every trie node is a random disk
read, so geth added a **flat snapshot layer** so ordinary reads never touch the
trie, and depth was eventually attacked by changing the *hash structure*
(Verkle, 256-ary vector commitments). That last point is the useful one: they
could not fix depth in the storage layout, because clients verify against the
canonical structure, so the structure *is* the interface. We can, and that is
the payoff of §3.4's hash-unit rule.

**Copy-on-write B-trees** — LMDB, ZFS, Btrfs — are §2.3's commit protocol, thirty
years old.

**FOKS** (`github.com/foks-proj/foks-whitepaper`, §3.4.3–3.4.5) **[V]** replaces
the VRF with a commitment chain: the leaf key is `H(p, i, t, r_i)` where `r_i` is
random, chosen when link `i-1` was published and committed as `H(r_i)` *inside
that signed link*; queries return `n+1` paths plus the openings
`(r_2, ..., r_{n+1})`, checked against the sigchain. They claim it achieves "the
same end as the pseudo-random function in CONIKs and SEEMLess" and list "hiding
identity and team updates in a larger transparency tree without the need for
pseudo-random functions" as a contribution.

Label derivation therefore stops being a secret-key operation and becomes a data
lookup, with three consequences for us. **The read path could be fully static** —
openings and records are immutable and client-nameable, so a client could fetch
openings, compute labels, fetch records, and assemble its own proof; FOKS does
not make this argument, it is an implication. **No secret material on the read
fleet**, which is a bigger operational win than the CPU. And **the cost model
inverts**: without the ~290 us VRF, reads become I/O-bound, which argues for
larger resident indexes and bigger pages than §3.2 picks. The cost is that
openings are revealed to any querier, including `r_{n+1}`, so anyone who has ever
looked up `p` can predict where `p`'s next update lands. A VRF hides labels from
everyone but the server, permanently. That is a security-model decision for the
KT layer, not a storage one — but it is *the* decision before building toward
static serving. Note also that FOKS's leaf key includes the sequence number, so a
lookup still costs `n+1` paths: it has \vkt's Theta(k) problem too (§4.8), and
the VRF was never what caused that. And FOKS runs a ~15 s epoch against AKD's
~1 s, a reminder that epoch cadence is a free parameter this note otherwise
treats as fixed.

---

## 7. Protocol changes worth making

None of these are storage changes, and all of them were deferred because they
touch the client and the security proof. That is the point of listing them
together: **the storage layer's shape is set by physics; the protocol's shape was
set by what was cheap to prove.**

### 7.1 Log-spaced back-pointers over epoch digests

**Demoted by §1.5.** At the measured 30 s cadence this is 2,867 x 32 B =
**92 KB/day** for a daily-syncing client, not the 2.8 MB/day I computed from a
1 s epoch — so it is a non-issue at AKD's actual cadence, and only becomes one if
you want sub-second epochs. Kept because the mechanism is still the right one if
the cadence ever drops, and because §7.2 wants the same construction anyway.

Today `link_e = H(link_{e-1} || dig_e)` — one
back-pointer — so moving a client from epoch `i` to `k` ships *every* digest
`dig_{i+1..k}` (`hashchain.go:31`) and `Verify` folds them one at a time (`:46`).
But the client only needs `dig_k`, to check proofs against, plus the knowledge
that `k` **descends from** what it trusts. It has no use for the intermediate
digests. So all `32*(k-i)` bytes exist to establish a *lineage* relation, and a
single-back-pointer chain is the most expensive possible way to establish it.

FOKS §3.4.3–3.4.4 gives each root block "a logarithmicly-sized set of pointers to
previous roots further back in history" — pointers to `e-1, e-2, e-4, e-8, ...` —
making the epoch history a skip list. Catch-up is a path through it: blocks
`j_1 < ... < j_n` where each points to its predecessor, `j_1` to `i`, and `k` to
`j_n`; largest-jump-first gives `n ~ log(k-i)`. Skipping is sound because **every
block still carries its `e-1` pointer**, so each block commits to its immediate
predecessor and transitively to all history: the chain is *pinned* whether or not
a given client *checks* it. The client checks a logarithmic path; adjacency is
audited — "clients should perform periodic audits of all root blocks to ensure
previous-pointer consistency". That is the division of labour \vkt already has,
since its auditor walks every epoch anyway.

At the measured 30 s cadence, a client syncing daily: 2,867 x 32 B = 92 KB/day
against ~12 hops x a few hundred bytes ~ 4 KB/day. At a hypothetical 1 s epoch it
would be 2.8 MB/day against ~5 KB/day.

A Merkle log (tlog/MMR) over the digest sequence is the better construction —
~32 B/epoch of storage against a skip list's ~1 KB of pointers per block,
`O(log k)` proofs, append-only by construction, and tileable, so the epoch
history becomes static-servable too. The skip list wins only on retrofit cost.
Since the client is being re-proved either way, take the Merkle log.

### 7.2 Marker versions

R9, bounding a Get to O(log k) rather than Theta(k) proofs. Note this is the same
exponentially-spaced skip structure as §7.1, on the version axis instead of the
epoch axis — AKD's `MARKER_VERSION_SKIPLIST` (`akd_core/src/utils.rs:15`). Worth
fixing both with one construction.

### 7.3 A freshness bound against the auditor

Require the auditor's latest epoch to be within X of the client's.
Party-to-party, no clock model. Not a signed timestamp (§2.4).

### 7.4 Pagination for `Audit` and `History`

R14. A server-chosen cap and a continuation token, so no reply size is
client-controlled.

---

## 8. Measurement plan

In order, because each answer decides whether the next question matters.

1. **What does a 64-key `batch_get` cost on Tulip?** Latency, per-group load, and
   p99, against one single-key read. Tulip's `Txn.Read` is one round trip per key
   and a `Txn` is not concurrency-safe (§5), so measure both "64 concurrent
   single-key read-only transactions" and "one batched primitive if we add one".
   **This single number decides A vs. B.**
2. **Tulip single-key read latency and per-group throughput.** One 56-thread
   replica wants ~190 k reads/s; nothing in this note validates that a group can
   feed it. Also measure the 400 ms resend interval's effect on p99.
3. **Packed-page proof gather, stored vs. derived inner hashes**, to fix `k` — but
   only if B is happening.
4. **Hit rate under a realistically heavy-tailed lookup distribution**, which
   decides whether any round trip is amortized.
5. **AKD's own counters** (`METRIC_GET` etc., `storage/manager/mod.rs:40-166`) on
   a deployment-shaped configuration, to get a config-independent baseline.

---

## 9. Open questions

1. Does the gluing lemma (§3.3 item 3) go through as cleanly as
   `to_map'`/`is_cut_tree`'s prefix structure suggests? The one place B's proof
   effort could blow up.
2. Fixed bands vs. size-adaptive pages. Adaptive keeps page sizes uniform under
   skew but makes the page key depend on history, breaking "key computable from
   the label". Probably unnecessary, since VRF labels are uniform by
   construction — worth stating as the explicit reason fixed bands are safe.
3. For B, is the resident index refreshed by `manifest` refetch (~32 MB/epoch at
   B = 1000) or by replaying update proofs (~1 MB/epoch, and self-verifying)?
   Replay is better but makes replicas stateful in a way that needs a cold-start
   path — the index must be bulk-loaded, since replaying from epoch 0 is not an
   option.
4. ~~Is the audit blob store the same KV or a separate object store?~~
   **Answered by §1.5**: separate, and it is the largest single data flow in the
   system — 109 GB/day, ~17 TB retained over ~160 days. The open question that
   replaces it: the blob appears to be ~10x larger than its inserted-leaves
   content because it ships unchanged nodes, so is there a cheaper append-only
   proof? That is worth more than any tree optimization here.
5. Is the FOKS unlinkability trade acceptable (§6)? Everything about static
   serving hangs on it.

---

## 10. What this draft reverses

Recorded so the reversals are not mistaken for oversights.

- **AKD cannot batch a single lookup** -> it can. Nodes are keyed by the prefix
  they represent, so every node on `L`'s path is a prefix of `L` and all ~64
  candidate keys are computable up front. This is what design A is, it removes
  the round-trip argument for B, and it makes the AKD comparison much narrower
  (§3.5).
- **AKD implemented its own transaction layer** -> it did not; `Transaction` is a
  write buffer and atomicity is delegated to the DB (§4.1).
- **A cache cannot participate in the store's snapshot** -> too strong. Versioned
  entries have validity intervals that end; hash-keyed entries do not. MVCC buys
  consistency, immutability buys cache stability (§4.1).
- **Retaining history buys free historical proofs** -> nothing in the protocol
  ever asks for a proof against a past digest. The retention window is for
  in-flight readers and is sized in seconds (§2.3).
- **Put a timestamp in the signed epoch record** -> retracted. Self-attested, so
  it buys nothing against a malicious signer, and is dominated by a
  replica-vs-`HEAD` comparison for the honest case (§2.4).
- **Expose "I am behind" in the reply** -> unnecessary; the protocol already has
  a transport-level channel that maps to `BlameUnknown` (§2.4).
- **Derive page inner hashes** -> for *leaf* pages, store them, or reconstruction
  costs ~2k hashes on the critical path and B ends up slower than AKD's
  in-memory ceiling (§2.2).
- **Design B (paging) is the escalation path** -> it is ruled out. Decoding two
  audit blobs gives `B ~ 46k` insertions per epoch, at which paging rewrites
  3.2 TB/day against 392 GB/day for one record per node. The first draft of this
  note had paging as its centrepiece.
- **The append-only proof is ~10x larger than its content** -> wrong. It is
  906–1006 B per insertion against 1088 B for one independent Merkle path: the
  unchanged nodes *are* the batch-shared sibling set. Not a lever.
- **Epochs are ~1 s, batches are ~1000** -> measured from the live audit log:
  30 s and ~46k. This deflates the R3 and R5 criticisms, demotes §7.1
  from "biggest win available" to a non-issue, and supplies the first
  measurement-grounded argument for A over B.
- **The resident index is 0.5 GB "as a cache"** -> it is a required index, not a
  cache; the earlier figure also undercounted 2x by omitting derived inner
  hashes, and it assumes packed bytes rather than `node` structs (§3.2).
