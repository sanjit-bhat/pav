# What AKD's public audit log measures

Measured **2026-08-20** against the live WhatsApp KT log. **[V]** throughout —
every number here came from the artifact, not from a paper. This exists because
the 2023–24 papers and slides are stale by up to 10x on the parameters that
matter (§6), and because the log turns out to expose far more than epoch cadence.

Companion to `persistent-server-design.md`, which consumes these numbers.

---

## 1. Method

The audit bucket is a plain S3 listing behind CloudFront, and the blobs are raw
protobuf. Both are public. AKD's own auditor does exactly this
(`whatsapp_kt_auditor/mod.rs:23`, `auditor.rs:79-108,120-131`).

```sh
U=https://d4ttn6vhp3mg0.cloudfront.net   # LogVersion::V2, "the current WhatsApp KT log"
V1=https://d1tfr3x7n136ak.cloudfront.net # the legacy log

# listing: Key = {epoch}/{prev_root}/{curr_root}, plus LastModified and Size
curl -sS "$U/?list-type=2&prefix=11798&max-keys=1000"

# one epoch's audit proof (30-200 MB)
curl -sS "$U/1179837/1762200b.../65e19311..." -o blob.pb
```

Keys are unpadded decimal epochs, so same-digit-count epochs sort numerically and
prefix probes binary-search either end of the log.

A blob is a `SingleAppendOnlyProof` (`akd_core/src/proto/specs/types.proto:102`):
`repeated AzksElement inserted = 1; repeated AzksElement unchanged_nodes = 2;`
where `AzksElement = {NodeLabel label = 1; bytes value = 2}` and
`NodeLabel = {bytes label_val = 1; uint32 label_len = 2}`. No compression, so a
plain protobuf field walk over the top level counts both vectors and recovers
every label length and label prefix. `AuditBlob::decode`
(`local_auditing.rs:150`) is the reference implementation.

---

## 2. Cadence and reliability

| | |
|---|---|
| bucket | `whatsapp-kt-audit-proofs` |
| **cadence** | **30 s** (median 30, mean 30.28 over 3,846 intervals) |
| latest epoch | **1,179,831** at 2026-08-20T23:04:02Z — live while querying |
| oldest retained | 722,606 at 2026-03-14T01:41:34Z |
| retention | ~160 days / 457,225 epochs; not a round epoch, so time-based |
| epochs/day | 2,867 |

Reliability, over 3,847 consecutive epochs:

- **No gaps in epoch numbering.** Every epoch publishes a blob.
- **The chain verifies from file names alone.** `curr_root(N) == prev_root(N+1)`
  for all 3,846 adjacent pairs. The listing is therefore a checkable record of
  457k root hashes with nothing downloaded — the cheapest possible continuity
  audit, and a useful cross-check for any auditor.
- **30 s is a target, not a guarantee.** p99 = 60 s, max 241 s. Thirty-seven
  intervals are exactly 60 s (one missed tick); a handful are 63–98 s; and **29
  intervals are ~2 s**, i.e. catch-up bursts after a stall. So ~1% of ticks slip
  and are made up by publishing back-to-back.

  *Consequence for anything that bounds the epoch rate*: "at most one epoch per
  `epochTime`" is false. A rate bound needs slack for catch-up bursts, not only
  for clock skew.

---

## 3. Audit proof size, and what is in it

Sizes over the recent window: **median 44.3 MB**, p25 37.5, p75 50.4, **max
201.7 MB**. So the RWC 2024 slides' "~200 MB each" is the *peak*, not the typical
case.

Two blobs decoded in full:

| | epoch | UTC | size | `inserted` | `unchanged_nodes` | ratio |
|---|---|---|---|---|---|---|
| trough | 1,179,837 | 23:07 | 30.9 MB | **30,710** | 600,155 | 19.5x |
| peak | 1,179,113 | 17:02 | 132.1 MB | **145,835** | 2,521,320 | 17.3x |

Both blobs are 49.0–49.5 B per element, so size is linear in element count:
`inserted ≈ 1138 × MB − 4442`. Applied to the size distribution:

| blob size | insertions/epoch |
|---|---|
| p25, 37.5 MB | 38,000 |
| **median, 44.3 MB** | **46,000** |
| p75, 50.4 MB | 53,000 |
| max, 201.7 MB | 225,000 |

So **~46k insertions per epoch at the median, ~132M per day.** One caveat before
reading that as key updates: AKD inserts a stale marker alongside each new
version (Parakeet, Appendix I: "updates to keys for existing users require more
values to be inserted into the tree (to mark old version numbers as stale)"), so
the underlying key-update rate is roughly half — call it ~66M/day. That is still
~6x Parakeet's 2023 estimate of 10M/day.

**The proof is not redundant.** `unchanged_nodes` outnumber `inserted` by ~18x,
which looks wasteful until you divide by insertions: **906–1006 B per
insertion**, against `depth × 32 B = 1088 B` for a single Merkle path. The
unchanged nodes *are* the sibling set, shared across the whole batch, so the
per-update cost is slightly *below* one independent path. This retracts an
earlier guess that the blob was ~10x larger than its information content and that
shrinking it was the biggest available lever — it is close to optimal for a
batched append-only proof. For comparison, \vkt ships a full non-membership proof
per update (`ktcore.UpdateProof`), ~34 siblings ≈ 1.1 KB, so AKD's batch-shared
encoding is *more* efficient per update, not less.

---

## 4. Workload shape

**A ~2x diurnal swing.** Median blob size by UTC hour, over 3,847 epochs:
trough ~31 MB at 23–00Z, peak ~60 MB at 16Z, **ratio 1.93x**. In insertions that
is roughly 31k to 64k per epoch. The same shape appears in samples from April,
May, June and July, so it is the workload rather than noise.

**No growth trend, once controlled for hour-of-day.** Same 08Z hour across four
monthly samples: 53.0 (Apr), 43.6 (May), 40.4 (Jun), 42.2 MB (Jul). Uncontrolled
samples look like a random walk purely because of the diurnal cycle — a trap for
anyone repeating this measurement.

**Labels are uniform, as the VRF implies.** Top-nibble histogram of the inserted
labels: 1867–2027 against 1919 expected (trough), 154,721–159,560 against 157,582
(peak). Within ±3%. So any design that assumes uniform label distribution — fixed
bucket boundaries, no hot spots, occupancy by construction — is safe on this
workload.

---

## 5. The tree's shape, from the depth profile

Every `inserted` label has `label_len = 256`: insertions are always full-length
leaves. The `unchanged_nodes` carry real depths, and their distribution is the
most informative thing in the blob.

| | trough | peak |
|---|---|---|
| non-leaf depth range | 13 – 48 | 14 – 51 |
| mean depth | 42.3 | 45.6 |
| leaves (`label_len = 256`) | 44,217 | 210,193 |

Two facts fall out.

**Everything above depth ~17 is rewritten every epoch.** The shallowest
*unchanged* node sits at depth 13–14, and `2^17 = 131k ≈ B`, so with ~46–146k
insertions spread uniformly, essentially every node in the top ~17 levels lies on
some insertion path. Any claim that "the top of the tree is hot and therefore
stable and cacheable" is wrong for this workload: the top of the tree is hot
*and* rewritten, every 30 s.

**The directory holds ~2^32 leaves.** The deepest branching is ~51. For uniform
labels, the deepest collision among `B` insertions into a tree of `N` leaves sits
near `log2 N + log2 B`; with `B ≈ 146k` that gives `log2 N ≈ 51 − 17 = 34`, so
`N ≈ 10^10` within a factor of a few. Consistent with Parakeet's estimate of
5.65B keys after year one, and it means the 10^10 column of any sizing table is
the relevant one.

---

## 6. What the older sources get wrong

- **\vkt's own comment**, "AKD uses an epochTime of ~1 second"
  (`server/server.go:127`) — it is 30 s.
- **RWC 2024's "5 min"** was right for its era. The V1 bucket
  (`kt-audit-proofs-integration-v2`) retains from epoch 1, published
  2023-02-14T22:45:18Z at 10.6 MB, and epoch 2,000 lands 2023-02-22 — **~346 s ≈
  5.8 min per epoch**. V2 has since gone to 30 s, a **10x cadence increase**.
  Treat every parameter from the 2023–24 papers and slides as stale by that
  factor.
- **"~200 MB" proofs** are the peak; the median is 44 MB.
- **Parakeet's ~10M daily key updates** understates the measured rate by ~6x.
- **Parakeet's compaction** — its headline storage result, 21.4 TB -> 0.87 TB in
  year one — is not implemented: `grep` for delete/remove/compact/prune across
  `akd/src` and `akd_core/src` returns nothing, and the `Database` trait has no
  delete operation. Parakeet's own abstract calls it "a future-facing solution".
  Its witness-quorum commitment distribution is likewise absent from the deployed
  architecture, which is single writer -> S3 -> clients.

---

## 7. Consequences for the design

The numbers that matter downstream, and where they land in
`persistent-server-design.md`:

| measured | consequence |
|---|---|
| 30 s cadence, not 1 s | R3's one-epoch reader window is ~1 min of tolerance, generous rather than fragile; R5's per-epoch cache flush roughly coincides with the cache's own 30 s TTL, so the flush is near a no-op and the surviving criticism is structural, not quantitative |
| 30 s cadence | linear hashchain catch-up is 92 KB/day for a daily-syncing client, not 2.8 MB/day — demotes §7.1 from "biggest win available" to a non-issue absent sub-second epochs |
| ~1% of ticks slip, catch-up at ~2 s | a rate-bound pre-filter on `prevEpoch` needs burst slack |
| **B ≈ 46k insertions/epoch** | a per-epoch *transaction* over B keys is out of the question; the atomic step must be O(1) in batch size |
| **B ≈ 46k**, top 17 levels fully rewritten | **paging is ruled out.** Distinct pages touched per epoch is `1 + 256 + min(B, 65536) + B + B ≈ 138k`, so ~1.13 GB/epoch, **3.2 TB/day** — against ~912k nodes ≈ 137 MB/epoch, **392 GB/day**, for one-node-per-record. 8x worse, and 3 TB/day of page rewrites is not a rounding error |
| labels uniform within ±3% | fixed bucket boundaries and no-skew occupancy assumptions are safe |
| audit proofs 109 GB/day, ~17 TB retained | the audit path is a first-class data flow, and it belongs in object storage, not in the serving store |
| proof is ~1 KB/insertion, near-optimal | do **not** spend effort shrinking the append-only proof |

The last two rows are the ones that changed my mind: paging was the centrepiece
of the first draft of the design doc, and a measured batch size kills it.
