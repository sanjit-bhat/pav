From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi cryptoutil hashchain merkle safemarshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  serde.

Module ktcore.
Import serde.ktcore.

(* gmap from uid's to list of pks (indexed by version). *)
Definition keys_ty := gmap w64 (list $ list w8).

(* FIXME: needed for lia to unify [length digs] terms where one has keys_ty and
the other has its unfolding *)
#[global] Hint Unfold keys_ty : word.

Definition keys_sub : relation keys_ty := map_included (λ _, prefix).

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _, !globalsGS Σ} {go_ctx : GoContext}.
Context `{!pavG Σ}.

Definition is_MapLabel vrf_pk uid ver map_label : iProp Σ :=
  let enc := MapLabel.pure_enc (MapLabel.mk' uid ver) in
  cryptoffi.is_vrf_out vrf_pk (Some enc) map_label.

Lemma is_MapLabel_det pk uid ver map_label0 map_label1 :
  is_MapLabel pk uid ver map_label0 -∗
  is_MapLabel pk uid ver map_label1 -∗
  ⌜map_label0 = map_label1⌝.
Proof.
  rewrite /is_MapLabel.
  iIntros "#H0 #H1".
  iDestruct (cryptoffi.is_vrf_out_det with "H0 H1") as %->.
  done.
Qed.

(* externalize [rand] bc some clients want to determ
derive [map_val] from [kt_pk]. *)
Definition is_MapVal kt_pk rand map_val : iProp Σ :=
  let enc := CommitOpen.pure_enc (CommitOpen.mk' kt_pk rand) in
  cryptoffi.is_hash (Some enc) map_val.

Lemma is_MapVal_det pk rand map_val0 map_val1 :
  is_MapVal pk rand map_val0 -∗
  is_MapVal pk rand map_val1 -∗
  ⌜map_val0 = map_val1⌝.
Proof.
  iIntros "#H0 #H1".
  iDestruct (cryptoffi.is_hash_det with "H0 H1") as %->.
  done.
Qed.

Definition decode_map_label odata :=
  rem0 ← odata;
  guard (length rem0 ≥ 8);;
  let uid := le_to_u64 (take 8 rem0) in
  let rem1 := drop 8 rem0 in
  guard (length rem1 ≥ 8);;
  let ver := le_to_u64 (take 8 rem1) in
  Some (uid, uint.nat ver).

Definition decode_map_val odata :=
  rem0 ← odata;
  guard (length rem0 ≥ 8);;
  let pk_len := sint.nat (le_to_u64 (take 8 rem0)) in
  let rem1 := drop 8 rem0 in
  guard (length rem1 ≥ pk_len);;
  let pk := take pk_len rem1 in
  (* drop the remaining rand. we don't need that. *)
  Some (pk).

Definition is_decode_map_label vrf_pk map_label obj : iProp Σ :=
  ∃ odata,
  "#His_vrf_out" ∷ cryptoffi.is_vrf_out vrf_pk odata map_label ∗
  "%Hdec" ∷ ⌜obj = decode_map_label odata⌝.

Definition is_decode_map_val map_val obj : iProp Σ :=
  ∃ odata,
  "#His_hash" ∷ cryptoffi.is_hash odata map_val ∗
  "%Hdec" ∷ ⌜obj = decode_map_val odata⌝.

Definition is_flat_keys vrf_pk hidden flat : iProp Σ :=
  ∃ decoded,
  "#Hdec" ∷ ([∗ list] kv;d ∈ map_to_list hidden;decoded,
    is_decode_map_label vrf_pk kv.1 d.1 ∗
    is_decode_map_val kv.2 d.2) ∗
  "%Hfilter" ∷ ⌜flat = omap (λ '(olabel, oval),
    '(uid, ver) ← olabel;
    pk ← oval;
    Some (uid, ver, pk)) decoded⌝.

Definition assemble (flat : list (w64 * nat * list w8)) :
    gmap w64 (gmap nat (list w8)) :=
  foldl
    (λ m '(uid, ver, pk),
      let m_uid := m !!! uid in
      let m_uid' := <[ver:=pk]>m_uid in
      <[uid:=m_uid']>m)
    ∅ flat.

Fixpoint get_contig (m_uid : gmap nat (list w8)) (ver fuel : nat) :=
  match fuel with 0%nat => [] | S fuel' =>
  match m_uid !! ver with None => [] | Some pk =>
  pk :: get_contig m_uid (S ver) fuel' end end.

Definition is_plain_keys (vrf_pk : list w8) (hidden : gmap (list w8) (list w8))
    (plain : keys_ty) : iProp Σ :=
  ∃ flat interm,
  "#His_flat" ∷ is_flat_keys vrf_pk hidden flat ∗
  "%Heq_interm" ∷ ⌜interm = assemble flat⌝ ∗
  (* size is simple upper bound on max ver. *)
  "%Heq_plain" ∷ ⌜plain = (λ m_uid, get_contig m_uid 0 (size m_uid)) <$> interm⌝.

(* used by clients who agree across the same digs. *)
Lemma is_plain_keys_det vrf_pk hidden plain0 plain1 :
  is_plain_keys vrf_pk hidden plain0 -∗
  is_plain_keys vrf_pk hidden plain1 -∗
  ⌜plain0 = plain1⌝.
Proof. Admitted.

(* used by auditor.
to prove, is_plain_keys can't require bijection. *)
Lemma is_plain_keys_invert vrf_pk hidden :
  ⊢ ∃ plain, is_plain_keys vrf_pk hidden plain.
Proof. Admitted.

(* used by auditor.
maybe could be generalized? *)
Lemma is_plain_keys_over_sub vrf_pk hidden0 hidden1 plain0 plain1 :
  hidden0 ⊆ hidden1 →
  is_plain_keys vrf_pk hidden0 plain0 -∗
  is_plain_keys vrf_pk hidden1 plain1 -∗
  ⌜keys_sub plain0 plain1⌝.
Proof. Admitted.

(* hidden is fully made up of contiguous versions.
i.e., hidden and the computed plain are bijective. *)
Definition is_contig (vrf_pk : list w8) (hidden : gmap (list w8) (list w8)) : iProp Σ.
Admitted.

(* used in server update. *)
Lemma is_plain_keys_add vrf_pk hidden plain uid kt_pk label val rand :
  let pks := plain !!! uid in
  is_plain_keys vrf_pk hidden plain -∗
  is_contig vrf_pk hidden -∗
  is_MapLabel vrf_pk uid (length pks) label -∗
  is_MapVal kt_pk rand val -∗
  let hidden' := <[label:=val]>hidden in
  let plain' := <[uid:=pks ++ [kt_pk]]>plain in
  is_plain_keys vrf_pk hidden' plain' ∗ is_contig vrf_pk hidden'.
Proof. Admitted.

End proof.
End ktcore.
