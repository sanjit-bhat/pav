From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi cryptoutil hashchain merkle safemarshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  serde.

Section sep_list2.
  Context {PROP : bi}.

  Lemma big_sepL2_det_l {A B} (Φ : A → B → PROP) l1 l2 l2' :
    ([∗ list] x1;x2 ∈ l1;l2, Φ x1 x2) -∗
    ([∗ list] x1;x2 ∈ l1;l2', Φ x1 x2) -∗
    (□ ∀ x1 x2 x2', Φ x1 x2 -∗ Φ x1 x2' -∗ ⌜x2 = x2'⌝) -∗
    ⌜l2 = l2'⌝.
  Proof.
    iIntros "Hsep0 Hsep1 #Hdet".
    iInduction l1 as [|? ? IH] forall (l2 l2').
    - iDestruct (big_sepL2_nil_inv_l with "Hsep0") as %->.
      by iDestruct (big_sepL2_nil_inv_l with "Hsep1") as %->.
    - iDestruct (big_sepL2_cons_inv_l with "Hsep0") as "(%&%&->&H0&Hsep0)".
      iDestruct (big_sepL2_cons_inv_l with "Hsep1") as "(%&%&->&H1&Hsep1)".
      iDestruct ("Hdet" with "H0 H1") as %->; [done..|].
      by iDestruct ("IH" with "Hsep0 Hsep1") as %->.
  Qed.

  Lemma big_sepL2_det_r {A B} (Φ : A → B → PROP) l1 l1' l2 :
    ([∗ list] x1;x2 ∈ l1;l2, Φ x1 x2) -∗
    ([∗ list] x1;x2 ∈ l1';l2, Φ x1 x2) -∗
    (□ ∀ x1 x1' x2, Φ x1 x2 -∗ Φ x1' x2 -∗ ⌜x1 = x1'⌝) -∗
    ⌜l1 = l1'⌝.
  Proof.
    iIntros "Hsep0 Hsep1 #Hdet".
    iDestruct (big_sepL2_flip with "Hsep0") as "Hsep0".
    iDestruct (big_sepL2_flip with "Hsep1") as "Hsep1".
    assert (∃ Φ', ∀ x y, Φ x y = Φ' y x) as [Φ' Ht]; [naive_solver|].
    iEval (setoid_rewrite Ht) in "Hdet".
    iDestruct (big_sepL2_mono _ (λ _, Φ') with "Hsep0") as "Hsep0".
    { by setoid_rewrite Ht. }
    iDestruct (big_sepL2_mono _ (λ _, Φ') with "Hsep1") as "Hsep1".
    { by setoid_rewrite Ht. }
    iDestruct (big_sepL2_det_l with "Hsep0 Hsep1 []") as %->; [|done].
    iIntros "!> *". naive_solver.
  Qed.

  Lemma big_sepL2_invert {A B} (Φ : A → B → PROP) l2 :
    (∀ x2, ⊢ ∃ x1, Φ x1 x2) →
    ⊢ ∃ l1, ([∗ list] x1;x2 ∈ l1;l2, Φ x1 x2).
  Proof.
    intros Hinv. iStartProof.
    iInduction l2 as [|x2 ? IH].
    - by iExists [].
    - iDestruct (Hinv x2) as (x1) "H0".
      iDestruct "IH" as (l1) "Hsep0".
      iExists (x1 :: l1).
      iFrame "#".
  Qed.
End sep_list2.

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

Local Definition decode_map_label odata :=
  rem0 ← odata;
  guard (length rem0 ≥ 8);;
  let uid := le_to_u64 (take 8 rem0) in
  let rem1 := drop 8 rem0 in
  guard (length rem1 ≥ 8);;
  let ver := le_to_u64 (take 8 rem1) in
  Some (uid, uint.nat ver).

Local Definition decode_map_val odata :=
  rem0 ← odata;
  guard (length rem0 ≥ 8);;
  let pk_len := sint.nat (le_to_u64 (take 8 rem0)) in
  let rem1 := drop 8 rem0 in
  guard (length rem1 ≥ pk_len);;
  let pk := take pk_len rem1 in
  (* drop the remaining rand. we don't need that. *)
  Some (pk).

Local Definition is_dec_map_label vrf_pk obj map_label : iProp Σ :=
  ∃ odata,
  "#His_vrf_out" ∷ cryptoffi.is_vrf_out vrf_pk odata map_label ∗
  "%Hdec" ∷ ⌜obj = decode_map_label odata⌝.

Local Definition is_dec_map_val obj map_val : iProp Σ :=
  ∃ odata,
  "#His_hash" ∷ cryptoffi.is_hash odata map_val ∗
  "%Hdec" ∷ ⌜obj = decode_map_val odata⌝.

(* equivalent to converting to gmap of options.
this approach means we can re-use some big_sepL2 infra. *)
Local Definition is_oflat vrf_pk oflat hidden : iProp Σ :=
  ([∗ list] x;y ∈ oflat;map_to_list hidden,
    "#His_label" ∷ is_dec_map_label vrf_pk x.1 y.1 ∗
    "#His_val" ∷ is_dec_map_val x.2 y.2).

Local Definition to_flat oflat : list (w64 * nat * list w8) :=
  omap
    (λ '(olabel, oval),
      label ← olabel;
      pk ← oval;
      Some (label, pk))
    oflat.

Local Definition to_dec_map flat : gmap (w64 * nat) (list w8) := list_to_map flat.

Local Definition to_mapped (dec : gmap (w64 * nat) (list w8)) := gmap_curry dec.

Local Fixpoint get_contig (m_uid : gmap nat (list w8)) ver fuel :=
  match fuel with 0%nat => [] | S fuel' =>
  match m_uid !! ver with None => [] | Some pk =>
  pk :: get_contig m_uid (S ver) fuel' end end.

Local Definition to_plain mapped : gmap w64 (list (list w8)) :=
  (* size is simple upper bound on max ver. *)
  (λ m_uid, get_contig m_uid 0 (size m_uid)) <$> mapped.

Definition is_plain_keys (vrf_pk : list w8)
    (plain : keys_ty) (hidden : gmap (list w8) (list w8)) : iProp Σ :=
  ∃ oflat,
  "#His_oflat" ∷ is_oflat vrf_pk oflat hidden ∗
  "%Heq_plain" ∷ ⌜plain = to_plain $ to_mapped $ to_dec_map $ to_flat oflat⌝.

(* injectivity. *)

Local Lemma is_dec_map_label_inj vrf_pk obj0 obj1 map_label :
  is_dec_map_label vrf_pk obj0 map_label -∗
  is_dec_map_label vrf_pk obj1 map_label -∗
  ⌜obj0 = obj1⌝.
Proof.
  iNamedSuffix 1 "0".
  iNamedSuffix 1 "1".
  iDestruct (cryptoffi.is_vrf_out_inj with "His_vrf_out0 His_vrf_out1") as %<-.
  by simplify_eq/=.
Qed.

Local Lemma is_dec_map_val_inj obj0 obj1 map_val :
  is_dec_map_val obj0 map_val -∗
  is_dec_map_val obj1 map_val -∗
  ⌜obj0 = obj1⌝.
Proof.
  iNamedSuffix 1 "0".
  iNamedSuffix 1 "1".
  iDestruct (cryptoffi.is_hash_inj with "His_hash0 His_hash1") as %<-.
  by simplify_eq/=.
Qed.

Local Lemma is_oflat_inj vrf_pk oflat0 oflat1 hidden :
  is_oflat vrf_pk oflat0 hidden -∗
  is_oflat vrf_pk oflat1 hidden -∗
  ⌜oflat0 = oflat1⌝.
Proof.
  iIntros "H0 H1".
  iDestruct (big_sepL2_det_r with "H0 H1 []") as %<-; [|done].
  iModIntro. iIntros ([??] [??] ?). simpl.
  iNamedSuffix 1 "0".
  iNamedSuffix 1 "1".
  iDestruct (is_dec_map_label_inj with "His_label0 His_label1") as %<-.
  by iDestruct (is_dec_map_val_inj with "His_val0 His_val1") as %<-.
Qed.

(* used by clients who agree across the same digs. *)
Lemma is_plain_keys_inj vrf_pk plain0 plain1 hidden :
  is_plain_keys vrf_pk plain0 hidden -∗
  is_plain_keys vrf_pk plain1 hidden -∗
  ⌜plain0 = plain1⌝.
Proof.
  iNamedSuffix 1 "0". iNamedSuffix 1 "1". subst.
  by iDestruct (is_oflat_inj with "His_oflat0 His_oflat1") as %<-.
Qed.

(* inversion. *)

Local Lemma is_dec_map_label_invert vrf_pk map_label :
  ⊢ ∃ obj, is_dec_map_label vrf_pk obj map_label.
Proof.
  iDestruct cryptoffi.is_vrf_out_invert as (?) "$".
  naive_solver.
Qed.

Local Lemma is_dec_map_val_invert map_val :
  ⊢ ∃ obj, is_dec_map_val obj map_val.
Proof.
  iDestruct cryptoffi.is_hash_invert as (?) "$".
  naive_solver.
Qed.

Local Lemma is_oflat_invert vrf_pk hidden :
  ⊢ ∃ oflat, is_oflat vrf_pk oflat hidden.
Proof.
  iApply big_sepL2_invert.
  iIntros ([??]). simpl.
  iDestruct is_dec_map_label_invert as (?) "H0".
  iDestruct is_dec_map_val_invert as (?) "H1".
  iExists (_, _). iFrame "#".
Qed.

(* used by auditor.
to prove this, is_plain_keys can't require bijection. *)
Lemma is_plain_keys_invert vrf_pk hidden :
  ⊢ ∃ plain, is_plain_keys vrf_pk plain hidden.
Proof.
  iDestruct is_oflat_invert as (?) "$".
  naive_solver.
Qed.

(* monotonicity. *)

Lemma is_dec_map_label_det vrf_pk obj map_label0 map_label1 :
  is_dec_map_label vrf_pk (Some obj) map_label0 -∗
  is_dec_map_label vrf_pk (Some obj) map_label1 -∗
  ⌜map_label0 = map_label1⌝.
Proof. Admitted.

(* used by auditor. *)
(* NOTE: this lemma requires that pks0@uid@plain0 are prefix of pks1@uid@plain1.
moving pks0 "up the stack" is easier, since the stack only filters.
moving pks0 "down the stack" is more tricky.
first, we remember that pks0 passes filters0.
some of filters1 (e.g., decode_map_label) are same as filters0.
second, we prove that the remaining filters (e.g., get_contig)
are strictly more permissible. *)
Lemma is_plain_keys_over_sub vrf_pk hidden0 hidden1 plain0 plain1 :
  hidden0 ⊆ hidden1 →
  is_plain_keys vrf_pk plain0 hidden0 -∗
  is_plain_keys vrf_pk plain1 hidden1 -∗
  ⌜keys_sub plain0 plain1⌝.
Proof. Admitted.

(* "correctness", requiring bijectivity. *)

(* hidden is fully made up of contiguous versions.
i.e., hidden and the computed plain are bijective. *)
Definition is_contig (vrf_pk : list w8) (hidden : gmap (list w8) (list w8)) : iProp Σ.
Admitted.

(* used in server update. *)
Lemma is_plain_keys_add vrf_pk hidden plain uid kt_pk label val rand :
  let pks := plain !!! uid in
  is_plain_keys vrf_pk plain hidden -∗
  is_contig vrf_pk hidden -∗
  is_MapLabel vrf_pk uid (length pks) label -∗
  is_MapVal kt_pk rand val -∗
  let hidden' := <[label:=val]>hidden in
  let plain' := <[uid:=pks ++ [kt_pk]]>plain in
  is_plain_keys vrf_pk plain' hidden' ∗ is_contig vrf_pk hidden'.
Proof. Admitted.

End proof.
End ktcore.
