From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi safemarshal.

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

(*
Definition is_MapLabel vrf_pk uid ver map_label :=
  let enc := MapLabel.pure_enc (MapLabel.mk' uid ver) in
  cryptoffi.vrf_func vrf_pk enc = Some map_label.

Lemma is_MapLabel_det pk uid ver map_label0 map_label1 :
  is_MapLabel pk uid ver map_label0 →
  is_MapLabel pk uid ver map_label1 →
  map_label0 = map_label1.
Proof.
  rewrite /is_MapLabel.
  intros H0 H1.
  iDestruct (cryptoffi.is_vrf_out_det with "H0 H1") as %->.
  done.
Qed.
*)

(* externalize [rand] bc some clients want to determ
derive [map_val] from [kt_pk]. *)
(*
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
*)

Local Definition dec_map_label vrf_pk map_label :=
  rem0 ← cryptoffi.vrf_inv_func vrf_pk map_label;
  guard (length rem0 ≥ 8);;
  let uid := le_to_u64 (take 8 rem0) in
  let rem1 := drop 8 rem0 in
  guard (length rem1 ≥ 8);;
  let ver := le_to_u64 (take 8 rem1) in
  let rem2 := drop 8 rem1 in
  guard (length rem2 = 0%nat);;
  Some (uid, uint.nat ver).

Local Definition dec_map_val map_val :=
  rem0 ← cryptoffi.hash_inv_func map_val;
  guard (length rem0 ≥ 8);;
  let pk_len := sint.nat (le_to_u64 (take 8 rem0)) in
  let rem1 := drop 8 rem0 in
  guard (length rem1 ≥ pk_len);;
  let pk := take pk_len rem1 in
  (* drop the remaining rand. we don't need that. *)
  Some (pk).

(* easier to reason in list form bc dec_map_label not inj.
might have mult labels that go to None.
however, after dropping None's, remaining (uid, ver) are unique. *)
Local Definition dec_map_labels vrf_pk hidden : gmap (w64 * nat) (list w8) :=
  let odec := (λ '(l, v), (dec_map_label vrf_pk l, v)) <$> map_to_list hidden in
  let dec := omap (λ '(ol, v), l ← ol; Some (l, v)) odec in
  list_to_map dec.

Local Definition dec_map_vals interm : gmap (w64 * nat) (list w8) :=
  omap (λ v, pk ← dec_map_val v; Some pk) interm.

Local Fixpoint get_contig (m_uid : gmap nat (list w8)) ver fuel :=
  match fuel with 0%nat => [] | S fuel' =>
  match m_uid !! ver with None => [] | Some pk =>
  pk :: get_contig m_uid (S ver) fuel' end end.

Local Definition filter_contig mapped : gmap w64 (list (list w8)) :=
  (* size is simple upper bound on max ver. *)
  (λ m_uid, get_contig m_uid 0 (size m_uid)) <$> mapped.

Definition plain_inv_func vrf_pk hidden :=
  filter_contig $ gmap_curry $ dec_map_vals $ dec_map_labels vrf_pk hidden.

(* monotonicity. *)

Lemma dec_map_label_inj vrf_pk label0 label1 :
  dec_map_label vrf_pk label0 = dec_map_label vrf_pk label1 →
  is_Some (dec_map_label vrf_pk label0) →
  label0 = label1.
Proof.
  rewrite /dec_map_label.
  intros ?[??].
  simplify_option_eq.
  assert (H1 = H0) as <-.
  2: {
    apply cryptoffi.vrf_bij_r in Heqo, Heqo3.
    by simplify_eq/=. }
  autorewrite with len in *.

  (* TODO: seal le_to_u64 to avoid [inversion] extracting
  [Naive.unsigned] from [le_to_u64 bs0 = le_to_u64 bs1]. *)
  assert (le_to_u64 (take 8 H1) = le_to_u64 (take 8 H0)) as Heq.
  { admit. }
  apply (f_equal u64_le) in Heq.
  rewrite !le_to_u64_le in Heq; [|len..].

  remember (le_to_u64 (take 8 (drop 8 H1))) as ver0.
  remember (le_to_u64 (take 8 (drop 8 H0))) as ver1.
  replace ver0 with ver1 in * by word.
  subst.
  apply (f_equal u64_le) in Heqver1.
  rewrite !le_to_u64_le in Heqver1; [|len..].

  rewrite -(take_drop 8 H1).
  rewrite -(take_drop 8 H0).
  rewrite -(take_drop 8 (drop 8 H1)).
  rewrite -(take_drop 8 (drop 8 H0)).
  f_equal; [done|].
  f_equal; [done|].
  rewrite !drop_drop.
  rewrite !drop_ge; [done|word..].
Admitted.

Lemma dec_map_labels_over_sub vrf_pk hidden0 hidden1 interm0 interm1 :
  hidden0 ⊆ hidden1 →
  dec_map_labels vrf_pk hidden0 = interm0 →
  dec_map_labels vrf_pk hidden1 = interm1 →
  interm0 ⊆ interm1.
Proof.
  rewrite /dec_map_labels.
  intros Hsub <- <-.
  apply map_subseteq_spec.
  intros [uid ver] val0 Hlook0.
  apply elem_of_list_to_map_2 in Hlook0.
  apply list_elem_of_omap in Hlook0 as ([opt val0']&Hlook0&?).
  destruct opt as [[??]|]; simplify_eq/=.
  apply list_elem_of_fmap in Hlook0 as ([label0 val0']&Ht&Hlook0).
  inv Ht as [Hdec0]. rename val0' into val0.
  apply elem_of_map_to_list in Hlook0.
  opose proof (lookup_weaken _ _ _ _ Hlook0 Hsub) as Hlook1.

  apply elem_of_list_to_map_1'.
  - intros val1 Hlook2.
    apply list_elem_of_omap in Hlook2 as ([opt val1']&Hlook2&?).
    destruct opt as [[??]|]; simplify_eq/=.
    apply list_elem_of_fmap in Hlook2 as ([label1 val1']&Ht&Hlook2).
    inv Ht as [Hdec1]. rename val1' into val1.
    apply elem_of_map_to_list in Hlook2.
    rewrite Hdec0 in Hdec1.
    apply dec_map_label_inj in Hdec1; [|done].
    by simplify_eq/=.
  - apply list_elem_of_omap.
    eexists (Some (_, _), _).
    split; [|done].
    apply list_elem_of_fmap.
    eexists (_, _).
    split; [by f_equal|].
    by apply elem_of_map_to_list.
Qed.

(* used by auditor. *)
(* NOTE: this lemma requires that pks0@uid@plain0 are prefix of pks1@uid@plain1.
moving pks0 "up the stack" is easier, since the stack only filters.
moving pks0 "down the stack" is more tricky.
we remember that pks0 passes filters0.
filter_Some is same in stack0 and stack1.
filter_contig in stack1 is more permissible than in stack0. *)
Lemma plain_inv_over_sub vrf_pk hidden0 hidden1 plain0 plain1 :
  hidden0 ⊆ hidden1 →
  plain_inv_func vrf_pk hidden0 = plain0 →
  plain_inv_func vrf_pk hidden1 = plain1 →
  keys_sub plain0 plain1.
Proof. Admitted.

(* "correctness", requiring bijectivity. *)

(* hidden is fully made up of contiguous versions.
i.e., hidden and the computed plain are bijective. *)
Definition is_contig (vrf_pk : list w8) (hidden : gmap (list w8) (list w8)) : iProp Σ.
Admitted.

(* used in server update. *)
(*
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
*)

End proof.
End ktcore.
