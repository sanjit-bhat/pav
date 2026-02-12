From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi safemarshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  serde.

(* TODO: upstream. *)
Lemma NoDup_omap {A B} (f : A → option B) l :
  (∀ x1 x2 y, x1 ∈ l → x2 ∈ l → f x1 = Some y → f x2 = Some y → x1 = x2) →
  NoDup l → NoDup (omap f l).
Proof.
  intros Hinj. induction 1 as [|x l ?? IH]; csimpl; [constructor|].
  ospecialize (IH _).
  { intros **.
    eapply Hinj; [..|done|done]; auto using list_elem_of_further. }
  destruct (f x) eqn:Hfx; [|done].
  apply NoDup_cons. split_and!; [|done].
  rewrite list_elem_of_omap. intros (?&?&Hfx').
  ospecialize (Hinj _ _ _ _ _ Hfx Hfx');
    auto using list_elem_of_here, list_elem_of_further.
  set_solver.
Qed.

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
Local Definition dec_map_labels_aux vrf_pk (hidden : gmap (list w8) (list w8)) :=
  omap (λ '(l, v), l' ← dec_map_label vrf_pk l; Some (l', v)) (map_to_list hidden).

Local Definition dec_map_labels vrf_pk hidden : gmap (w64 * nat) (list w8) :=
  list_to_map $ dec_map_labels_aux vrf_pk hidden.

Local Definition dec_map_vals interm : gmap (w64 * nat) (list w8) :=
  omap (λ v, dec_map_val v) interm.

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

Local Lemma dec_map_label_inj {vrf_pk label0 label1 dec} :
  dec_map_label vrf_pk label0 = Some dec →
  dec_map_label vrf_pk label1 = Some dec →
  label0 = label1.
Proof.
  rewrite /dec_map_label. intros **.
  simplify_option_eq.
  autorewrite with len in *.
  rename H0 into d0. rename H1 into d1.
  rename Heqo3 into Hvrf0. rename Heqo into Hvrf1.
  rename H into Heq_uid. rename H8 into Heq_ver.

  assert (d0 = d1) as <-.
  2: {
    apply cryptoffi.vrf_bij_r in Hvrf0, Hvrf1.
    by simplify_eq/=. }
  apply (f_equal u64_le) in Heq_uid.
  rewrite !le_to_u64_le in Heq_uid; [|len..].
  apply uint_nat_inj in Heq_ver.
  apply (f_equal u64_le) in Heq_ver.
  rewrite !le_to_u64_le in Heq_ver; [|len..].

  rewrite -(take_drop 8 d0).
  rewrite -(take_drop 8 d1).
  rewrite -(take_drop 8 (drop 8 d0)).
  rewrite -(take_drop 8 (drop 8 d1)).
  f_equal; [done|].
  f_equal; [done|].
  rewrite !drop_drop.
  rewrite !drop_ge; [done|word..].
Qed.

Local Lemma dec_map_labels_lift_elem {vrf_pk hidden interm dec val} :
  dec_map_labels_aux vrf_pk hidden = interm →
  (dec, val) ∈ interm →
  ∃ label, dec_map_label vrf_pk label = Some dec ∧ hidden !! label = Some val.
Proof.
  rewrite /dec_map_labels_aux. intros <- Hlook.
  apply list_elem_of_omap in Hlook as ([opt val']&Hlook&?).
  simplify_option_eq.
  apply elem_of_map_to_list in Hlook.
  naive_solver.
Qed.

Local Lemma dec_map_labels_drop_elem {vrf_pk hidden interm label val dec} :
  dec_map_labels_aux vrf_pk hidden = interm →
  hidden !! label = Some val →
  dec_map_label vrf_pk label = Some dec →
  (dec, val) ∈ interm.
Proof.
  rewrite /dec_map_labels_aux. intros <- Hlook Hdec.
  apply list_elem_of_omap.
  eexists (_, _).
  split.
  { by apply elem_of_map_to_list. }
  by rewrite Hdec.
Qed.

Local Lemma dec_map_labels_unique vrf_pk hidden interm :
  dec_map_labels_aux vrf_pk hidden = interm →
  (∀ label val0 val1, (label, val0) ∈ interm → (label, val1) ∈ interm → val0 = val1).
Proof.
  intros Hcomp ??? Helem0 Helem1.
  opose proof (dec_map_labels_lift_elem Hcomp Helem0) as (?&Hdec0&?).
  opose proof (dec_map_labels_lift_elem Hcomp Helem1) as (?&Hdec1&?).
  opose proof (dec_map_label_inj Hdec0 Hdec1) as ->.
  by simplify_eq/=.
Qed.

Local Lemma dec_map_labels_NoDup vrf_pk hidden :
  NoDup ((dec_map_labels_aux vrf_pk hidden).*1).
Proof.
  rewrite /dec_map_labels_aux.
  apply NoDup_fmap_fst.
  { by eapply dec_map_labels_unique. }
  apply NoDup_omap.
  2: { apply NoDup_map_to_list. }
  intros [??][??] **.
  simplify_option_eq.
  by opose proof (dec_map_label_inj Heqo0 Heqo) as ->.
Qed.

Local Lemma dec_map_labels_over_sub vrf_pk hidden0 hidden1 interm0 interm1 :
  dec_map_labels vrf_pk hidden0 = interm0 →
  dec_map_labels vrf_pk hidden1 = interm1 →
  hidden0 ⊆ hidden1 →
  interm0 ⊆ interm1.
Proof.
  rewrite /dec_map_labels. intros <- <- Hsub.
  apply map_subseteq_spec.
  intros [uid ver] val0 Hlook0.
  apply elem_of_list_to_map_2 in Hlook0.
  opose proof (dec_map_labels_lift_elem _ Hlook0) as (?&?&Hlook0'); [done|].
  apply elem_of_list_to_map_1.
  { apply dec_map_labels_NoDup. }
  eapply dec_map_labels_drop_elem; [done|idtac|done].
  by eapply lookup_weaken.
Qed.

Local Lemma dec_map_vals_over_sub prev0 prev1 next0 next1 :
  dec_map_vals prev0 = next0 →
  dec_map_vals prev1 = next1 →
  prev0 ⊆ prev1 →
  next0 ⊆ next1.
Proof. intros <- <- **. by apply map_omap_mono. Qed.

(* used by auditor. *)
(* NOTE: this lemma requires that pks0@uid@plain0 are prefix of pks1@uid@plain1.
moving pks0 "up the stack" is easier, since the stack only filters.
moving pks0 "down the stack" is more tricky.
we remember that pks0 passes filters0.
filter_Some is same in stack0 and stack1.
filter_contig in stack1 is more permissible than in stack0. *)
Lemma plain_inv_over_sub vrf_pk hidden0 hidden1 plain0 plain1 :
  plain_inv_func vrf_pk hidden0 = plain0 →
  plain_inv_func vrf_pk hidden1 = plain1 →
  hidden0 ⊆ hidden1 →
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
