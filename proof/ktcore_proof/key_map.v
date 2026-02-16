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

Section curry_mono.
  Context `{FinMap K1 M1, FinMap K2 M2, FinMap (K1 * K2) MC} {A : Type}.
  Notation map_curry := (map_curry (M1:=M1) (M2:=M2)).
  Notation map_uncurry := (map_uncurry (M12:=MC)).

  Definition curry_sub : relation (M1 (M2 A)) :=
    map_included (λ _, (⊆)).

  Local Lemma lookup_map_curry_weaken (m0 m1 : MC A) i mi0 :
    m0 ⊆ m1 →
    map_curry m0 !! i = Some mi0 →
    ∀ j v, mi0 !! j = Some v → map_curry m1 !! i ≫= (.!! j) = Some v.
  Proof using All.
    intros Hsub Hi0 j v Hj. rewrite lookup_map_curry.
    eapply lookup_weaken; [|done]. by rewrite -lookup_map_curry Hi0.
  Qed.

  (* TODO: maybe upstream. *)
  Lemma map_curry_mono (m0 m1 : MC A) :
    m0 ⊆ m1 →
    curry_sub (map_curry m0) (map_curry m1).
  Proof using All.
    intros Hsub i.
    destruct (map_curry m0 !! i) as [mi0|] eqn:Hi0;
      [|by destruct (map_curry m1 !! i)].
    pose proof (lookup_map_curry_weaken _ _ _ _ Hsub Hi0) as Hlift.
    destruct (map_curry m1 !! i) as [mi1|]; simpl.
    - apply map_subseteq_spec. intros j v Hj. exact (Hlift _ _ Hj).
    - destruct (map_choose _ (map_curry_non_empty _ _ _ Hi0)) as (j & v & Hj).
      pose proof (Hlift _ _ Hj). done.
  Qed.
End curry_mono.

Section map.
  Context `{FinMap K M} {A B : Type}.
  (* TODO: upstream. *)
  Lemma map_included_alt (R : K → A → B → Prop) (m1 : M A) (m2 : M B) :
    map_included R m1 m2 ↔
      (∀ k a, m1 !! k = Some a → ∃ b, m2 !! k = Some b ∧ R k a b).
  Proof.
    rewrite /map_included /map_relation /option_relation. split.
    - intros Hincl ?? Hlook.
      specialize (Hincl k).
      rewrite Hlook in Hincl.
      case_match; naive_solver.
    - intros Hincl k.
      repeat case_match; naive_solver.
  Qed.
End map.

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

(** backward computation from hidden to plain.
must always succeed for invert capability. *)

Local Definition map_label_inv_fn vrf_pk map_label :=
  rem0 ← cryptoffi.vrf_inv_fn vrf_pk map_label;
  guard (length rem0 ≥ 8);;
  let uid := le_to_u64 (take 8 rem0) in
  let rem1 := drop 8 rem0 in
  guard (length rem1 ≥ 8);;
  let ver := le_to_u64 (take 8 rem1) in
  let rem2 := drop 8 rem1 in
  guard (length rem2 = 0%nat);;
  Some (uid, uint.nat ver).

Local Definition map_val_inv_fn map_val :=
  rem0 ← cryptoffi.hash_inv_fn map_val;
  guard (length rem0 ≥ 8);;
  let pk_len := sint.nat (le_to_u64 (take 8 rem0)) in
  let rem1 := drop 8 rem0 in
  guard (length rem1 ≥ pk_len);;
  let pk := take pk_len rem1 in
  (* drop the remaining rand. we don't need that. *)
  Some (pk).

(* easier to reason in list form bc map_label_inv_fn not inj.
might have mult labels that go to None. *)
Local Definition dec_map_labels_aux vrf_pk (m : gmap (list w8) (list w8)) :=
  omap (λ '(l, v), l' ← map_label_inv_fn vrf_pk l; Some (l', v)) (map_to_list m).

Local Definition dec_map_labels vrf_pk m : gmap (w64 * nat) (list w8) :=
  list_to_map $ dec_map_labels_aux vrf_pk m.

Local Definition dec_map_vals m : gmap (w64 * nat) (list w8) :=
  omap (λ v, map_val_inv_fn v) m.

Local Fixpoint get_contig (m : gmap nat (list w8)) ver fuel :=
  match fuel with 0%nat => [] | S fuel' =>
  match m !! ver with None => [] | Some pk =>
  pk :: get_contig m (S ver) fuel' end end.

Local Definition filter_contig m : gmap w64 (list (list w8)) :=
  (* size is simple upper bound on max ver. *)
  (λ m_uid, get_contig m_uid 0 (size m_uid)) <$> m.

Definition plain_inv_fn vrf_pk hidden :=
  filter_contig $ map_curry (M1:=gmap _) $
    dec_map_vals $ dec_map_labels vrf_pk hidden.

(** forward relation - bijection between plain and hidden. *)

Definition map_label_fn vrf_pk uid ver map_label :=
  let enc := MapLabel.pure_enc (MapLabel.mk' uid ver) in
  cryptoffi.vrf_fn vrf_pk enc = Some map_label.

Definition map_val_fn kt_pk rand map_val :=
  let enc := CommitOpen.pure_enc (CommitOpen.mk' kt_pk rand) in
  cryptoffi.hash_fn enc = Some map_val ∧
  safemarshal.Slice1D.valid kt_pk.

Definition plain_to_hidden vrf_pk (plain : gmap w64 (list $ list w8))
    (hidden : gmap (list w8) (list w8)) :=
  map_Forall
    (λ uid pks,
      length pks ≠ 0%nat ∧
      (∀ (ver : nat) pk,
        pks !! ver = Some pk →
        ∃ map_label rand map_val,
          map_label_fn vrf_pk uid (W64 ver) map_label ∧
          map_val_fn pk rand map_val ∧
          hidden !! map_label = Some map_val))
    plain.

Definition hidden_to_plain vrf_pk (hidden : gmap (list w8) (list w8))
    (plain : gmap w64 (list $ list w8)) :=
  map_Forall
    (λ map_label map_val,
      ∃ uid (ver : nat) pk pks,
        (* arbitrarily using map_label fn vs. inv fn. they are equiv. *)
        map_label_inv_fn vrf_pk map_label = Some (uid, ver) ∧
        map_val_inv_fn map_val = Some pk ∧
        plain !! uid = Some pks ∧
        pks !! ver = Some pk)
    hidden.

Definition is_plain vrf_pk plain hidden :=
  plain_to_hidden vrf_pk plain hidden ∧
  hidden_to_plain vrf_pk hidden plain.

(** monotonicity. *)

Local Lemma map_label_inv_fn_inj {vrf_pk label0 label1 dec} :
  map_label_inv_fn vrf_pk label0 = Some dec →
  map_label_inv_fn vrf_pk label1 = Some dec →
  label0 = label1.
Proof.
  rewrite /map_label_inv_fn. intros **.
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

Local Lemma dec_map_labels_lift_elem {vrf_pk m_prev m_next dec val} :
  dec_map_labels_aux vrf_pk m_prev = m_next →
  (dec, val) ∈ m_next →
  ∃ label, map_label_inv_fn vrf_pk label = Some dec ∧ m_prev !! label = Some val.
Proof.
  rewrite /dec_map_labels_aux. intros <- Hlook.
  apply list_elem_of_omap in Hlook as ([opt val']&Hlook&?).
  simplify_option_eq.
  apply elem_of_map_to_list in Hlook.
  naive_solver.
Qed.

Local Lemma dec_map_labels_drop_elem {vrf_pk m_prev m_next label val dec} :
  dec_map_labels_aux vrf_pk m_prev = m_next →
  m_prev !! label = Some val →
  map_label_inv_fn vrf_pk label = Some dec →
  (dec, val) ∈ m_next.
Proof.
  rewrite /dec_map_labels_aux. intros <- Hlook Hdec.
  apply list_elem_of_omap.
  eexists (_, _).
  split.
  { by apply elem_of_map_to_list. }
  by rewrite Hdec.
Qed.

Local Lemma dec_map_labels_unique vrf_pk m_prev m_next :
  dec_map_labels_aux vrf_pk m_prev = m_next →
  (∀ label val0 val1, (label, val0) ∈ m_next → (label, val1) ∈ m_next → val0 = val1).
Proof.
  intros Hcomp ??? Helem0 Helem1.
  opose proof (dec_map_labels_lift_elem Hcomp Helem0) as (?&Hdec0&?).
  opose proof (dec_map_labels_lift_elem Hcomp Helem1) as (?&Hdec1&?).
  opose proof (map_label_inv_fn_inj Hdec0 Hdec1) as ->.
  by simplify_eq/=.
Qed.

Local Lemma dec_map_labels_NoDup vrf_pk m :
  NoDup ((dec_map_labels_aux vrf_pk m).*1).
Proof.
  rewrite /dec_map_labels_aux.
  apply NoDup_fmap_fst.
  { by eapply dec_map_labels_unique. }
  apply NoDup_omap.
  2: { apply NoDup_map_to_list. }
  intros [??][??] **.
  simplify_option_eq.
  by opose proof (map_label_inv_fn_inj Heqo0 Heqo) as ->.
Qed.

Local Lemma dec_map_labels_mono vrf_pk m0 m1 :
  m0 ⊆ m1 →
  dec_map_labels vrf_pk m0 ⊆ dec_map_labels vrf_pk m1.
Proof.
  rewrite /dec_map_labels. intros ?.
  apply map_subseteq_spec.
  intros [uid ver] val0 Hlook0.
  apply elem_of_list_to_map_2 in Hlook0.
  opose proof (dec_map_labels_lift_elem _ Hlook0) as (?&?&Hlook0'); [done|].
  apply elem_of_list_to_map_1.
  { apply dec_map_labels_NoDup. }
  eapply dec_map_labels_drop_elem; [done|idtac|done].
  by eapply lookup_weaken.
Qed.

Local Lemma get_contig_mono m0 m1 ver fuel :
  m0 ⊆ m1 →
  get_contig m0 ver fuel `prefix_of` get_contig m1 ver fuel.
Proof.
  intros Hsub.
  revert ver. induction fuel; simpl; [done|].
  intros. destruct (m0 !! ver) eqn:Hlook.
  2: { apply prefix_nil. }
  opose proof (lookup_weaken _ _ _ _ Hlook Hsub) as ->.
  apply prefix_cons.
  naive_solver.
Qed.

Local Lemma get_contig_add_fuel m ver fuel fuel' :
  (fuel ≤ fuel')%nat →
  get_contig m ver fuel `prefix_of` get_contig m ver fuel'.
Proof.
  revert ver fuel'. induction fuel; simpl.
  { intros. apply prefix_nil. }
  intros. destruct fuel'; [lia|]. simpl.
  case_match; try done.
  apply prefix_cons.
  apply IHfuel. lia.
Qed.

Local Lemma filter_contig_mono m0 m1 :
  curry_sub (M1:=gmap _) m0 m1 →
  keys_sub (filter_contig m0) (filter_contig m1).
Proof.
  rewrite /curry_sub /keys_sub !map_included_alt. intros Hsub.
  rewrite /filter_contig.
  intros uid pks Hlook.
  rewrite lookup_fmap in Hlook.
  simplify_option_eq. rename H into m_uid0.
  odestruct (Hsub _ _ _) as (m_uid1&?&?); [done|].
  opose proof (get_contig_mono m_uid0 m_uid1 0 (size m_uid0) _) as Hpref0; [done|].
  opose proof (get_contig_add_fuel m_uid1 0 (size m_uid0) (size m_uid1) _) as Hpref1.
  { by apply map_subseteq_size. }
  eexists. split.
  { rewrite lookup_fmap. by simplify_option_eq. }
  by trans (get_contig m_uid1 0 (size m_uid0)).
Qed.

(* used by auditor. *)
Lemma plain_inv_mono vrf_pk m0 m1 :
  m0 ⊆ m1 →
  keys_sub (plain_inv_fn vrf_pk m0) (plain_inv_fn vrf_pk m1).
Proof.
  rewrite /plain_inv_fn. intros Hsub.
  apply filter_contig_mono.
  apply map_curry_mono.
  apply map_omap_mono.
  by apply dec_map_labels_mono.
Qed.

(** "correctness". this requires a bijection between plain and hidden,
modulo plain maps with empty pk lists. *)

Local Lemma map_label_fn_has_inv vrf_pk uid ver map_label :
  map_label_fn vrf_pk uid ver map_label →
  map_label_inv_fn vrf_pk map_label = Some (uid, uint.nat ver).
Proof.
  rewrite /map_label_fn /map_label_inv_fn /MapLabel.pure_enc /safemarshal.w64.pure_enc /=.
  intros ?%cryptoffi.vrf_bij_l.
  simplify_option_eq; try done.
  all: try (autorewrite with len in *; lia).
  pose proof (u64_le_length uid).
  pose proof (u64_le_length ver).
  rewrite take_app_le; [|lia].
  rewrite take_ge; [|lia].
  rewrite drop_app_le; [|lia].
  rewrite drop_ge; [|lia]. simpl.
  rewrite take_ge; [|lia].
  rewrite !u64_le_to_word. done.
Qed.

Local Lemma map_val_fn_has_inv kt_pk rand map_val :
  map_val_fn kt_pk rand map_val →
  map_val_inv_fn map_val = Some kt_pk.
Proof. Admitted.

Local Definition pks_in_m_uid (m : gmap nat (list w8)) pks :=
  ∀ (ver : nat) pk, pks !! ver = Some pk → m !! ver = Some pk ∧
  m !! (length pks) = None.

Local Lemma get_contig_on_pks m pks :
  pks_in_m_uid m pks →
  get_contig m 0%nat (size m) = pks.
Proof. Admitted.

Local Lemma filter_contig_on_pks m m_uid uid pks :
  m !! uid = Some m_uid →
  pks_in_m_uid m_uid pks →
  filter_contig m !! uid = Some pks.
Proof. Admitted.

Lemma is_plain_has_inv vrf_pk plain hidden :
  is_plain vrf_pk plain hidden →
  plain_inv_fn vrf_pk hidden = plain.
Proof. Admitted.

(* used in server update. *)
Lemma plain_insert vrf_pk plain hidden uid (ver : w64) pk rand map_label map_val :
  let pks := plain !!! uid in
  is_plain vrf_pk plain hidden →
  map_label_fn vrf_pk uid ver map_label →
  uint.nat ver = length pks →
  map_val_fn pk rand map_val →
  let plain' := <[uid:=pks ++ [pk]]>plain in
  let hidden' := <[map_label:=map_val]>hidden in
  is_plain vrf_pk plain' hidden'.
Proof. Admitted.

End proof.
End ktcore.
