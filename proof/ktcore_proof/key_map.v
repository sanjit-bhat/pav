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

(* TODO: upstream. *)
Lemma map_seq_subseteq {A} start (vs : list A) (m : gmap _ _) :
  (∀ i v, vs !! i = Some v → m !! (start + i)%nat = Some v) ↔
  map_seq start vs ⊆ m.
Proof.
  split.
  - intros Hvs.
    apply map_subseteq_spec.
    intros ?? Hlook.
    apply lookup_map_seq_Some in Hlook as [? Hlook].
    ospecialize (Hvs _ _ _); [done|].
    by replace (_ + _)%nat with i in Hvs by lia.
  - intros Hseq ?? Hlook.
    eapply lookup_weaken; [|done].
    by apply lookup_map_seq_Some_inv.
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
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

(** inverse computation from hidden to plain.
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

Notation map_curry := (map_curry (M1:=gmap _) (M2:=gmap _)).

Definition plain_inv_fn vrf_pk hidden :=
  filter_contig $ map_curry $ dec_map_vals $ dec_map_labels vrf_pk hidden.

(** forward relation - bijection between plain and hidden. *)

Definition map_label_fn vrf_pk uid ver map_label :=
  let enc := MapLabel.pure_enc (MapLabel.mk' uid ver) in
  cryptoffi.vrf_fn vrf_pk enc = Some map_label.

Definition map_val_fn kt_pk rand map_val :=
  let enc := CommitOpen.pure_enc (CommitOpen.mk' kt_pk rand) in
  cryptoffi.hash_fn enc = Some map_val ∧
  safemarshal.Slice1D.valid kt_pk.

Local Definition in_hidden vrf_pk (hidden : gmap (list w8) (list w8)) uid ver pk :=
  ∃ map_label map_val,
  map_label_inv_fn vrf_pk map_label = Some (uid, ver) ∧
  map_val_inv_fn map_val = Some pk ∧
  hidden !! map_label = Some map_val.

Local Definition in_plain vrf_pk (plain : gmap w64 (list $ list w8)) map_label map_val :=
  ∃ uid ver pk pks,
  (* arbitrarily using inv version of map_label_fn. both are equiv. *)
  map_label_inv_fn vrf_pk map_label = Some (uid, ver) ∧
  map_val_inv_fn map_val = Some pk ∧
  plain !! uid = Some pks ∧
  pks !! ver = Some pk.

Local Definition plain_to_hidden vrf_pk (plain : gmap w64 (list $ list w8))
    (hidden : gmap (list w8) (list w8)) :=
  map_Forall
    (λ uid pks,
      length pks ≠ 0%nat ∧
      (∀ ver pk, pks !! ver = Some pk → in_hidden vrf_pk hidden uid ver pk))
    plain.

Local Definition hidden_to_plain vrf_pk (hidden : gmap (list w8) (list w8))
    (plain : gmap w64 (list $ list w8)) :=
  map_Forall
    (λ map_label map_val, in_plain vrf_pk plain map_label map_val)
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

(** "correctness". this requires a bijection (modulo empty uid's)
between plain and hidden. *)

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

(* analogous to map_label_fn_has_inv, but for CommitOpen / hash instead of
   MapLabel / vrf. proof strategy:
   1. hash_bij_l to invert hash_fn.
   2. simplify_option_eq to process the option binds + guards.
      leaves 3 goals: the main eq, and 2 guard side conditions.
   3. for the main eq: simplify take/drop of the CommitOpen encoding
      (two layers of app: outer (Slice1D pk ++ Slice1D rand), inner
      (u64_le len ++ data)), then use Slice1D.valid to convert
      sint.nat (W64 (length kt_pk)) to length kt_pk.
   STUCK: after simplify_option_eq, take_app_le can't match because
   lia doesn't know app_length. the side conditions need
   `rewrite length_app u64_le_length; lia` but the exact goal shape
   is hard to predict without interactive exploration. *)
Local Lemma map_val_fn_has_inv kt_pk rand map_val :
  map_val_fn kt_pk rand map_val →
  map_val_inv_fn map_val = Some kt_pk.
Proof.
  rewrite /map_val_fn /map_val_inv_fn /CommitOpen.pure_enc
    /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc /=.
  intros [?%cryptoffi.hash_bij_l Hvalid].
  rewrite /safemarshal.Slice1D.valid in Hvalid.
  simplify_option_eq; try done.
  (* goal 1: main eq. goal 2,3: guard side conditions.
     all involve take/drop of (u64_le _ ++ kt_pk) ++ (u64_le _ ++ rand). *)
Admitted.

(* move vals thru plain_inv_fn (in both directions). *)

Local Lemma get_contig_out_lookup {m fuel pks} ver pk :
  get_contig m 0%nat fuel = pks →
  pks !! ver = Some pk →
  m !! ver = Some pk.
Proof.
  intros Hfn Hlook_pks.
  remember 0%nat as scan_ver.
  assert (ver ≥ scan_ver); [lia|].
  (* lookup idx in pks "decreases" with each scan_ver. *)
  replace ver with (ver - scan_ver)%nat in Hlook_pks by lia.
  clear Heqscan_ver.
  generalize dependent scan_ver. revert pks ver.
  induction fuel; simpl; intros ??? Hfn Hlook_pks ?.
  { list_simplifier. }
  case_match; subst; [|list_simplifier].
  destruct (decide (ver = scan_ver)).
  { replace (_ - _)%nat with 0%nat in Hlook_pks by lia.
    by simplify_eq/=. }
  rewrite lookup_cons_ne_0 in Hlook_pks; [|lia].
  replace (pred _) with (ver - S scan_ver)%nat in Hlook_pks by lia.
  eapply IHfuel; [done..|lia].
Qed.

Local Lemma inv_fn_out_lookup {vrf_pk plain hidden uid pks} ver pk :
  plain_inv_fn vrf_pk hidden = plain →
  plain !! uid = Some pks →
  pks !! ver = Some pk →
  in_hidden vrf_pk hidden uid ver pk.
Proof.
  rewrite /plain_inv_fn. intros Hfn Hlook_plain Hlook_pks.
  rewrite /filter_contig in Hfn.
  apply (f_equal (lookup uid)) in Hfn.
  rewrite {}Hlook_plain in Hfn. clear plain.
  apply lookup_fmap_Some in Hfn as (m_uid&?&Hfn).
  opose proof (get_contig_out_lookup _ _ _ _) as  Hlook_uid; [done..|].
  rename Hfn into Hfn'.
  opose proof (lookup_map_curry _ uid ver) as Hfn.
  setoid_rewrite Hfn' in Hfn. simpl in *.
  rewrite Hlook_uid in Hfn. symmetry in Hfn. clear Hfn'.
  rewrite /dec_map_vals in Hfn.
  apply lookup_omap_Some in Hfn as (?&?&Hfn).
  rewrite /dec_map_labels in Hfn.
  apply elem_of_list_to_map_2 in Hfn.
  rewrite /dec_map_labels_aux in Hfn.
  apply list_elem_of_omap in Hfn as ([??]&Hfn&?).
  simplify_option_eq.
  apply elem_of_map_to_list in Hfn.
  rewrite /in_hidden.
  naive_solver.
Qed.

(* helpers for inv_fn_in_lookup. *)
Local Lemma to_contig_in_lookup {vrf_pk m0 m1} uid ver pk :
  map_curry $ dec_map_vals $ dec_map_labels vrf_pk m0 = m1 →
  in_hidden vrf_pk m0 uid ver pk →
  m1 !! uid ≫= (!!) ver = Some pk.
Proof.
  rewrite /in_hidden. intros <- (?&?&?&?&Hfn).
  rewrite lookup_map_curry.
  rewrite /dec_map_vals.
  rewrite lookup_omap_Some.
  eexists. split; try done.
  rewrite /dec_map_labels.
  apply elem_of_list_to_map_1.
  { apply dec_map_labels_NoDup. }
  rewrite /dec_map_labels_aux.
  rewrite list_elem_of_omap.
  eexists (_, _). split.
  2: { by simplify_option_eq. }
  by rewrite elem_of_map_to_list.
Qed.

Local Lemma get_contig_in_lookup m pks :
  map_seq 0 pks ⊆ m →
  get_contig m 0%nat (length pks) = pks.
Proof.
  remember 0%nat as scan_ver.
  clear Heqscan_ver.
  revert scan_ver.
  induction pks; simpl; intros * Hpks; try done.
  eapply lookup_weaken in Hpks as ?.
  2: { by erewrite lookup_insert_eq. }
  case_match; try done.
  simplify_eq/=. f_equal.
  apply IHpks.
  rewrite insert_union_singleton_l in Hpks.
  etrans; [|done].
  apply map_union_subseteq_r.
  apply map_disjoint_singleton_l.
  apply map_seq_cons_disjoint.
Qed.

Local Lemma size_approx (m : gmap _ (list w8)) pks :
  map_seq 0 pks ⊆ m →
  (length pks ≤ size m)%nat.
Proof.
  intros Hpks%subseteq_dom.
  rewrite dom_seq in Hpks.
  apply subseteq_size in Hpks.
  by rewrite size_set_seq -map_size_dom in Hpks.
Qed.

Local Lemma inv_fn_on_pks {vrf_pk plain0 plain1 hidden} uid pks :
  is_plain vrf_pk plain0 hidden →
  plain_inv_fn vrf_pk hidden = plain1 →
  plain0 !! uid = Some pks →
  plain1 !! uid = Some pks.
Proof.
  intros Hbij <- Hlook.
  rename plain0 into plain.
  rewrite /plain_inv_fn.
  rewrite /filter_contig.
  apply lookup_fmap_Some.
  remember (map_curry _) as inv_fn.
  assert (∃ x, inv_fn !! uid = Some x) as (m&?); subst.
  { odestruct (proj1 Hbij _ _ _) as (?&Hpks); [done|].
    destruct pks; try done.
    ospecialize (Hpks 0%nat _ _); [done|].
    opose proof (to_contig_in_lookup _ _ _ _ _) as Hlook_fn; [done..|].
    apply bind_Some in Hlook_fn as (?&?&?).
    naive_solver. }
  eexists. split; [|done].

  assert (map_seq 0 pks ⊆ m).
  { (* transfer pks from plain. *)
    admit. }

  opose proof (get_contig_add_fuel m 0 _ _ _) as Hpref.
  { by apply size_approx. }
  rewrite get_contig_in_lookup in Hpref; [|done].
  destruct Hpref as ([]&?).
  { by list_simplifier. }

  (* contradict versions bigger than pks. *)
  exfalso.
  opose proof (inv_fn_out_lookup (length pks) _ _ _ _) as (?&?&?); [done|..].
  { apply lookup_fmap_Some. naive_solver. }
  { by apply list_lookup_middle. }
  destruct_and!.
  odestruct (proj2 Hbij _ _ _) as (?&?&?&?&?&?&?&Hlook_pks); [done|].
  simplify_eq/=.
  apply lookup_lt_Some in Hlook_pks.
  lia.
Admitted.

Local Lemma inv_fn_non_empty_pks {vrf_pk plain hidden} uid pks :
  plain_inv_fn vrf_pk hidden = plain →
  plain !! uid = Some pks →
  length pks ≠ 0%nat.
Proof. Admitted.

Lemma is_plain_has_inv vrf_pk plain hidden :
  is_plain vrf_pk plain hidden →
  plain_inv_fn vrf_pk hidden = plain.
Proof.
  rename plain into plain0. intros Hbij.
  remember (plain_inv_fn _ _) as plain1.
  symmetry. apply map_eq. intros uid.
  destruct (plain0 !! uid) as [pks0|] eqn:Hlook0.
  { by erewrite inv_fn_on_pks. }
  destruct (plain1 !! uid) as [[]|] eqn:Hlook1; try done; exfalso.
  { by opose proof (inv_fn_non_empty_pks _ _ _ _) as ?. }
  opose proof (inv_fn_out_lookup 0 _ _ _ _) as (?&?&?); [done..|].
  destruct_and!.
  odestruct (proj2 Hbij _ _ _) as (?&?&?&?&?&?&?&?); [done|].
  simplify_eq/=.
Qed.

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
