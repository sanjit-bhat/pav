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

(* TODO: upstream. *)
Lemma map_included_alt `{FinMap K M} {A B : Type}
    (R : K → A → B → Prop) (m1 : M A) (m2 : M B) :
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
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

(** [plain_inv_fn] definition. *)

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
  omap map_val_inv_fn m.

Local Fixpoint get_contig_aux (m : gmap nat (list w8)) ver fuel :=
  match fuel with 0%nat => [] | S fuel' =>
  match m !! ver with None => [] | Some pk =>
  pk :: get_contig_aux m (S ver) fuel' end end.

(* size is simple upper bound on max ver. *)
Local Definition get_contig m := get_contig_aux m 0 (size m).

Local Definition filter_contig m : gmap w64 (list (list w8)) :=
  omap
    (λ m_uid,
      let pks := get_contig m_uid in
      guard (length pks ≠ 0%nat);;
      Some pks)
    m.

Notation map_curry := (map_curry (M1:=gmap _) (M2:=gmap _)).

(* inversion from hidden to plain.
inversion must succeed on every hidden, so we make this a function. *)
Definition plain_inv_fn vrf_pk hidden :=
  filter_contig $ map_curry $ dec_map_vals $ dec_map_labels vrf_pk hidden.
#[global] Opaque plain_inv_fn.
#[local] Transparent plain_inv_fn.

(** [is_plain] definition. *)

Definition in_hidden vrf_pk (hidden : gmap (list w8) (list w8)) uid ver opt_pk :=
  ∃ map_label,
  map_label_inv_fn vrf_pk map_label = Some (uid, ver) ∧
  match opt_pk with
  | None =>
    hidden !! map_label = None
  | Some pk =>
    ∃ map_val,
    map_val_inv_fn map_val = Some pk ∧
    hidden !! map_label = Some map_val
  end.
#[global] Opaque in_hidden.
#[local] Transparent in_hidden.

Local Definition pks_in_hidden vrf_pk hidden uid (pks : list _) :=
  ∀ ver pk, pks !! ver = Some pk → in_hidden vrf_pk hidden uid ver (Some pk).

Local Definition in_plain vrf_pk (plain : gmap w64 (list $ list w8)) map_label map_val :=
  ∃ uid ver pk pks,
  map_label_inv_fn vrf_pk map_label = Some (uid, ver) ∧
  map_val_inv_fn map_val = Some pk ∧
  plain !! uid = Some pks ∧
  pks !! ver = Some pk.

Local Definition plain_to_hidden vrf_pk (plain : gmap w64 (list $ list w8))
    (hidden : gmap (list w8) (list w8)) :=
  map_Forall
    (λ uid pks, length pks ≠ 0%nat ∧ pks_in_hidden vrf_pk hidden uid pks)
    plain.

Local Definition hidden_to_plain vrf_pk (hidden : gmap (list w8) (list w8))
    (plain : gmap w64 (list $ list w8)) :=
  map_Forall
    (λ map_label map_val, in_plain vrf_pk plain map_label map_val)
    hidden.

(* bijection (modulo empty uid's) between plain and hidden.
required to prove "correctness" (see below). *)
Definition is_plain vrf_pk plain hidden :=
  plain_to_hidden vrf_pk plain hidden ∧
  hidden_to_plain vrf_pk hidden plain.
#[global] Opaque is_plain.
#[local] Transparent is_plain.

(** out->in reasoning for [plain_inv_fn]. *)

Local Lemma dec_map_labels_out_lookup {vrf_pk m_prev m_next dec val} :
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

Local Lemma get_contig_out_lookup {m pks} ver pk :
  get_contig m = pks →
  pks !! ver = Some pk →
  m !! ver = Some pk.
Proof.
  rewrite /get_contig. intros Hfn Hlook_pks.
  remember 0%nat as scan_ver.
  assert (ver ≥ scan_ver); [lia|].
  (* lookup idx in pks "decreases" with each scan_ver. *)
  replace ver with (ver - scan_ver)%nat in Hlook_pks by lia.
  clear Heqscan_ver.
  remember (size m) as fuel. clear Heqfuel.
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

Lemma inv_fn_out_lookup {vrf_pk plain hidden uid pks} ver pk :
  plain_inv_fn vrf_pk hidden = plain →
  plain !! uid = Some pks →
  pks !! ver = Some pk →
  in_hidden vrf_pk hidden uid ver (Some pk).
Proof.
  rewrite /plain_inv_fn. intros Hfn Hlook_plain Hlook_pks.
  rewrite /filter_contig in Hfn.
  apply (f_equal (lookup uid)) in Hfn.
  rewrite {}Hlook_plain in Hfn. clear plain.
  apply lookup_omap_Some in Hfn as (m_uid&?&Hfn).
  simplify_option_eq.
  opose proof (get_contig_out_lookup _ _ _ _) as Hlook_uid; [done..|].
  rename Hfn into Hfn'.
  opose proof (lookup_map_curry _ uid ver) as Hfn.
  setoid_rewrite Hfn' in Hfn. simpl in *.
  rewrite Hlook_uid in Hfn. symmetry in Hfn. clear Hfn'.
  rewrite /dec_map_vals in Hfn.
  apply lookup_omap_Some in Hfn as (?&?&Hfn).
  rewrite /dec_map_labels in Hfn.
  apply elem_of_list_to_map_2 in Hfn.
  rename Hfn into Hfn'.
  opose proof (dec_map_labels_out_lookup _ _) as (?&Hfn&?); [done..|].
  clear Hfn'.
  rewrite /in_hidden.
  naive_solver.
Qed.

Local Lemma inv_fn_out_pks {vrf_pk plain hidden} uid pks :
  plain_inv_fn vrf_pk hidden = plain →
  plain !! uid = Some pks →
  pks_in_hidden vrf_pk hidden uid pks.
Proof. intros **?**. by eapply inv_fn_out_lookup. Qed.

(** in->out reasoning for [plain_inv_fn]. *)

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

Local Lemma dec_map_labels_unique vrf_pk m_prev m_next :
  dec_map_labels_aux vrf_pk m_prev = m_next →
  (∀ label val0 val1, (label, val0) ∈ m_next → (label, val1) ∈ m_next → val0 = val1).
Proof.
  intros Hcomp ??? Helem0 Helem1.
  opose proof (dec_map_labels_out_lookup Hcomp Helem0) as (?&Hdec0&?).
  opose proof (dec_map_labels_out_lookup Hcomp Helem1) as (?&Hdec1&?).
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

Local Lemma to_contig_inp_lookup {vrf_pk m0 m1} uid ver pk :
  map_curry $ dec_map_vals $ dec_map_labels vrf_pk m0 = m1 →
  in_hidden vrf_pk m0 uid ver (Some pk) →
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

Local Lemma get_contig_aux_inp_lookup m pks :
  map_seq 0 pks ⊆ m →
  get_contig_aux m 0%nat (length pks) = pks.
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

Local Lemma map_seq_approx_len (m : gmap _ (list w8)) pks :
  map_seq 0 pks ⊆ m →
  (length pks ≤ size m)%nat.
Proof.
  intros Hpks%subseteq_dom.
  rewrite dom_seq in Hpks.
  apply subseteq_size in Hpks.
  by rewrite size_set_seq -map_size_dom in Hpks.
Qed.

Local Lemma get_contig_add_fuel m ver fuel fuel' :
  (fuel ≤ fuel')%nat →
  get_contig_aux m ver fuel `prefix_of` get_contig_aux m ver fuel'.
Proof.
  revert ver fuel'. induction fuel; simpl.
  { intros. apply prefix_nil. }
  intros. destruct fuel'; [lia|]. simpl.
  case_match; try done.
  apply prefix_cons.
  apply IHfuel. lia.
Qed.

Local Lemma get_contig_inp_lookup m pks :
  map_seq 0 pks ⊆ m →
  pks `prefix_of` get_contig m.
Proof.
  intros Hseq.
  opose proof (get_contig_aux_inp_lookup _ _ _) as <-; [done|].
  rewrite /get_contig.
  apply get_contig_add_fuel.
  by apply map_seq_approx_len.
Qed.

Local Lemma inv_fn_inp_pks {vrf_pk plain hidden} uid pks0 :
  plain_inv_fn vrf_pk hidden = plain →
  pks_in_hidden vrf_pk hidden uid pks0 →
  length pks0 ≠ 0%nat →
  ∃ pks1, plain !! uid = Some pks1 ∧ pks0 `prefix_of` pks1.
Proof.
  intros <- Hpks ?.
  remember (plain_inv_fn _ _ !! _) as fn.
  assert (∃ x, fn = Some x) as (pks1&Hfn); subst.
  2: {
    (* assuming pks1, do backwards reasoning. *)
    eexists. split; [done|].
    rewrite /plain_inv_fn /filter_contig in Hfn.
    apply lookup_omap_Some in Hfn as (m_uid&?&?).
    simplify_option_eq.
    apply get_contig_inp_lookup.
    apply map_seq_subseteq.
    intros ver pk Hlook_pks.
    replace (_ + _)%nat with ver by lia.
    opose proof (to_contig_inp_lookup _ _ _ _ _); [done|..].
    2: { by simplify_option_eq. }
    by apply Hpks. }

  (* fill in pks1 using forward reasoning on ver 0. *)
  rewrite /plain_inv_fn.
  destruct pks0 as [|pk]; try done.
  ospecialize (Hpks 0%nat _ _); [done|].
  opose proof (to_contig_inp_lookup _ _ _ _ _) as Hlook_fn; [done..|].
  simplify_option_eq. rename H0 into m_uid.
  eexists. rewrite /filter_contig.
  apply lookup_omap_Some.
  eexists. split; [|done].
  simplify_option_eq; [|done].

  exfalso.
  opose proof (get_contig_inp_lookup m_uid [pk] _) as Hpref.
  2: { apply prefix_length in Hpref. simpl in *. lia. }
  apply map_seq_subseteq.
  intros ?? Hlook.
  apply list_lookup_singleton_Some in Hlook as [-> ->].
  by replace (_ + _)%nat with 0%nat by lia.
Qed.

Local Lemma inv_fn_inp_pks_weak {vrf_pk plain0 plain1 hidden} uid pks :
  is_plain vrf_pk plain0 hidden →
  plain_inv_fn vrf_pk hidden = plain1 →
  plain0 !! uid = Some pks →
  plain1 !! uid = Some pks.
Proof.
  intros Hbij Hfn Hlook.
  opose proof (inv_fn_inp_pks uid pks _ _ _) as (pks1&?&Hpref); [done|..].
  1-2: by eapply Hbij.
  destruct Hpref as ([]&Hpref).
  { by list_simplifier. }
  exfalso.
  opose proof (inv_fn_out_lookup (length pks) _ _ _ _) as (?&?&?&?); [done|done|..].
  { rewrite Hpref. by apply list_lookup_middle. }
  destruct_and!.
  odestruct (proj2 Hbij _ _ _) as (?&?&?&?&?&?&?&Hlook_pks); [done|].
  simplify_eq/=.
  apply lookup_lt_Some in Hlook_pks.
  lia.
Qed.

Lemma inv_fn_None_bound vrf_pk m uid ver :
  in_hidden vrf_pk m uid ver None →
  length $ plain_inv_fn vrf_pk m !!! uid ≤ ver.
Proof.
  intros Hnone.
  eremember (_ !!! uid) as pks.
  destruct (decide (length $ pks > ver)); try done.
  exfalso.
  list_elem pks ver as x.
  rewrite lookup_total_alt in Heqpks.
  destruct (_ !! uid) eqn:Hinv; simplify_eq/=.
  eapply inv_fn_out_lookup in Hinv; [|done..].
  destruct Hnone as (?&Hl0&?).
  destruct Hinv as (?&Hl1&?&?).
  destruct_and!.
  opose proof (map_label_inv_fn_inj Hl0 Hl1) as ->.
  simplify_eq/=.
Qed.

(** monotonicity. *)

Local Lemma inv_fn_non_empty_pks {vrf_pk plain hidden} uid pks :
  plain_inv_fn vrf_pk hidden = plain →
  plain !! uid = Some pks →
  length pks ≠ 0%nat.
Proof.
  rewrite /plain_inv_fn /filter_contig. intros <- Hfn.
  apply lookup_omap_Some in Hfn as (?&?&?).
  by simplify_option_eq.
Qed.

(* used by auditor. *)
Lemma plain_inv_mono vrf_pk m0 m1 :
  m0 ⊆ m1 →
  keys_sub (plain_inv_fn vrf_pk m0) (plain_inv_fn vrf_pk m1).
Proof.
  rewrite /keys_sub. intros Hsub.
  apply map_included_alt.
  intros uid pks Hfn.
  eapply inv_fn_inp_pks; [done|..].
  2: { by eapply inv_fn_non_empty_pks. }
  assert (pks_in_hidden vrf_pk m0 uid pks) as Hin.
  { by eapply inv_fn_out_pks. }
  intros ?**.
  opose proof (Hin _ _ _) as (?&?&?&?); [done|].
  destruct_and!.
  repeat eexists; [done..|].
  by eapply lookup_weaken.
Qed.

(** relation between [is_plain] and [plain_inv_fn]. *)

Lemma is_plain_has_inv vrf_pk plain hidden :
  is_plain vrf_pk plain hidden →
  plain_inv_fn vrf_pk hidden = plain.
Proof.
  rename plain into plain0. intros Hbij.
  remember (plain_inv_fn _ _) as plain1.
  symmetry. apply map_eq. intros uid.
  destruct (plain0 !! uid) as [pks0|] eqn:Hlook0.
  { by erewrite inv_fn_inp_pks_weak. }
  destruct (plain1 !! uid) as [[]|] eqn:Hlook1; try done; exfalso.
  { by opose proof (inv_fn_non_empty_pks _ _ _ _) as ?. }
  opose proof (inv_fn_out_lookup 0 _ _ _ _) as (?&?&?&?); [done..|].
  destruct_and!.
  odestruct (proj2 Hbij _ _ _) as (?&?&?&?&?&?&?&?); [done|].
  simplify_eq/=.
Qed.

(** "correctness". *)

(* clients only need to compute the label.
the inverse computation, [map_label_inv_fn], is internal to this file. *)
Definition map_label_fn vrf_pk uid ver map_label :=
  let enc := MapLabel.pure_enc (MapLabel.mk' uid ver) in
  cryptoffi.vrf_fn vrf_pk enc = Some map_label.
#[global] Opaque map_label_fn.
#[local] Transparent map_label_fn.

Definition map_val_fn kt_pk rand map_val :=
  let enc := CommitOpen.pure_enc (CommitOpen.mk' kt_pk rand) in
  cryptoffi.hash_fn enc = Some map_val ∧
  safemarshal.Slice1D.valid kt_pk.
#[global] Opaque map_val_fn.
#[local] Transparent map_val_fn.

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

(* TODO: hopefully claude can do this, given access to proof window.
claude needs to see the hyps generated by simplify_option_eq. *)
Local Lemma map_val_fn_has_inv kt_pk rand map_val :
  map_val_fn kt_pk rand map_val →
  map_val_inv_fn map_val = Some kt_pk.
Proof.
  rewrite /map_val_fn /map_val_inv_fn /CommitOpen.pure_enc
    /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc /=.
  intros [?%cryptoffi.hash_bij_l Hvalid].
  rewrite /safemarshal.Slice1D.valid in Hvalid.
  simplify_option_eq; try done.
Admitted.

Local Lemma pks_in_hidden_insert {vrf_pk hidden uid pks} map_label map_val :
  pks_in_hidden vrf_pk hidden uid pks →
  hidden !! map_label = None →
  pks_in_hidden vrf_pk (<[map_label:=map_val]>hidden) uid pks.
Proof.
  intros Hrel Hnone ?? Hlook.
  opose proof (Hrel _ _ _) as (?&?&?&?); [done|].
  destruct_and!.
  rewrite /in_hidden.
  repeat eexists; [done..|].
  rewrite insert_union_singleton_l lookup_union.
  by simplify_map_eq/=.
Qed.

Local Lemma pks_in_hidden_snoc {vrf_pk hidden uid pks} pk :
  pks_in_hidden vrf_pk hidden uid pks →
  in_hidden vrf_pk hidden uid (length pks) (Some pk) →
  pks_in_hidden vrf_pk hidden uid (pks ++ [pk]).
Proof.
  rewrite /pks_in_hidden. intros Hrel Hin ver ? Hlook.
  apply lookup_app_Some in Hlook as [?|[? Hlook]].
  - by eapply Hrel.
  - apply list_lookup_singleton_Some in Hlook as [? ->].
    by replace ver with (length pks) by lia.
Qed.

Local Lemma pks_in_hidden_insert_both {vrf_pk hidden uid pks} map_label map_val pk :
  pks_in_hidden vrf_pk hidden uid pks →
  map_label_inv_fn vrf_pk map_label = Some (uid, length pks) →
  map_val_inv_fn map_val = Some pk →
  hidden !! map_label = None →
  pks_in_hidden vrf_pk (<[map_label:=map_val]>hidden) uid (pks ++ [pk]).
Proof.
  intros Hrel Hlab Hval Hnone.
  apply pks_in_hidden_snoc.
  { by apply pks_in_hidden_insert. }
  repeat eexists; [done..|].
  rewrite insert_union_singleton_l lookup_union.
  simplify_map_eq/=.
  by rewrite union_Some_l.
Qed.

Local Lemma in_plain_insert {vrf_pk plain map_label map_val} uid pk :
  in_plain vrf_pk plain map_label map_val →
  in_plain vrf_pk (<[uid:=plain !!! uid ++ [pk]]>plain) map_label map_val.
Proof.
  rewrite /in_plain. intros (uid0&ver0&pk0&pks0&?&?&Hlook_plain&Hlook_pks).
  rewrite lookup_total_alt.
  setoid_rewrite insert_union_singleton_l.
  setoid_rewrite lookup_union.
  destruct (decide (uid = uid0)).
  - subst. do 3 eexists. exists (pks0 ++ [pk]).
    repeat split; try done.
    + rewrite Hlook_plain.
      simplify_map_eq/=.
      by rewrite union_Some_l.
    + by apply lookup_app_l_Some.
  - repeat eexists; try done.
    rewrite Hlook_plain.
    by simplify_map_eq/=.
Qed.

Local Lemma hidden_insert_unique {vrf_pk plain hidden} uid ver map_label :
  hidden_to_plain vrf_pk hidden plain →
  map_label_inv_fn vrf_pk map_label = Some (uid, ver) →
  ver = length $ plain !!! uid →
  hidden !! map_label = None.
Proof.
  simpl. intros Hhtop Hlab ?.
  destruct (decide (hidden !! map_label = None)) as [|Ht]; [done|].
  exfalso.
  apply not_eq_None_Some in Ht as [? Hsome].
  opose proof (Hhtop _ _ _) as (?&?&?&pks&?&?&Hlook_plain&Hlook_pks); [done|].
  simplify_eq/=.
  rewrite lookup_total_alt Hlook_plain /= in Hlook_pks.
  replace pks with (pks ++ []) in Hlook_pks at 2.
  2: { by list_simplifier. }
  by rewrite lookup_app_r in Hlook_pks; [|lia].
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
Proof.
  simpl. intros Hbij Hlabel Heq_ver Hval.
  eapply map_label_fn_has_inv in Hlabel.
  eapply map_val_fn_has_inv in Hval.
  destruct Hbij as [Hptoh Hhtop].
  split.
  - rewrite /plain_to_hidden in Hptoh |-*.
    opose proof (hidden_insert_unique _ _ _ _ _ _); [done..|word|].
    apply map_Forall_insert_2.
    + split; [len|].
      eapply pks_in_hidden_insert_both; try done.
      2: { exact_eq Hlabel. repeat f_equal. word. }
      rewrite lookup_total_alt.
      destruct (plain !! uid) eqn:?; [|done].
      by apply Hptoh.
    + eapply map_Forall_impl; [done|].
      simpl. intros * [].
      split; [done|].
      by apply pks_in_hidden_insert.
  - rewrite /hidden_to_plain in Hhtop |-*.
    apply map_Forall_insert_2.
    + repeat eexists; try done.
      * rewrite insert_union_singleton_l lookup_union.
        simplify_map_eq/=.
        by rewrite union_Some_l.
      * by rewrite Heq_ver lookup_snoc.
    + eapply map_Forall_impl; [done|].
      simpl. intros **.
      by apply in_plain_insert.
Qed.

End proof.
End ktcore.
