From New.proof Require Import proof_prelude.
From stdpp Require Import prelude.

Definition option_bool {A} (mx : option A) :=
  match mx with None => false | _ => true end.

#[global] Tactic Notation "destruct_exis" := repeat
  match goal with
  | H : ∃ _, _ |- _ => destruct H as (?&H)
  end.

Lemma list_reln_singleton {A} (a : A) R : list_reln [a] R.
Proof. by intros ?**. Qed.

Lemma last_drop_Some {A} (l : list A) x n :
  last l = Some x →
  (n < length l)%nat →
  last (drop n l) = Some x.
Proof.
  intros (?&->)%last_Some ?.
  autorewrite with len in *.
  rewrite drop_app_le; [|lia].
  by rewrite last_snoc.
Qed.

Lemma list_reln_snoc' {A} R (l : list A) a :
  list_reln (l ++ [a]) R → list_reln l R.
Proof.
  rewrite /list_reln. intros Hr * Hlook0 Hlook1.
  eapply lookup_app_l_Some in Hlook0, Hlook1.
  by eapply Hr.
Qed.

Lemma list_reln_app {A} R (l0 l1 : list A) :
  list_reln (l0 ++ l1) R →
  list_reln l0 R ∧ list_reln l1 R.
Proof.
  rewrite /list_reln. intros Happ. split.
  - intros i x y Hx Hy.
    eapply Happ.
    + rewrite lookup_app_l; [done|eapply lookup_lt_Some; done].
    + rewrite lookup_app_l; [done|eapply lookup_lt_Some; done].
  - intros i x y Hx Hy.
    apply (Happ (i + length l0)%nat).
    + rewrite lookup_app_r; last lia.
      replace (i + length l0 - length l0)%nat with i by lia. done.
    + rewrite lookup_app_r; last lia.
      replace (S (i + length l0) - length l0)%nat with (S i) by lia. done.
Qed.

Lemma lookup_app_r' {A} (l1 l2 : list A) i :
  l2 !! i = (l1 ++ l2) !! (i + length l1)%nat.
Proof. rewrite lookup_app_r; [|lia]. f_equal. lia. Qed.

Lemma prefix_eq {A} (l1 l2 : list A) :
  l1 `prefix_of` l2 →
  l2 `prefix_of` l1 →
  l1 = l2.
Proof. intros ? ?%prefix_length. by apply prefix_length_eq. Qed.

Lemma list_reln_app' {A} R (l0 : list A) l1 :
  list_reln l0 R →
  list_reln l1 R →
  (∀ x0 x1, last l0 = Some x0 → head l1 = Some x1 → R x0 x1) →
  list_reln (l0 ++ l1) R.
Proof.
  intros Hl0. induction l1 using rev_ind; [by list_simplifier|].
  intros Hl1 Hr.
  rewrite (assoc _).
  apply list_reln_snoc.
  - apply IHl1.
    + by eapply list_reln_snoc'.
    + intros * ? Hhead. eapply Hr; [done|].
      by rewrite head_snoc Hhead.
  - clear IHl1.
    destruct l1 using rev_ind; [|clear IHl1].
    + list_simplifier.
      intros **. by apply Hr.
    + rewrite (assoc _) last_snoc.
      intros **. simplify_eq/=.
      rewrite -(assoc _) in Hl1.
      apply list_reln_app in Hl1 as [_ Hl1].
      rewrite /list_reln in Hl1.
      by eapply (Hl1 0%nat).
Qed.

Lemma list_reln_take {A} R (l : list A) n :
  list_reln l R →
  list_reln (take n l) R.
Proof.
  intros H.
  rewrite -(take_drop n l) in H.
  apply list_reln_app in H.
  naive_solver.
Qed.

Lemma list_reln_drop {A} R (l : list A) n :
  list_reln l R →
  list_reln (drop n l) R.
Proof.
  intros H.
  rewrite -(take_drop n l) in H.
  apply list_reln_app in H.
  naive_solver.
Qed.

Lemma list_reln_prefix {A} R (l0 : list A) l1 :
  list_reln l0 R →
  l1 `prefix_of` l0 →
  list_reln l1 R.
Proof.
  intros H [? ->].
  apply list_reln_app in H.
  naive_solver.
Qed.

(* TODO: not sure if right form. *)
Lemma bind_is_Some {A B} (f : A → option B) (mx : option A) :
  is_Some (mx ≫= f) ↔ is_Some mx ∧ (∀ x, mx = Some x → is_Some (f x)).
Proof. destruct mx; naive_solver. Qed.

Lemma subslice_snoc {A} n m (l : list A) x :
  l !! m = Some x →
  (n ≤ m)%nat →
  subslice n (S m) l = subslice n m l ++ [x].
Proof.
  (* TODO: rm [subslice_split_r], worse version of [subslice_app_contig]. *)
  intros **.
  rewrite -(subslice_app_contig _ m); [|lia].
  by erewrite subslice_singleton; [|done].
Qed.

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

Lemma list_reln_box {A B} R0 R1 (f : A → B) (l0 : list A) :
  list_reln l0 R0 →
  (∀ x0 x1, R0 x0 x1 → R1 (f x0) (f x1)) →
  list_reln (f <$> l0) R1.
Proof.
  rewrite /list_reln. intros H Hrel i x y.
  rewrite !list_lookup_fmap.
  intros [a [Ha ->]]%fmap_Some [b [Hb ->]]%fmap_Some.
  exact (Hrel _ _ (H _ _ _ Ha Hb)).
Qed.

Lemma prefix_or_length_eq {A} (l0 l1 : list A) :
  l0 `prefix_of` l1 ∨ l1 `prefix_of` l0 →
  length l0 = length l1 →
  l0 = l1.
Proof.
  intros [?|?] ?.
  - apply prefix_length_eq; [done|lia].
  - symmetry. apply prefix_length_eq; [done|lia].
Qed.

Lemma last_length_Some {A} (l : list A) :
  is_Some $ last l →
  length l ≠ 0.
Proof. destruct l; naive_solver. Qed.

Lemma last_drop_Some' {A} (l : list A) x :
  last l = Some x →
  drop (pred $ length l) l = [x].
Proof.
  intros [? ->]%last_Some.
  len. rewrite drop_app_length'; [done|lia].
Qed.

Lemma lookup_drop_Some {A} n (l : list A) i x :
  l !! i = Some x →
  n ≤ i →
  drop n l !! (i - n) = Some x.
Proof.
  intros Hl ?.
  rewrite lookup_drop.
  exact_eq Hl. f_equal. lia.
Qed.
