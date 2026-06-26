From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

Module ktcore.

Section blame.
(* [BlameSpec] is defined completely outside separation logic,
so it could even be transported via the adequacy theorem. *)

Inductive BlameTys :=
  | BlameServSig
  | BlameServFull
  | BlameAdtrSig
  | BlameAdtrFull
  | BlameClients
  | BlameUnknown.

Axiom BlameTys_EqDecision : EqDecision BlameTys.
Global Existing Instance BlameTys_EqDecision.

Axiom BlameTys_Countable : Countable BlameTys.
Global Existing Instance BlameTys_Countable.

Definition Blame := gset BlameTys.

Definition party_bit (p : BlameTys) : w64 :=
  match p with
  | BlameServSig => W64 1
  | BlameServFull => W64 2
  | BlameAdtrSig => W64 4
  | BlameAdtrFull => W64 8
  | BlameClients => W64 16
  | BlameUnknown => W64 32
  end.

Definition blame_to_u64 (err : Blame) : w64 :=
  set_fold (λ p acc, word.or (party_bit p) acc) (W64 0) err.

(* the fold function commutes in its accumulator, which is needed for the
[set_fold] union/disj-union lemmas. *)
Lemma word_or_comm_acc (a1 a2 b : w64) :
  word.or a1 (word.or a2 b) = word.or a2 (word.or a1 b).
Proof.
  apply (inj uint.Z).
  rewrite !word.unsigned_or_nowrap.
  rewrite !Z.lor_assoc.
  by rewrite (Z.lor_comm (uint.Z a1) (uint.Z a2)).
Qed.

Lemma blame_fold_comm (x1 x2 : BlameTys) (b : w64) :
  word.or (party_bit x1) (word.or (party_bit x2) b) =
  word.or (party_bit x2) (word.or (party_bit x1) b).
Proof. apply word_or_comm_acc. Qed.

(* OR-ing two words is zero iff both are zero. *)
Lemma word_or_eq_zero (a b : w64) :
  word.or a b = W64 0 ↔ a = W64 0 ∧ b = W64 0.
Proof.
  split.
  2: { intros [-> ->]. apply (inj uint.Z). by rewrite word.unsigned_or_nowrap. }
  intros Hor.
  pose proof (word.unsigned_range a) as [??].
  pose proof (word.unsigned_range b) as [??].
  assert (uint.Z (word.or a b) = uint.Z (W64 0)) as Hu by by rewrite Hor.
  rewrite word.unsigned_or_nowrap in Hu.
  change (uint.Z (W64 0)) with 0 in Hu.
  apply Z.lor_eq_0_iff in Hu as [Ha Hb].
  split; apply (inj uint.Z); [rewrite Ha | rewrite Hb]; done.
Qed.

Lemma party_bit_ne_zero (p : BlameTys) : party_bit p ≠ W64 0.
Proof. destruct p; done. Qed.

(* [BlameSpec] formalizes the notion of blaming a set of parties who
are responsible for a bad thing happening.
[interp] maps parties to is_good flags. *)
Definition BlameSpec (err : Blame) (interp : gmap BlameTys bool) :=
  err = ∅ ∨
  err = {[ BlameUnknown ]} ∨
  (* exists bad party in blame set. *)
  (∃ p, p ∈ err ∧ interp !! p = Some false).

(* TODO: curr spec allows Blame'ing more parties than are strictly responsible.
e.g., if only server is responsible for a merkle proof not verifying,
the client dev can blame both ServerFull and AuditorFull.
to fix, need notion of "minimal party set".
e.g., this might be a def, which intuitively requires that for any Blamed party,
all remaining parties are good.

TODO: i'm not sure if this is provable.
we can't unconditionally prove that someone is good.
we can only prove that someone must be bad after observing a bad event.

TODO: minmality should take into account that ServSig is a strictly
more minimal assumption than ServFull. *)
Definition minimal (err : Blame) (interp : gmap BlameTys bool) :=
  ∀ p p', p ∈ err → p' ∈ (err ∖ {[p]}) → interp !! p' = Some true.

Lemma blame_add_interp err interp0 interp1 :
  BlameSpec err interp0 →
  interp0 ⊆ interp1 →
  BlameSpec err interp1.
Proof.
  rewrite /BlameSpec.
  intros HB Hsub.
  destruct_or!; try naive_solver.
  destruct HB as (p&?&?).
  right. right.
  exists p. split; try done.
  by eapply map_subseteq_spec.
Qed.

End blame.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma rw_Blame0 err :
  blame_to_u64 err = W64 0 ↔ err = ∅.
Proof.
  rewrite /blame_to_u64.
  split.
  - (* fold = 0 → err = ∅. by contradiction: a non-empty set has a party
    whose bit is nonzero, and OR-ing only sets bits. *)
    intros Hfold.
    apply (set_fold_ind_L
             (λ (acc : w64) (s : Blame),
                acc = W64 0 → s = ∅)
             (λ p acc, word.or (party_bit p) acc) (W64 0)); [done| |done].
    intros p s acc Hp IH Hor.
    apply word_or_eq_zero in Hor as [Hbit _].
    by destruct (party_bit_ne_zero p).
  - intros ->. apply set_fold_empty.
Qed.

Lemma rw_BlameNone :
  # (W64 0) = # (blame_to_u64 ∅).
Proof. rewrite /blame_to_u64 set_fold_empty. done. Qed.

(* TODO: would be nice to re-use Blame defs from code file.
rewriting on code.BlameServFull (#(W64 1)) doesn't work on #(W64 1) goal. *)
(* [blame_to_u64] on a singleton reduces to that party's bit. *)
Lemma blame_to_u64_singleton p :
  blame_to_u64 {[ p ]} = party_bit p.
Proof.
  rewrite /blame_to_u64 set_fold_singleton.
  apply (inj uint.Z). rewrite word.unsigned_or_nowrap.
  destruct p; vm_compute; reflexivity.
Qed.

Lemma rw_BlameServSig :
  # (W64 1) = # (blame_to_u64 {[ BlameServSig ]}).
Proof. by rewrite blame_to_u64_singleton. Qed.

Lemma rw_BlameServFull :
  # (W64 2) = # (blame_to_u64 {[ BlameServFull ]}).
Proof. by rewrite blame_to_u64_singleton. Qed.

Lemma rw_BlameAdtrSig :
  # (W64 4) = # (blame_to_u64 {[ BlameAdtrSig ]}).
Proof. by rewrite blame_to_u64_singleton. Qed.

Lemma rw_BlameAdtrFull :
  # (W64 8) = # (blame_to_u64 {[ BlameAdtrFull ]}).
Proof. by rewrite blame_to_u64_singleton. Qed.

Lemma rw_BlameClients :
  # (W64 16) = # (blame_to_u64 {[ BlameClients ]}).
Proof. by rewrite blame_to_u64_singleton. Qed.

Lemma rw_BlameUnknown :
  # (W64 32) = # (blame_to_u64 {[ BlameUnknown ]}).
Proof. by rewrite blame_to_u64_singleton. Qed.

Lemma rw_BlameServClients :
  # (W64 18) = # (blame_to_u64 {[ BlameServFull; BlameClients ]}).
Proof.
  enough (blame_to_u64 {[BlameServFull; BlameClients]} = W64 18) as -> by done.
  rewrite /blame_to_u64.
  rewrite (set_fold_disj_union_strong (=@{w64})
             (λ p acc, word.or (party_bit p) acc) (W64 0)
             {[BlameServFull]} {[BlameClients]}).
  all: try (intros x; solve_proper).
  all: try (intros ??????; apply word_or_comm_acc).
  all: try set_solver.
  rewrite !set_fold_singleton.
  apply (inj uint.Z). rewrite !word.unsigned_or_nowrap.
  vm_compute. reflexivity.
Qed.

Lemma blame_none interp : BlameSpec ∅ interp.
Proof. rewrite /BlameSpec. naive_solver. Qed.

Lemma blame_unknown interp : BlameSpec {[ BlameUnknown ]} interp.
Proof. rewrite /BlameSpec. naive_solver. Qed.

(* iProp form so it can be iApply'd and proven with iris resources. *)
Lemma blame_one party good interp :
  (* written as "not good" bc goodness is how to learn contra. *)
  (¬ ⌜good = true⌝ : iProp Σ) -∗
  ⌜BlameSpec {[ party ]} (<[party:=good]>interp)⌝.
Proof.
  iPureIntro. intros ?. right. right.
  destruct good; try done.
  exists party.
  split; [set_solver|by simplify_map_eq/=].
Qed.

Lemma blame_two party0 party1 good0 good1 interp :
  (⌜party0 ≠ party1⌝ : iProp Σ) ∗
  ¬ ⌜(good0 = true ∧ good1 = true)⌝ -∗
  ⌜BlameSpec {[ party0; party1 ]} (<[party0:=good0]>(<[party1:=good1]>interp))⌝.
Proof.
  iPureIntro. intros [? Heq%Classical_Prop.not_and_or]. right. right.
  destruct Heq as [?|?].
  - destruct good0; try done.
    exists party0.
    split; [set_solver|by simplify_map_eq/=].
  - destruct good1; try done.
    exists party1.
    split; [set_solver|by simplify_map_eq/=].
Qed.

End proof.
End ktcore.
