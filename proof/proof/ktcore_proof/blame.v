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

Definition blame_to_u64 (err : Blame) : w64. Admitted.

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
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Lemma rw_Blame0 err :
  blame_to_u64 err = W64 0 ↔ err = ∅.
Proof. Admitted.

Lemma rw_BlameNone :
  # (W64 0) = # (blame_to_u64 ∅).
Proof. Admitted.

(* TODO: would be nice to re-use Blame defs from code file.
rewriting on code.BlameServFull (#(W64 1)) doesn't work on #(W64 1) goal. *)
Lemma rw_BlameServSig :
  # (W64 1) = # (blame_to_u64 {[ BlameServSig ]}).
Proof. Admitted.

Lemma rw_BlameServFull :
  # (W64 2) = # (blame_to_u64 {[ BlameServFull ]}).
Proof. Admitted.

Lemma rw_BlameAdtrSig :
  # (W64 4) = # (blame_to_u64 {[ BlameAdtrSig ]}).
Proof. Admitted.

Lemma rw_BlameAdtrFull :
  # (W64 8) = # (blame_to_u64 {[ BlameAdtrFull ]}).
Proof. Admitted.

Lemma rw_BlameClients :
  # (W64 16) = # (blame_to_u64 {[ BlameClients ]}).
Proof. Admitted.

Lemma rw_BlameUnknown :
  # (W64 32) = # (blame_to_u64 {[ BlameUnknown ]}).
Proof. Admitted.

Lemma rw_BlameServClients :
  # (W64 18) = # (blame_to_u64 {[ BlameServFull; BlameClients ]}).
Proof. Admitted.

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
