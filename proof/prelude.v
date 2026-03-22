(* usage: before importing this, import anything you want.
after importing this, don't import anything except "new/proof" files,
which shouldn't have side-effects (including Exports)
or unintended name shadows. *)

(* add extra dependencies. *)
From RecordUpdate Require Export RecordSet.
From iris_named_props Require Export custom_syntax.
From Perennial.Helpers Require Export bytes condition Map.

(* set the right shadowed dependencies. *)
(* note: stdpp overrides some Stdlib names. *)
From stdpp Require Export prelude.

(* restore perennial's side-effects. *)
Ltac obligation_tac :=
  try
    match goal with
    | |- seal _ => eexists; reflexivity
    | _ => solve [ apply _ ]
    end.
#[global] Obligation Tactic := obligation_tac.
#[export] Set Default Goal Selector "!".
#[global] Open Scope Z_scope.

(* misc. TODO: these should definitely go into separate file. *)
From New.proof Require Import proof_prelude.

Definition option_bool {A} (mx : option A) :=
  match mx with None => false | _ => true end.

#[global] Tactic Notation "destruct_exis" := repeat
  match goal with
  | H : ∃ _, _ |- _ => destruct H as (?&H)
  end.

Section misc.
Context {PROP : bi} `{!BiFUpd PROP}.

(* this helps proving [BlameSpec] when we need to open invs
after learning that a party is good. *)
Lemma fupd_not_prop P `{Decision P} : (⌜P⌝ ={⊤}=∗ False : PROP) ⊢ |={⊤}=> ¬ ⌜P⌝.
Proof.
  iIntros "H".
  destruct (decide P); [|done].
  by iMod ("H" with "[//]").
Qed.
End misc.
