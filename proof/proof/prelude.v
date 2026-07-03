(* usage: before importing this, import anything you want.
after importing this, don't import anything except "new/proof" files,
which shouldn't have side-effects (including Exports)
or unintended name shadows. *)

(* add extra dependencies. *)
From RecordUpdate Require Export RecordSet.
From iris_named_props Require Export custom_syntax.
From Perennial.Helpers Require Export bytes condition Map.

(* set the right shadowed dependencies. *)
(* stdpp overrides some Stdlib names. *)
From stdpp Require Export prelude.
(* so do our helpers. *)
From New.proof.github_com.sanjit_bhat.pav.helpers Require Export
  stdpp iris.

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
