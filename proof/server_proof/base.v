From New.generatedproof.github_com.sanjit_bhat.pav Require Import server.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof Require Import sync time.
From New.proof.github_com.goose_lang Require Import std.
From New.proof.github_com.sanjit_bhat.pav Require Import
  advrpc cryptoffi hashchain ktcore merkle safemarshal.
From New.proof.github_com.tchajed Require Import marshal.

Module server.
Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition is_initialized : iProp Σ :=
  ∃ (EpochTime : w64),
  "#HEpochTime" ∷ global_addr server.EpochTime ↦□ EpochTime.

#[global] Instance : IsPkgInit (iProp Σ) server := define_is_pkg_init is_initialized.
#[global] Instance : GetIsPkgInitWf (iProp Σ) server := build_get_is_pkg_init_wf.

End proof.
End server.
