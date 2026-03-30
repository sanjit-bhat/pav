From New.generatedproof.github_com.sanjit_bhat.pav Require Import auditor.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof Require Import bytes sync.
From New.proof.github_com.sanjit_bhat.pav Require Import
  advrpc cryptoffi hashchain ktcore merkle safemarshal server.

Module auditor.
Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

#[global] Instance : IsPkgInit (iProp Σ) auditor := define_is_pkg_init True%I.
#[global] Instance : GetIsPkgInitWf (iProp Σ) auditor := build_get_is_pkg_init_wf.

End proof.
End auditor.
