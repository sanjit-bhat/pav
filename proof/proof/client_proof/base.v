From New.generatedproof.github_com.sanjit_bhat.pav Require Import client.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof Require Import bytes.
From New.proof.github_com.goose_lang Require Import std.
From New.proof.github_com.sanjit_bhat.pav Require Import
  advrpc auditor cryptoffi hashchain ktcore merkle server.

Module client.
Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : client.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

#[global] Instance : IsPkgInit (iProp Σ) client := define_is_pkg_init True%I.
#[global] Instance : GetIsPkgInitWf (iProp Σ) client := build_get_is_pkg_init_wf.

End proof.
End client.
