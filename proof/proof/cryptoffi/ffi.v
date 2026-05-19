From New.generatedproof.github_com.sanjit_bhat.pav.cryptoffi Require Import ffi.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

Module ffi.
Section init.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ffi.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

#[global] Instance : IsPkgInit (iProp Σ) ffi := define_is_pkg_init True%I.
#[global] Instance : GetIsPkgInitWf (iProp Σ) ffi := build_get_is_pkg_init_wf.
End init.
End ffi.
