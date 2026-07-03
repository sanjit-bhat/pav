From New.generatedproof.github_com.sanjit_bhat.pav Require Import advrpc.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import
  safemarshal netffi.

Module advrpc.

Section defs.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Definition is_Server (s : loc) : iProp Σ. Admitted.

#[global] Instance is_Server_pers s : Persistent (is_Server s). Admitted.

End defs.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : advrpc.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

#[global] Instance : IsPkgInit (iProp Σ) advrpc := define_is_pkg_init True%I.
#[global] Instance : GetIsPkgInitWf (iProp Σ) advrpc := build_get_is_pkg_init_wf.

Lemma wp_Server_Serve s (addr : w64) :
  {{{
    is_pkg_init advrpc ∗
    "#His_serv" ∷ is_Server s
  }}}
  s @! (go.PointerType advrpc.Server) @! "Serve" #addr
  {{{ RET #(); True }}}.
Proof. Admitted.

End proof.
End advrpc.
