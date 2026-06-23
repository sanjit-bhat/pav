From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof Require Import bytes.
From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi cryptoutil safemarshal.
From New.proof.github_com.tchajed Require Import marshal.

Module ktcore.
Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

#[global] Instance : IsPkgInit (iProp Σ) ktcore := define_is_pkg_init True%I.
#[global] Instance : GetIsPkgInitWf (iProp Σ) ktcore := build_get_is_pkg_init_wf.

Lemma wp_initialize' get_is_pkg_init :
  get_is_pkg_init_prop ktcore get_is_pkg_init →
  {{{ own_initializing get_is_pkg_init }}}
    ktcore.initialize' #()
  {{{ RET #(); own_initializing get_is_pkg_init ∗ is_pkg_init ktcore }}}.
Proof.
  intros Hinit. wp_start as "Hown".
  wp_apply (wp_package_init with "[$Hown] HΦ") as "Hown".
  { destruct Hinit as (-> & ?); done. }
  wp_apply (marshal.wp_initialize' with "[$Hown]").
  { naive_solver. }
  iIntros "(Hown & #?)". wp_auto.
  wp_apply (safemarshal.wp_initialize' with "[$Hown]").
  { naive_solver. }
  iIntros "(Hown & #?)". wp_auto.
  wp_apply (cryptoutil.wp_initialize' with "[$Hown]").
  { naive_solver. }
  iIntros "(Hown & #?)". wp_auto.
  wp_apply (cryptoffi.wp_initialize' with "[$Hown]").
  { naive_solver. }
  iIntros "(Hown & #?)". wp_auto.
  wp_apply (bytes.wp_initialize' with "[$Hown]").
  { naive_solver. }
  iIntros "(Hown & #?)". wp_auto.
  iFrame. iEval (rewrite is_pkg_init_unfold). simpl. iFrame "#".
Qed.

End proof.
End ktcore.
