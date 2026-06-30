From New.generatedproof.github_com.sanjit_bhat.pav Require Import alicebob.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof Require Import bytes time.
From New.proof.github_com.goose_lang Require Import primitive std.
From New.proof.github_com.sanjit_bhat.pav Require Import
  auditor client cryptoffi ktcore server.

Module alicebob.

Module Trust.
Inductive t :=
  | No
  | SigPred
  | Full.

Definition rank t : nat :=
  match t with No => 0 | SigPred => 1 | Full => 2 end.
End Trust.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : alicebob.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

#[global] Instance : IsPkgInit (iProp Σ) alicebob := define_is_pkg_init True%I.
#[global] Instance : GetIsPkgInitWf (iProp Σ) alicebob := build_get_is_pkg_init_wf.

(* [alice_okay] is whether alice's uid is adversarially controlled. *)
Lemma wp_testAliceBob (serv_trust adtr_trust : Trust.t)
    (alice_okay bob_okay : bool)
    (servAddr : w64) (servGood : bool) sl_adtrAddrs (adtrAddrs : list w64) :
  {{{
    is_pkg_init alicebob ∗
    "#Hsl_adtrAddrs" ∷ sl_adtrAddrs ↦*□ adtrAddrs ∗
    "%Heq_servGood" ∷ ⌜servGood =
      bool_decide (Trust.rank Trust.No < Trust.rank serv_trust)⌝ ∗
    "%Hmin_trust" ∷ ⌜Trust.rank Trust.No < Trust.rank serv_trust ∨
      Trust.rank Trust.No < Trust.rank adtr_trust⌝
  }}}
  @! alicebob.testAliceBob #servAddr #servGood #sl_adtrAddrs
  {{{ RET #(); True }}}.
Proof. Admitted.

End proof.
End alicebob.
