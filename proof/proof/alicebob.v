From New.generatedproof.github_com.sanjit_bhat.pav Require Import alicebob.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof Require Import bytes time.
From New.proof.github_com.goose_lang Require Import primitive std.
From New.proof.github_com.sanjit_bhat.pav Require Import
  advrpc auditor client cryptoffi ktcore server.

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

Lemma wp_testAliceBob (serv_trust adtr_trust : Trust.t)
    (alice_good bob_good : bool)
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
Proof.
  wp_start as "@". wp_auto.
  iMod (mono_list_own_alloc ([] : list (nat * list w8))) as (alice_uidγ) "[Halice_puts _]".
  iMod (mono_list_own_alloc ([] : list (nat * list w8))) as (bob_uidγ) "[Hbob_puts _]".
  iAssert (
    |={⊤}=>
    match alice_good with
    | true => mono_list_auth_own alice_uidγ 1 ([] : list (nat * list w8))
    | false => client.ver.is_uid_inv alice_uidγ
    end)%I with "[Halice_puts]" as "> Halice_good".
  { case_match; [by iFrame|].
    iApply inv_alloc.
    iFrame. }
  iAssert (
    |={⊤}=>
    match bob_good with
    | true => mono_list_auth_own bob_uidγ 1 ([] : list (nat * list w8))
    | false => client.ver.is_uid_inv bob_uidγ
    end)%I with "[Hbob_puts]" as "> Hbob_good".
  { case_match; [by iFrame|].
    iApply inv_alloc.
    iFrame. }
  set ({[W64 0:=alice_uidγ; W64 1:=bob_uidγ]} : gmap w64 gname) as uidγs.
  wp_apply (server.wp_New uidγs) as "* @".
  wp_apply (server.wp_NewRpcServer with "[$Hlocks]") as "* @".
  wp_apply advrpc.wp_Server_Serve.
Admitted.

End proof.
End alicebob.
