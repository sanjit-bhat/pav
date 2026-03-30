(** Iris reasoning principles for crypto FFI *)
From iris.base_logic Require Export lib.mono_nat.
From stdpp Require Import gmap vector fin_maps.
From RecordUpdate Require Import RecordSet.
From iris.algebra Require Import numbers.
From Perennial.algebra Require Import gen_heap_names.
From iris.proofmode Require Import proofmode.
From Perennial.base_logic Require Import ghost_map.
From Perennial.program_logic Require Import ectx_lifting atomic.

From Perennial.Helpers Require Import CountableTactics Transitions Integers.
From Perennial.goose_lang Require Import lang lifting.
From Perennial.goose_lang Require Import crash_modality.
From New.golang Require Import theory.
From Cryptoffi Require Export impl.

Set Default Proof Using "Type".
Set Printing Projections.

(** * Crypto semantic interpretation and lifting lemmas *)

Implicit Type Σ : gFunctors.
Class cryptoGS (Σ : gFunctors) : Type := CryptoGS {
  all_hash_data : list (list w8);
  hash_proph_id : proph_id;
  total_hash_fn : list w8 → list w8;
}.

Class cryptoGpreS (Σ : gFunctors) : Type := {
}.

Class cryptoNodeGS Σ : Set := CryptoNodeGS {
}.

(* TODO: update with real ghost functors *)
Definition cryptoΣ : gFunctors := #[].

#[global]
Instance subG_cryptoGpreS Σ : subG cryptoΣ Σ → cryptoGpreS Σ.
Proof. Qed.

Section clean.
  Context `{!cryptoGS Σ}.
  Local Definition clean_hash_data : list (list w8) :=
    foldl (λ clean_so_far data,
             if decide ((total_hash_fn data) ∈ total_hash_fn <$> clean_so_far) then
               clean_so_far
             else clean_so_far ++ [data]) [] all_hash_data.
End clean.

Section crypto.
  (* these are local instances on purpose, so that importing this file doesn't
  suddenly cause all FFI parameters to be inferred as the crypto model *)
  Existing Instances crypto_op crypto_model.
  Context {go_gctx : GoGlobalContext}.

  (* TODO: fill in ffi_local_ctx, ffi_global_ctx, ffi_local_start, ffi_global_start,
     ffi_crash_rel with the actual state interpretation *)
  Local Program Instance crypto_interp : ffi_interp crypto_model :=
    {| ffiGlobalGS := cryptoGS;
       ffiLocalGS := cryptoNodeGS;
       ffi_local_ctx _ _ σ := True%I;
       ffi_global_ctx _ _ g := (
                                ⌜ g.(crypto_hash_proph_id) = hash_proph_id ⌝ ∗
                                ⌜ g.(crypto_hash_fn) = total_hash_fn ⌝ ∗
                                ⌜ prefix g.(crypto_hash_prev_data) clean_hash_data ⌝
                              )%I;
       ffi_local_start _ _ σ := True%I;
       ffi_global_start _ _ g := True%I;
       ffi_restart _ _ _ := True%I;
       ffi_crash_rel Σ hF1 σ1 hF2 σ2 :=
         ⌜ hF1 = hF2 ⌝%I;
    |}.
End crypto.

Section lifting.
  Existing Instances crypto_op crypto_model crypto_semantics crypto_interp.
  Context `{!gooseGlobalGS Σ, !gooseLocalGS Σ} {go_gctx : GoGlobalContext}.
  Local Instance goose_cryptoGS : cryptoGS Σ := goose_ffiGlobalGS.
  Local Instance goose_cryptoNodeGS : cryptoNodeGS Σ := goose_ffiLocalGS.

  (* Lifting automation *)
  Local Hint Extern 0 (base_reducible _ _ _) => eexists _, _, _, _, _; simpl : core.
  Local Hint Extern 0 (base_reducible_no_obs _ _ _) => eexists _, _, _, _; simpl : core.
  Ltac inv_base_step :=
    repeat match goal with
        | _ => progress simplify_map_eq/= (* simplify memory stuff *)
        | H : to_val _ = Some _ |- _ => apply of_to_val in H
        | H : base_step ?e _ _ _ _ _ _ _ |- _ =>
          rewrite /base_step /= in H;
          monad_inv; repeat (simpl in H; monad_inv)
        | H : ffi_step _ _ _ _ _ |- _ =>
          inversion H; subst; clear H
        | H : prod _ _ |- _ => destruct H
        | H : and _ _ |- _ => destruct H
        | H : ex _ |- _ => destruct H
        | H : ∀ _, (_ = _) → _ |- _ => specialize (H _ ltac:(done))
        | H : ∀ _ _, (_ = _) → _ |- _ => specialize (H _ _ ltac:(done))
        | H : ∀ _ _ _ , (_ = _) → _ |- _ => specialize (H _ _ _ ltac:(done))
        | _ => progress subst
        end.

  Local Lemma wp_CryptoOp op (v : val) s E Φ :
    ▷ (∀ σ1 g1 e2 σ2 g2 (Hstep : is_crypto_ffi_step op v e2 σ1 σ2 g1 g2),
       ffi_local_ctx goose_ffiLocalGS σ1 -∗
       ffi_global_ctx goose_ffiGlobalGS g1 -∗ |NC={E}=>
       (ffi_local_ctx goose_ffiLocalGS σ2 ∗
        ffi_global_ctx goose_ffiGlobalGS g2 ∗
        WP e2 @ s; E {{ Φ }})) -∗
    WP ExternalOp op v @ s; E {{ v, Φ v }}.
  Proof.
    iLöb as "IH".
    iIntros "HΦ".
    iApply wp_lift_step_ncfupd; first by auto.
    iIntros (σ1 g1 ns mj D κ κs nt) "@ Hg".
    iApply ncfupd_mask_intro; [solve_ndisj|iIntros "Hmask"].
    iSplit.
    { iPureIntro. destruct s; try done. apply base_prim_reducible.
      repeat econstructor; simpl.
      { instantiate (1:=(_, _, _)). repeat econstructor. }
      repeat econstructor. }
    iIntros "!>" (v2 σ2 g2 efs Hstep).
    iMod (global_state_interp_le with "Hg") as "Hg".
    { apply step_count_next_incr. }
    apply base_reducible_prim_step in Hstep.
    2:{ repeat econstructor; simpl.
        { instantiate (1:=(_, _, _)). repeat econstructor. }
        repeat econstructor. }
    inv Hstep. simpl in *.
    inv_base_step. monad_inv. simpl in *.
    inv_base_step. monad_inv. destruct H0; inv_base_step.
    { iFrame "∗#%". iMod "Hmask" as "_". iIntros "Hlc". iModIntro.
      by iApply "IH". }
    iMod "Hmask" as "_".
    iDestruct "Hg" as "[Hffi_global Hg]".
    iMod ("HΦ" with "[//] [$] [$]") as "H".
    iDestruct "H" as "(? & ? & ?)".
    iIntros "Hlc". iFrame "∗#%". done.
  Qed.

  (* TODO: add wp lemmas for each crypto op here *)

  Definition is_hash_proph_inv : iProp Σ :=
    inv nroot (∃ l, proph hash_proph_id l).

  Definition hash_fn (data : list w8) : option (list w8) :=
    if decide (data ∈ clean_hash_data) then Some (total_hash_fn data) else None.

  Context {sem_fn : GoSemanticsFunctions} {pre_sem : go.PreSemantics}.
  Lemma wp_Hash data :
    {{{ is_hash_proph_inv }}}
      ExternalOp Hash #data
    {{{ hash, RET #hash; ⌜ hash_fn data = Some hash ⌝ }}}.
  Proof.
    iIntros (Φ) "_ HΦ".
    iApply (wp_CryptoOp with "[-]").
    iIntros "!> * Hl Hg".
    inv_base_step. monad_inv.
    lazymatch goal with
    | H : (if decide _ then _ else _) |- _ => rename H into Hstep
    end.
    iDestruct "Hg" as "(% & %)".
    destruct decide in Hstep.
    { (* already hashed before. *)
      iFrame "∗#%". inv_base_step.
      iModIntro. iFrame "∗#%". iApply wp_value. iApply "HΦ".
      destruct g1. simpl in *. iPureIntro.
      unfold hash_fn. subst.
      rewrite decide_True //.
      eapply elem_of_prefix; eassumption. }
    destruct decide in Hstep.
    { (* ran into a collision *)
      inv_base_step. iFrame "∗#%". iModIntro.
      admit. (* FIXME: heapGS bundling annoyane *) }
    { (* first time computing this hash *)
      inv_base_step. iFrame "∗#%". iModIntro.
      iSplitR.
      - iPureIntro.
        Search prefix_of
    }
  Qed.

(* design sketch for proving wp_Hash:
- trusted code maintains this inv:
proph 0 suffix_data ∗
own_ffi_state prefix_data ∗
all_hash_data = prefix_data ++ suffix_data.
- Resolve op updates proph, while HashOp updates own_ffi_state.
- for consistency, need to update both of these atomically.
otherwise, the ffi state might not match all_hash_data,
preventing us from establishing hash_fn = Some.
- so, we wanna call Resolve atomically with HashOp, but how?
HashOp might infinite loop, which isn't atomic.
solution: have HashOp ret err on collision. Resolve with this err.
trusted code infinite loops after the Resolve.
we only have to establish hash_fn = Some at the end of trusted code.
- TODO: perennial doesn't have Resolve around atomic expression.
need to port iris's support for that.
*)

End lifting.


Section crypto_helpers.
  Existing Instances crypto_op crypto_model crypto_semantics crypto_interp goose_cryptoGS goose_cryptoNodeGS.
  Context `{!heapGS Σ}.


End crypto_helpers.

From Perennial.goose_lang Require Import adequacy.

(* #[global] *)
(* Program Instance crypto_interp_adequacy {go_gctx : GoGlobalContext} : *)
(*   @ffi_interp_adequacy crypto_model crypto_interp crypto_op crypto_semantics := *)
(*   {| ffiGpreS := cryptoGpreS; *)
(*      ffiΣ := cryptoΣ; *)
(*      subG_ffiPreG := subG_cryptoGpreS; *)
(*      ffi_initgP := λ g, True; *)
(*      ffi_initP := λ σ g, True; *)
(*   |}. *)
(* Next Obligation. *)
(*   rewrite //=. iIntros (_ Σ hPre g _). eauto. *)
(*   iExists (CryptoGS _ γ _). iFrame. eauto. *)
(* Qed. *)
(* Next Obligation. *)
(*   rewrite //=. *)
(*   iIntros (_ Σ hPre σ ??). *)
(*   (* TODO: allocate real per-node ghost state here *) *)
(*   iMod (mono_nat_own_alloc 0) as (γ) "[Hmono _]". *)
(*   iExists (CryptoNodeGS _ _ γ). eauto with iFrame. *)
(* Qed. *)
(* Next Obligation. *)
(*   intros ?. iIntros (Σ σ σ' Hcrash Hold) "Hctx". *)
(*   simpl in Hold. destruct Hcrash. *)
(*   iExists Hold. iFrame. iPureIntro. done. *)
(* Qed. *)
