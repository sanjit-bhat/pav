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
From Perennial.goose_lang.ffi.crypto_ffi Require Export impl.

Set Default Proof Using "Type".
Set Printing Projections.

(** * Crypto semantic interpretation and lifting lemmas *)

(* TODO: fill in with desired ghost state for global crypto resources *)
Class cryptoGS Σ : Set := CryptoGS {
  crypto_placeholder_name : gname;
  #[global] cryptoG_monoG :: mono_natG Σ; (* placeholder; replace with real ghost state *)
}.

(* TODO: fill in with pre-ghost state needed before initialization *)
Class cryptoGpreS Σ : Set := {
  #[global] crypto_preG_monoG :: mono_natG Σ; (* placeholder; replace with real ghost state *)
}.

(* TODO: fill in with desired ghost state for per-node crypto resources *)
Class cryptoNodeGS Σ : Set := CryptoNodeGS {
  #[global] cryptoG_preS :: cryptoGpreS Σ;
  crypto_node_placeholder_name : gname;
}.

(* TODO: update with real ghost functors *)
Definition cryptoΣ : gFunctors :=
  #[mono_natΣ].

#[global]
Instance subG_cryptoGpreS Σ : subG cryptoΣ Σ → cryptoGpreS Σ.
Proof. solve_inG. Qed.

Section crypto.
  (* these are local instances on purpose, so that importing this file doesn't
  suddenly cause all FFI parameters to be inferred as the crypto model *)
  Existing Instances crypto_op crypto_model.
  Context {go_gctx : GoGlobalContext}.

  (* TODO: fill in ffi_local_ctx, ffi_global_ctx, ffi_local_start, ffi_global_start,
     ffi_crash_rel with the actual state interpretation *)
  Local Program Instance crypto_interp: ffi_interp crypto_model :=
    {| ffiGlobalGS := cryptoGS;
       ffiLocalGS := cryptoNodeGS;
       ffi_local_ctx _ _ σ := True%I;
       ffi_global_ctx _ _ g := True%I;
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
      iSplitL; last done. by iApply "IH". }
    iMod "Hmask" as "_".
    iDestruct "Hg" as "[Hffi_global Hg]".
    iMod ("HΦ" with "[//] [$] [$]") as "H".
    iDestruct "H" as "(? & ? & ?)".
    iIntros "Hlc". iFrame "∗#%". done.
  Qed.

  (* TODO: add wp lemmas for each crypto op here *)

End lifting.

Section crypto_helpers.
  Existing Instances crypto_op crypto_model crypto_semantics crypto_interp goose_cryptoGS goose_cryptoNodeGS.
  Context `{!heapGS Σ}.

  (* TODO: add generally useful lemmas here *)

End crypto_helpers.

From Perennial.goose_lang Require Import adequacy.

#[global]
Program Instance crypto_interp_adequacy {go_gctx : GoGlobalContext} :
  @ffi_interp_adequacy crypto_model crypto_interp crypto_op crypto_semantics :=
  {| ffiGpreS := cryptoGpreS;
     ffiΣ := cryptoΣ;
     subG_ffiPreG := subG_cryptoGpreS;
     ffi_initgP := λ g, True;
     ffi_initP := λ σ g, True;
  |}.
Next Obligation.
  rewrite //=. iIntros (_ Σ hPre g _). eauto.
  (* TODO: allocate real ghost state here *)
  iMod (mono_nat_own_alloc 0) as (γ) "[Hmono _]".
  iExists (CryptoGS _ γ _). iFrame. eauto.
Qed.
Next Obligation.
  rewrite //=.
  iIntros (_ Σ hPre σ ??).
  (* TODO: allocate real per-node ghost state here *)
  iMod (mono_nat_own_alloc 0) as (γ) "[Hmono _]".
  iExists (CryptoNodeGS _ _ γ). eauto with iFrame.
Qed.
Next Obligation.
  intros ?. iIntros (Σ σ σ' Hcrash Hold) "Hctx".
  simpl in Hold. destruct Hcrash.
  iExists Hold. iFrame. iPureIntro. done.
Qed.
