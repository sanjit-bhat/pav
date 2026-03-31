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
Class cryptoGS Σ : Type := CryptoGS {
  prefix_gn : gname;
  total_hash_fn : list w8 → list w8;
  #[local] crypto_allG :: allG Σ;
}.

Class cryptoGpreS Σ : Type := {
  #[local] cryptopre_allG :: allG Σ;
}.

Class cryptoNodeGS Σ : Set := CryptoNodeGS {
}.

(* TODO: update with real ghost functors *)
Definition cryptoΣ : gFunctors := #[allΣ].

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
  Local Program Instance crypto_interp : ffi_interp crypto_model :=
    {| ffiGlobalGS := cryptoGS;
      ffiLocalGS := cryptoNodeGS;
      ffi_local_ctx _ _ σ := True%I;
      ffi_global_ctx _ _ g := (mono_list_auth_own prefix_gn (1/2) g.(crypto_hash_prev_data) ∗
                               ⌜ g.(crypto_total_hash_fn) = total_hash_fn ⌝)%I;
      ffi_local_start _ _ σ := True%I;
      ffi_global_start _ _ g := (mono_list_auth_own prefix_gn (1/2) g.(crypto_hash_prev_data))%I;
      ffi_restart _ _ _ := True%I;
      ffi_crash_rel Σ hF1 σ1 hF2 σ2 :=
        ⌜ hF1 = hF2 ⌝%I;
    |}.
End crypto.

Section lifting.
  Existing Instances crypto_op crypto_model crypto_semantics crypto_interp.
  Context `{!heapGS Σ}.
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

  Fixpoint has_hash all d : bool :=
    match all with
    | [] => false
    | d' :: all' =>
        if decide (d' = d) then true
        else if (decide (total_hash_fn d' = total_hash_fn d)) then false
             else has_hash all' d
    end.

  Class HashContext := {
    all_hash_data : list (list w8)
  }.

  Context {hash_ctx : HashContext}.

  Definition hash_fn (data : list w8) : option (list w8) :=
    if (has_hash all_hash_data data) then Some (total_hash_fn data) else None.

  Local Definition extract (vs : list val) : list (list w8) :=
    foldr (λ v l, match v with
                  | LitV (LitString x) => x :: l
                  | _ => l
                  end
      ) [] vs.

  Definition no_collisions (datas : list (list w8))  : Prop :=
    ∀ data data',
     data ∈ datas → data' ∈ datas →
     total_hash_fn data = total_hash_fn data' →
     data = data'.

  Lemma no_collisions_has_hash datas d:
    no_collisions datas →
    d ∈ datas →
    has_hash datas d = true.
  Proof.
    intros Hncoll. induction datas as [|d' datas IH]; [set_solver|].
    intros Hin. simpl. case_decide; [done|].
    case_decide.
    - exfalso. apply H. apply Hncoll; [set_solver..|done].
    - apply IH.
      + intros ?? Hin1 Hin2. apply Hncoll; set_solver.
      + rewrite elem_of_cons in Hin.
        destruct Hin as [->|]; [done|done].
  Qed.

  (* Lemma has_hash_subseteq datas pre suf d : *)
  (*   sub ⊆ datas → *)
  (*   has_hash datas d = true → *)
  (*   d ∈ sub → *)
  (*   has_hash sub d = true. *)
  (* Proof. *)
  (*   intros ->. induction pre as [|p pre IH]; [done|]. *)
  (*   simpl. repeat case_decide; naive_solver. *)
  (* Qed. *)

  (* Hpast_inv : past ⊆ crypto_hash_prev_data *)
  (* Hno_coll_inv : has_hash crypto_hash_prev_data data = true *)

  Lemma no_collisions_contained d l :
    d ∈ l →
    no_collisions l →
    no_collisions (l ++ [d]).
  Proof.
    intros Hin Hncoll data data' Hd Hd' Hhash.
    apply elem_of_app in Hd as [?|?%list_elem_of_singleton];
    apply elem_of_app in Hd' as [?|?%list_elem_of_singleton];
    subst; eauto using Hncoll.
  Qed.

  Lemma no_collisions_snoc l d :
    no_collisions l →
    total_hash_fn d ∉ (total_hash_fn <$> l) →
    no_collisions (l ++ [d]).
  Proof.
    intros Hncoll Hfresh data data' Hd Hd' Hhash.
    apply elem_of_app in Hd as [?|?%list_elem_of_singleton];
    apply elem_of_app in Hd' as [?|?%list_elem_of_singleton]; subst; eauto.
    - exfalso. apply Hfresh. apply list_elem_of_fmap. eauto.
    - exfalso. apply Hfresh. apply list_elem_of_fmap. exists data'. split; [done|done].
  Qed.

  Lemma has_hash_app_mid pre data suf :
    (∀ d, d ∈ pre → total_hash_fn d = total_hash_fn data → d = data) →
    has_hash (pre ++ data :: suf) data = true.
  Proof.
    induction pre as [|d' pre IH]; intros Hinj; simpl.
    - case_decide; done.
    - case_decide; [done|].
      case_decide.
      + exfalso. apply H. apply Hinj; [set_solver|done].
      + apply IH. intros. apply Hinj; set_solver.
  Qed.

  Lemma prefix_subseteq {A} (l l' : list A) :
    prefix l l' →
    l ⊆ l'.
  Proof.
    intros [? ?]. subst. set_solver.
  Qed.

  Definition is_hash_proph_inv : iProp Σ := (*  *)
    inv nroot (∃ past hash_prev future,
          "H●" ∷ mono_list_auth_own prefix_gn (1/2) hash_prev ∗
          "%Hall" ∷ ⌜ all_hash_data = past ++ (extract future) ⌝ ∗
          "%Hpast" ∷ ⌜ past ⊆ hash_prev ⌝ ∗
          "%Hno_coll" ∷ (⌜ no_collisions hash_prev ⌝) ∗
          "Hproph" ∷ proph crypto_hash_proph_id future).

  Context {sem_fn : GoSemanticsFunctions} {pre_sem : go.PreSemantics}.
  Lemma wp_Hash data :
    {{{ is_hash_proph_inv }}}
      ExternalOp Hash #data
    {{{ hash, RET #hash; ⌜ hash_fn data = Some hash ⌝ }}}.
  Proof using pre_sem.
    iIntros (Φ) "#Hinv HΦ".
    iApply (wp_CryptoOp with "[-]").
    iIntros "!> * Hl Hg".
    inv_base_step. monad_inv.
    lazymatch goal with
    | H : (if decide _ then _ else _) |- _ => rename H into Hstep
    end.
    iDestruct "Hg" as "(H● & %)". destruct g1. simpl in *. subst.
    iInv "Hinv" as ">Hi" "Hclose".
    iNamedSuffix "Hi" "_inv".
    iDestruct (mono_list_auth_own_agree with "[$] [$]") as "#[_ %Heq]".
    destruct decide in Hstep.
    { (* already hashed before. *)
      inv_base_step. iFrame "∗#%".
      iCombine "H● H●_inv" as "H●".
      iMod (mono_list_auth_own_update with "[$]") as "[[$ H●_inv] #Hlb]".
      { by eexists. }
      iCombineNamed "*_inv" as "Hi".
      iMod ("Hclose" with "[Hi]") as "_".
      { iNamed "Hi". iFrame "∗#%". iPureIntro.
        split.
        - set_solver.
        - by apply no_collisions_contained.
      }
      iModIntro. iFrame "∗#%". iSplitR; first done.

      wp_bind (ResolveProph _ _).
      iInv "Hinv" as ">Hi" "Hclose".
      iNamedSuffix "Hi" "_inv".
      (* FIXME: bind doesn't work *)
      iApply (wp_resolve_proph with "[$]").
      iIntros "!> % [% Hproph_inv]". subst.
      iDestruct (mono_list_auth_lb_valid with "[$] [$]") as %[_ Hlb].
      iCombineNamed "*_inv" as "Hi".
      iMod ("Hclose" with "[Hi]") as "_".
      { iNamed "Hi". iExists (past0 ++ [data]).
        iFrame "∗#%". iPureIntro.
        split.
        - rewrite Hall_inv0. rewrite -app_assoc.
          f_equal. rewrite go.into_val_unfold //.
        - apply prefix_subseteq in Hlb. set_solver.
      }
      iModIntro. wp_auto. wp_end. iPureIntro.
      unfold hash_fn.
      rewrite Hall_inv0 /extract -/extract go.into_val_unfold.
      rewrite has_hash_app_mid //.
      intros d Hd Hhash.
      apply Hno_coll_inv0; [| | done].
      { set_solver. }
      apply prefix_subseteq in Hlb.
      set_solver.
    }
    destruct decide in Hstep.
    { (* ran into a collision *)
      iCombineNamed "*_inv" as "Hi".
      iMod ("Hclose" with "[Hi]") as "_".
      { iNamed "Hi". iFrame "∗#%". }
      inv_base_step. iFrame "∗#%". iModIntro. iSplitR; first done.
      iApply wp_AngelicExit. }
    { (* already hashed before. *)
      inv_base_step. iFrame "∗#%".
      iCombine "H● H●_inv" as "H●".
      iMod (mono_list_auth_own_update with "[$]") as "[[$ H●_inv] #Hlb]".
      { by eexists. }
      iCombineNamed "*_inv" as "Hi".
      iMod ("Hclose" with "[Hi]") as "_".
      { iNamed "Hi". iFrame "∗#%". iPureIntro.
        split.
        - set_solver.
        - by apply no_collisions_snoc.
      }
      iModIntro. iFrame "∗#%". iSplitR; first done.

      wp_bind (ResolveProph _ _).
      iInv "Hinv" as ">Hi" "Hclose".
      iNamedSuffix "Hi" "_inv".
      (* FIXME: bind doesn't work *)
      iApply (wp_resolve_proph with "[$]").
      iIntros "!> % [% Hproph_inv]". subst.
      iDestruct (mono_list_auth_lb_valid with "[$] [$]") as %[_ Hlb].
      iCombineNamed "*_inv" as "Hi".
      iMod ("Hclose" with "[Hi]") as "_".
      { iNamed "Hi". iExists (past0 ++ [data]).
        iFrame "∗#%". iPureIntro.
        split.
        - rewrite Hall_inv0. rewrite -app_assoc.
          f_equal. rewrite go.into_val_unfold //.
        - apply prefix_subseteq in Hlb. set_solver.
      }
      iModIntro. wp_auto. wp_end.
      iPureIntro.
      unfold hash_fn.
      rewrite Hall_inv0 /extract -/extract go.into_val_unfold.
      rewrite has_hash_app_mid //.
      intros d Hd Hhash.
      apply Hno_coll_inv0; try done.
      { set_solver. }
      apply prefix_subseteq in Hlb.
      apply Hlb. set_solver.
    }
Qed.

End lifting.

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
  rewrite //=.
  iIntros (_ Σ hPre σ ?).
  iMod (mono_list_own_alloc) as (γ) "[Hmono _]".
  iExists (CryptoGS _ _ _ _). simpl. iModIntro.
  iDestruct "Hmono" as "[$ $]".
  done.
Qed.
Next Obligation.
  rewrite //=.
  iIntros (_ Σ hPre σ ??).
  iExists (CryptoNodeGS _). done.
Qed.
Final Obligation.
  intros ?. iIntros (Σ σ σ' Hcrash Hold) "Hctx".
  simpl in Hold. destruct Hcrash.
  iExists Hold. iFrame. iPureIntro. done.
Qed.
