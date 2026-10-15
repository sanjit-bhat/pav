From Perennial.algebra Require Import gen_heap_names.
From Perennial.program_logic Require Import dist_lang.
From Perennial.goose_lang Require Import lang lifting.
From Cryptoffi Require Import crypto_ffi.
From New.ghost Require Import mono_list.

From Perennial.goose_lang Require Import adequacy recovery_adequacy dist_adequacy.

Set Default Proof Using "Type".

Existing Instances crypto_op crypto_model.
Existing Instances crypto_semantics crypto_interp.
Existing Instances goose_cryptoGS goose_cryptoNodeGS.

(* Like Perennial's [goose_dist_adequacy], but it builds [cryptoGS] itself,
reading [all_hash_data] off the static hash prophecy. *)
Theorem crypto_ffi_dist_adequacy Σ {go_gctx : GoGlobalContext}
  {hGhost: all.allG Σ} `{hPre: !gooseGpreS Σ} ebσs g
  (Hhash_proph : crypto_hash_proph_id ∈ g.(used_proph_id))
  (Hprev_hash : g.(global_world).(crypto_hash_prev_data) = [])
  (Hhash_len : ∀ data, length (g.(global_world).(crypto_total_hash_fn) data) = hash_len)
  (φinv : _ → Prop) :
  (∀ HG : gooseGlobalGS Σ,
      ⊢@{iPropI Σ}
        is_hash_proph_inv ={⊤}=∗
          (([∗ list] ρ ∈ ebσs,
                ∀ HL : gooseLocalGS Σ,
                  ffi_local_start goose_ffiLocalGS ρ.(init_local_state).(world)
                    ={⊤}=∗ ∃ Φ Φc Φr, wpr NotStuck ⊤ ρ.(init_thread) ρ.(init_restart) Φ Φc Φr) ∗
          (∀ g', ffi_global_ctx goose_ffiGlobalGS g'.(global_world) ={⊤,∅}=∗ ⌜ φinv g' ⌝) )) →
  dist_adequacy.dist_adequate (CS := goose_crash_lang) ebσs g (λ g, φinv g).
Proof.
  intros Hwp.
  eapply (dist_adequacy.wpd_dist_adequacy_inv Σ _ _ _ _ _ _ _ (λ n, 10 * (n + 1))%nat).
  iIntros (Hinv κs) "".
  iMod (mono_list_own_alloc []) as (γ) "[[Hprev Hprev_inv] _]".
  iMod (credit_name_init (crash_borrow_ginv_number)) as (name_credit) "(Hcred_auth&Hcred&Htok)".
  iMod (proph_map_init κs (g.(used_proph_id)∖{[crypto_hash_proph_id]})) as (proph_names) "Hproph".
  iMod (proph_map_new_proph crypto_hash_proph_id with "Hproph") as "[Hproph Hhash_proph]".
  { set_solver. }
  set (hC := CryptoGS Σ γ _ Hhash_len
               (extract (proph_list_resolves κs crypto_hash_proph_id)) _).
  set (hG := GooseGlobalGS (ffi_interp0:=crypto_interp) _ _ proph_names
               (creditGS_update_pre _ _ name_credit) hC).
  iAssert (|={⊤}=> is_hash_proph_inv (gooseGlobalGS0:=hG))%I
    with "[Hprev_inv Hhash_proph]" as ">#Hhash_inv".
  { iApply inv_alloc. iNext. iExists [], [], _. iFrame "Hprev_inv Hhash_proph".
    iPureIntro. split_and!; [done|set_solver|]. intros ??. set_solver. }

  iExists global_state_interp, fork_post.
  iExists _, _.

  iMod (Hwp hG with "Hhash_inv") as "(Hwp&Hφ)".

  iAssert (|={⊤}=> crash_borrow_ginv)%I with "[Hcred]" as ">Hinv".
  { rewrite /crash_borrow_ginv. iApply (inv_alloc _). iNext. eauto. }
  iModIntro.
  replace ({[crypto_hash_proph_id]} ∪ g.(used_proph_id) ∖ {[crypto_hash_proph_id]})
            with g.(used_proph_id).
  2:{
    clear -Hhash_proph.
    apply union_difference_singleton_L.
    done.
  }

  iAssert (ffi_global_ctx (FfiInterp:=crypto_interp) hC g.(global_world)) with "[Hprev]" as "Hgw".
  { rewrite /= Hprev_hash. by iFrame. }
  iFrame "Hgw Hinv Hcred_auth Htok Hproph".
  iSplitR; first by eauto.
  iSplitL "Hwp"; last first.
  { iIntros (???) "Hσ".
    iApply ("Hφ" with "[Hσ]").
    iDestruct "Hσ" as "($&_)".
  }
  rewrite /wpd/dist_weakestpre.wpd.
  iApply (big_sepL_mono with "Hwp").
  iIntros (k' σ Hin) "H %Hc".

  iMod (na_heap_name_init tls σ.(init_local_state).(heap)) as (name_na_heap) "Hh".
  iMod (ffi_local_init _ _ σ.(init_local_state).(world) g.(global_world)) as (ffi_names) "(Hw&Hstart)".
  { done. }
  iMod (go_state_init) as (globals_name) "(Hg & Hg_auth)".
  set (hL := GooseLocalGS Σ Hc ffi_names σ.(init_local_state).(go_state).(go_lctx) (na_heapGS_update_pre _ name_na_heap)
                          (go_stateGS_update_pre Σ _ globals_name)
      ).

  iMod ("H" $! hL with "[$]") as (Φ Φrx Φinv) "Hwpr".
  iModIntro. iExists state_interp, _, _, _.
  iSplitR "Hwpr"; first by iFrame.
  rewrite /wpr//=.
Qed.

Theorem crypto_ffi_dist_adequacy_failstop Σ {go_gctx : GoGlobalContext}
  {hGhost: all.allG Σ} `{hPre: !gooseGpreS Σ}
  (ebσs : list (goose_lang.expr * state)) g (φinv : _ → Prop)
  (Hprev_hash: g.(global_world).(crypto_hash_prev_data) = [])
  (Hhash_len : ∀ data, length (g.(global_world).(crypto_total_hash_fn) data) = hash_len) :
  (∀ HG : gooseGlobalGS Σ,
      ⊢@{iPropI Σ}
        ffi_global_start goose_ffiGlobalGS g.(global_world) ={⊤}=∗
          (([∗ list] '(e, σ) ∈ ebσs,
                ∀ HL : gooseLocalGS Σ,
                  ffi_local_start goose_ffiLocalGS σ.(world) -∗
                  own_go_state σ.(go_state).(package_state)
                  ={⊤}=∗ ∃ Φ, wp NotStuck ⊤ e Φ
            ) ∗
          (∀ g', ffi_global_ctx goose_ffiGlobalGS g'.(global_world) ={⊤,∅}=∗ ⌜ φinv g' ⌝) )) →
  dist_adequate_failstop (ffi_sem:=crypto_semantics) ebσs g (λ g, φinv g).
Proof.
  intros H. eapply goose_dist_adequacy_failstop; try done.
  intros. iIntros "Hstart". iMod (H HG with "Hstart") as "(H1&H2)".
  iModIntro. iSplitL "H1".
  { iApply (big_sepL_mono with "H1").
    iIntros (? [e σ] Hlookup) "H". iIntros. iApply ("H" with "[$] [$]"). }
  { eauto. }
Qed.

Theorem crypto_ffi_single_node_adequacy_failstop Σ {go_gctx : GoGlobalContext}
  {hGhost: all.allG Σ} `{hPre: !gooseGpreS Σ} e σ g φ
  (Hprev_hash: g.(global_world).(crypto_hash_prev_data) = [])
  (Hhash_len : ∀ data, length (g.(global_world).(crypto_total_hash_fn) data) = hash_len) :
  (∀ (Hl : gooseLocalGS Σ) (Hg : gooseGlobalGS Σ),
    ⊢ ffi_global_start goose_ffiGlobalGS g.(global_world) -∗
      ffi_local_start goose_ffiLocalGS σ.(world)
      ={⊤}=∗
      WP e @ ⊤ {{ v, ⌜φ v⌝ }}) →
  adequate_failstop e σ g (λ v _ _, φ v).
Proof.
  intros. eapply goose_recv_adequacy_failstop; eauto; try done.
Qed.
