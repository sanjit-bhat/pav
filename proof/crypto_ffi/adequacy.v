From Perennial.algebra Require Import gen_heap_names.
From Perennial.program_logic Require Import dist_lang.
From Perennial.goose_lang Require Import lang lifting.
From Cryptoffi Require Import crypto_ffi.

From Perennial.goose_lang Require Import adequacy recovery_adequacy dist_adequacy.

Set Default Proof Using "Type".

Existing Instances crypto_op crypto_model.
Existing Instances crypto_semantics crypto_interp.
Existing Instances goose_cryptoGS goose_cryptoNodeGS.

(* This is like the original, but gives [proph crypto_hash_proph_id .] so long
   as that proph_id is already marked as used. *)
Theorem goose_dist_adequacy `{ffi_sem: ffi_semantics}
  `{!ffi_interp ffi} {Hffi_adequacy:ffi_interp_adequacy}
  {go_gctx : GoGlobalContext}
  Σ `{!all.allG Σ} `{hPre: !gooseGpreS Σ} (ebσs : list node_init_cfg)
  g φinv (Hhash_proph : crypto_hash_proph_id ∈ g.(used_proph_id)) (HINITG: ffi_initgP g.(global_world)) (HINIT: ∀ σ, σ ∈ init_local_state <$> ebσs → ffi_initP σ.(world) g.(global_world))
  : (∀ `(HG : !gooseGlobalGS Σ),
      ⊢ ffi_global_start goose_ffiGlobalGS g.(global_world) ∗
        (∃ l, proph crypto_hash_proph_id l)
      ={⊤}=∗
        wpd ⊤ ebσs ∗
        (∀ g, ffi_global_ctx goose_ffiGlobalGS g.(global_world) -∗ |={⊤, ∅}=> ⌜ φinv g ⌝)) →
  dist_adequacy.dist_adequate (CS := goose_crash_lang) ebσs g (λ g, φinv g).
Proof.
  intros Hwp.
  eapply (dist_adequacy.wpd_dist_adequacy_inv Σ _ _ _ _ _ _ _ (λ n, 10 * (n + 1))%nat).
  iIntros (Hinv ?) "".
  iMod (ffi_global_init _ _ g.(global_world)) as (ffi_namesg) "(Hgw&Hgstart)"; first by auto.
  iMod (credit_name_init (crash_borrow_ginv_number)) as (name_credit) "(Hcred_auth&Hcred&Htok)".
  iMod (proph_map_init κs (g.(used_proph_id)∖{[crypto_hash_proph_id]})) as (proph_names) "Hproph".
  iMod (proph_map_new_proph crypto_hash_proph_id with "Hproph") as "[Hproph H]".
  { set_solver. }
  set (hG := GooseGlobalGS _ _ proph_names (creditGS_update_pre _ _ name_credit) ffi_namesg).

  iExists global_state_interp, fork_post.
  iExists _, _.

  iMod (Hwp hG with "[$]") as "(Hwp&Hφ)".

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
  iMod (ffi_local_init _ _ σ.(init_local_state).(world)) as (ffi_names) "(Hw&Hstart)".
  { eapply HINIT. apply list_elem_of_fmap. eexists. split; first done.
    eapply list_elem_of_lookup_2. done. }
  iMod (go_state_init) as (globals_name) "(Hg & Hg_auth)".
  set (hL := GooseLocalGS Σ Hc ffi_names σ.(init_local_state).(go_state).(go_lctx) (na_heapGS_update_pre _ name_na_heap)
                          (go_stateGS_update_pre Σ _ globals_name)
      ).

  iMod ("H" $! hL with "[$] [$]") as (Φ Φrx Φinv) "Hwpr".
  iModIntro. iExists state_interp, _, _, _.
  iSplitR "Hwpr"; first by iFrame.
  rewrite /wpr//=.
Qed.


Theorem crypto_ffi_dist_adequacy Σ {go_gctx : GoGlobalContext}
  {hGhost: all.allG Σ} `{hPre: !gooseGpreS Σ} ebσs g
  (Hhash_proph : crypto_hash_proph_id ∈ g.(used_proph_id))
  (Hprev_hash: g.(global_world).(crypto_hash_prev_data) = [])
  (φinv : _ → Prop) :
  (∀ HG : gooseGlobalGS Σ,
      ⊢@{iPropI Σ}
        (ffi_global_start goose_ffiGlobalGS g.(global_world) ∗
         ∃ l, proph crypto_hash_proph_id l) ={⊤}=∗
          (([∗ list] ρ ∈ ebσs,
                ∀ HL : gooseLocalGS Σ,
                  ffi_local_start goose_ffiLocalGS ρ.(init_local_state).(world) ={⊤}=∗
                  ∃ Φ Φc Φr, wpr NotStuck ⊤ ρ.(init_thread) ρ.(init_restart) Φ Φc Φr) ∗
          (∀ g', ffi_global_ctx goose_ffiGlobalGS g'.(global_world) ={⊤,∅}=∗ ⌜ φinv g' ⌝) )) →
  dist_adequacy.dist_adequate (CS := goose_crash_lang) ebσs g (λ g, φinv g).
Proof.
  intros H. eapply goose_dist_adequacy; try done.
  intros. iIntros "Hstart". iMod (H HG with "Hstart") as "(H1&H2)".
  iModIntro. iSplitL "H1".
  { iApply (big_sepL_mono with "H1").
    iIntros (? [e er σ] Hlookup) "H". iIntros. iSpecialize ("H" $! hG).
    iMod ("H" with "[$]") as "H".
    iDestruct "H" as (???) "H". iModIntro. iExists _, _, _. iFrame "H".
  }
  { eauto. }
Qed.

Theorem crypto_ffi_dist_adequacy_failstop Σ {go_gctx : GoGlobalContext}
  {hGhost: all.allG Σ} `{hPre: !gooseGpreS Σ}
  (ebσs : list (goose_lang.expr * state)) g (φinv : _ → Prop)
  (Hprev_hash: g.(global_world).(crypto_hash_prev_data) = []) :
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
  (Hprev_hash: g.(global_world).(crypto_hash_prev_data) = []) :
  (∀ (Hl : gooseLocalGS Σ) (Hg : gooseGlobalGS Σ),
    ⊢ ffi_global_start goose_ffiGlobalGS g.(global_world) -∗
      ffi_local_start goose_ffiLocalGS σ.(world)
      ={⊤}=∗
      WP e @ ⊤ {{ v, ⌜φ v⌝ }}) →
  adequate_failstop e σ g (λ v _ _, φ v).
Proof.
  intros. eapply goose_recv_adequacy_failstop; eauto; try done.
Qed.

Theorem crypto_ffi_dist_adequacy_with_hashes Σ {go_gctx : GoGlobalContext}
  {hGhost: all.allG Σ} `{hPre: !gooseGpreS Σ} ebσs g
  (Hhash_proph : crypto_hash_proph_id ∈ g.(used_proph_id)) (φinv : _ → Prop)
  (Hprev_hash: g.(global_world).(crypto_hash_prev_data) = []) :
  (∀ HG : gooseGlobalGS Σ,
      ⊢@{iPropI Σ}
        ∀ {hash_ctx : HashContext},
        is_hash_proph_inv ={⊤}=∗
          (([∗ list] ρ ∈ ebσs,
                ∀ HL : gooseLocalGS Σ,
                  ffi_local_start goose_ffiLocalGS ρ.(init_local_state).(world)
                    ={⊤}=∗ ∃ Φ Φc Φr, wpr NotStuck ⊤ ρ.(init_thread) ρ.(init_restart) Φ Φc Φr) ∗
          (∀ g', ffi_global_ctx goose_ffiGlobalGS g'.(global_world) ={⊤,∅}=∗ ⌜ φinv g' ⌝) )) →
  dist_adequacy.dist_adequate (CS := goose_crash_lang) ebσs g (λ g, φinv g).
Proof.
  intros H. eapply crypto_ffi_dist_adequacy; try done.
  iIntros "* Hstart".
  iDestruct (H _) as "H".
  iAssert (|={⊤}=> ∃ (hash_ctx :HashContext), is_hash_proph_inv)%I with "[Hstart]" as ">#[% ?]".
  2:{ iMod ("H" $! _ with "[$]"). iFrame. done. }
  simpl.
  iDestruct "Hstart" as "[? [% ?]]".
  iExists ({| all_hash_data := _|}).
  iMod (inv_alloc with "[-]") as "$"; last done.
  iFrame. iPureIntro. eexists. split_and!; simpl; try done.
  intros ?. intros. apply not_elem_of_nil in H0. done.
Qed.
