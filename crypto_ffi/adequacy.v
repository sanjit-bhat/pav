From Perennial.algebra Require Import gen_heap_names.
From Perennial.program_logic Require Import dist_lang.
From Perennial.goose_lang Require Import lang lifting.
From Cryptoffi Require Import crypto_ffi.

From Perennial.goose_lang Require Import adequacy recovery_adequacy dist_adequacy.

Set Default Proof Using "Type".

Existing Instances crypto_op crypto_model.
Existing Instances crypto_semantics crypto_interp.
Existing Instances goose_cryptoGS goose_cryptoNodeGS.

Theorem crypto_ffi_dist_adequacy Σ {go_gctx : GoGlobalContext}
  {hGhost: all.allG Σ} `{hPre: !gooseGpreS Σ} ebσs g (φinv : _ → Prop) :
  (∀ HG : gooseGlobalGS Σ,
      ⊢@{iPropI Σ}
        ffi_global_start goose_ffiGlobalGS g.(global_world) ={⊤}=∗
          (([∗ list] ρ ∈ ebσs,
                ∀ HL : gooseLocalGS Σ,
                  ffi_local_start goose_ffiLocalGS ρ.(init_local_state).(world)
                    ={⊤}=∗ ∃ Φ Φc Φr, wpr NotStuck ⊤ ρ.(init_thread) ρ.(init_restart) Φ Φc Φr) ∗
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
  (ebσs : list (goose_lang.expr * state)) g (φinv : _ → Prop) :
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
  {hGhost: all.allG Σ} `{hPre: !gooseGpreS Σ} e σ g φ :
  (∀ (Hl : gooseLocalGS Σ) (Hg : gooseGlobalGS Σ),
    ⊢ ffi_global_start goose_ffiGlobalGS g.(global_world) -∗
      ffi_local_start goose_ffiLocalGS σ.(world)
      ={⊤}=∗
      WP e @ ⊤ {{ v, ⌜φ v⌝ }}) →
  adequate_failstop e σ g (λ v _ _, φ v).
Proof.
  intros. eapply goose_recv_adequacy_failstop; eauto; try done.
Qed.
