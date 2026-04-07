From New.generatedproof.github_com.sanjit_bhat.pav Require Import auditor.

From New.proof Require Import bytes sync.
From New.proof.github_com.goose_lang Require Import std.
From New.proof.github_com.sanjit_bhat.pav Require Import
  advrpc cryptoffi hashchain ktcore merkle server.

From New.proof.github_com.sanjit_bhat.pav.auditor_proof Require Import
  base rpc serde.

(* TODO: bad New.proof.sync exports.
https://github.com/mit-pdos/perennial/issues/470 *)
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

Module auditor.
Import base.auditor rpc.auditor serde.auditor.

(* TODO: upstream. *)
Lemma last_drop_Some {A} (l : list A) x n :
  last l = Some x →
  (n < length l)%nat →
  last (drop n l) = Some x.
Proof.
  intros (?&->)%last_Some ?.
  autorewrite with len in *.
  rewrite drop_app_le; [|lia].
  by rewrite last_snoc.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

(* 1/2 in Auditor pred, 1/2 in iris inv. *)
Definition own_aux γ σ q : iProp Σ :=
  "Hgs_digs" ∷ mono_list_auth_own (digsγ γ) q σ.(state.digs).

Definition own γ σ := own_aux γ σ (1/2).

Definition is_inv γ := inv nroot (∃ σ, own γ σ).

#[global] Instance own_timeless γ σ : Timeless (own γ σ).
Proof. apply _. Qed.

#[global] Instance own_aux_frac γ σ :
  fractional.Fractional (λ q, own_aux γ σ q).
Proof.
  rewrite /own_aux. intros ??. iSplit.
  - iIntros "@".
    iDestruct "Hgs_digs" as "[? ?]".
    iFrame "∗".
  - iIntros "[H0 H1]".
    iNamedSuffix "H0" "0".
    iNamedSuffix "H1" "1".
    iCombine "Hgs_digs0 Hgs_digs1" as "?".
    iFrame "∗".
Qed.

#[global] Instance own_aux_as_frac γ σ q :
  fractional.AsFractional (own_aux γ σ q) (λ q, own_aux γ σ q) q.
Proof. auto. Qed.

#[global] Instance own_aux_combine_sep_gives γ σ0 σ1 q0 q1 :
  CombineSepGives (own_aux γ σ0 q0) (own_aux γ σ1 q1) (⌜σ0 = σ1⌝).
Proof.
  rewrite /CombineSepGives /own_aux.
  iIntros "[H0 H1]".
  iNamedSuffix "H0" "0".
  iNamedSuffix "H1" "1".
  iDestruct (mono_list_auth_own_agree with "Hgs_digs0 Hgs_digs1") as %[? ?].
  iModIntro.
  destruct σ0, σ1. by simplify_eq/=.
Qed.

#[global] Instance own_aux_combine_sep_as γ σ0 σ1 q0 q1 :
  CombineSepAs (own_aux γ σ0 q0) (own_aux γ σ1 q1) (own_aux γ σ0 (q0 + q1)) | 60.
Proof.
  rewrite /CombineSepAs.
  iIntros "[H0 H1]".
  iCombine "H0 H1" gives %->.
  by iCombine "H0 H1" as "H".
Qed.

End proof.

Module serv.
Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr γ good : iProp Σ :=
  ∃ ptr_cli sl_sigPk sl_vrfPk sl_servVrfSig servVrfSig sl_adtrVrfSig adtrVrfSig,
  "#Hstr_serv" ∷ ptr ↦□ (auditor.serv.mk ptr_cli sl_sigPk sl_vrfPk sl_servVrfSig sl_adtrVrfSig) ∗
  "#His_rpc" ∷ server.is_rpc_cli ptr_cli good ∗
  "#Hsl_sigPk" ∷ sl_sigPk ↦*□ γ.(cfg.serv_sig_pk) ∗
  "#Hsl_vrfPk" ∷ sl_vrfPk ↦*□ vrf_pkγ γ ∗
  "#Hsl_servVrfSig" ∷ sl_servVrfSig ↦*□ servVrfSig ∗
  "#His_servVrfSig" ∷ ktcore.wish_VrfSig γ.(cfg.serv_sig_pk) (vrf_pkγ γ) servVrfSig ∗
  "#Hsl_adtrVrfSig" ∷ sl_adtrVrfSig ↦*□ adtrVrfSig ∗
  "#His_adtrVrfSig" ∷ ktcore.wish_VrfSig γ.(cfg.adtr_sig_pk) (vrf_pkγ γ) adtrVrfSig.

Definition align_serv γ servγ : iProp Σ :=
  (* trusted Auditor.New assumption. *)
  "%Heq_sig_pk" ∷ ⌜γ.(cfg.serv_sig_pk) = servγ.(server.cfg.sig_pk)⌝ ∗
  "#His_sig_pk" ∷ cryptoffi.is_sig_pk γ.(cfg.serv_sig_pk)
    (sigpred.P servγ.(server.cfg.sigγ)) ∗
  (* from signed vrf_pk. *)
  "%Heq_vrf_pk" ∷ ⌜vrf_pkγ γ = server.vrf_pkγ servγ⌝.

End proof.
End serv.

Module Auditor.
Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr γ σ q : iProp Σ :=
  ∃ ptr_sk ptr_hist ptr_serv,
  "#Hfld_sk" ∷ ptr.[auditor.Auditor.t, "sk"] ↦□ ptr_sk ∗
  "#Hfld_hist" ∷ ptr.[auditor.Auditor.t, "hist"] ↦□ ptr_hist ∗
  "#Hfld_serv" ∷ ptr.[auditor.Auditor.t, "serv"] ↦□ ptr_serv ∗

  "#Hown_sk" ∷ cryptoffi.own_sig_sk ptr_sk γ.(cfg.adtr_sig_pk)
    (sigpred.P γ.(cfg.sigγ)) ∗

  "Hown_hist" ∷ history.own ptr_hist γ σ q ∗
  "Hown_gs" ∷ own_aux γ σ (q/2) ∗
  "%Hmono_maps" ∷ ⌜ktcore.mono_plain (vrf_pkγ γ)
    (drop (audit_offsetγ γ) σ.(state.digs))⌝ ∗
  "#Halign_hist" ∷ match γ.(cfg.serv_good) with None => True | Some servγ =>
    history.align_serv σ γ servγ end ∗

  "#Hown_serv" ∷ serv.own ptr_serv γ γ.(cfg.serv_good) ∗
  "#Halign_serv" ∷ match γ.(cfg.serv_good) with None => True | Some servγ =>
    serv.align_serv γ servγ end.

Definition own_aux ptr γ q : iProp Σ := ∃ σ, own ptr γ σ q.

Definition lock_perm ptr γ : iProp Σ :=
  ∃ ptr_mu,
  "#Hfld_mu" ∷ ptr.[auditor.Auditor.t, "mu"] ↦□ ptr_mu ∗
  "Hperm" ∷ own_RWMutex ptr_mu (own_aux ptr γ).

#[global] Instance own_aux_frac ptr γ :
  fractional.Fractional (λ q, own_aux ptr γ q).
Proof.
  rewrite /own_aux. intros ??. iSplit.
  - iIntros "(%&%&@)".
    iDestruct "Hown_hist" as "[? ?]".
    rewrite Qp.div_add_distr.
    iDestruct "Hown_gs" as "[? ?]".
    iFrame "∗#%".
  - iIntros "[(%&%&H0)(%&%&H1)]".
    iNamedSuffix "H0" "0".
    iNamedSuffix "H1" "1".
    iCombine "Hfld_sk0 Hfld_sk1" gives %?.
    iCombine "Hfld_hist0 Hfld_hist1" gives %?.
    iCombine "Hfld_serv0 Hfld_serv1" gives %?.
    simplify_eq/=.
    iCombine "Hown_hist0 Hown_hist1" as "?".
    iCombine "Hown_gs0 Hown_gs1" as "?".
    rewrite -Qp.div_add_distr.
    iFrame "∗#%".
Qed.

#[global] Instance own_aux_as_frac ptr γ q :
  fractional.AsFractional (own_aux ptr γ q) (λ q, own_aux ptr γ q) q.
Proof. auto. Qed.

End proof.
End Auditor.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_CheckStartChain sl_servPk servPk ptr_chain chain :
  {{{
    is_pkg_init auditor ∗
    "#Hsl_servPk" ∷ sl_servPk ↦*□ servPk ∗
    "#Hown_chain" ∷ server.StartChain.own ptr_chain chain (□)
  }}}
  @! auditor.CheckStartChain #sl_servPk #ptr_chain
  {{{
    (ep : w64) sl_dig sl_link (err : bool),
    RET (#ep, #sl_dig, #sl_link, #err);
    "Hgenie" ∷
      match err with
      | true => ¬ ∃ digs cut ep dig link,
        server.wish_CheckStartChain servPk chain digs cut ep dig link
      | false =>
        ∃ digs cut dig link,
        "#Hsl_dig" ∷ sl_dig ↦*□ dig ∗
        "#Hsl_link" ∷ sl_link ↦*□ link ∗
        "#Hwish_CheckStartChain" ∷ server.wish_CheckStartChain servPk chain
          digs cut ep dig link
      end
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hown_chain". destruct chain. simpl.
  wp_auto.
  iDestruct (own_slice_len with "Hsl_PrevLink") as %[? _].
  wp_if_destruct.
  2: {
    iApply "HΦ". iIntros "@". simpl in *.
    destruct His_chain_prev as []. word. }
  opose proof (hashchain.invert PrevLink (uint.nat PrevEpochLen))
    as (?&?&His_chain_prev); [word|].
  wp_apply (hashchain.wp_Verify with "[]") as "* @".
  { iFrame "#%". }
  wp_if_destruct.
  { iApply "HΦ". iNamedSuffix 1 "'". simpl in *. iApply "Hgenie". naive_solver. }
  iNamed "Hgenie".
  iPersist "Hsl_newVal Hsl_newLink".
  wp_if_destruct.
  { iApply "HΦ". iNamedSuffix 1 "'". simpl in *.
    opose proof (hashchain.wish_Proof_det _ _ _ Hwish_chain His_proof') as ->.
    apply last_Some in Heq_dig' as [? Heq].
    apply (f_equal length) in Heq.
    autorewrite with len in *.
    word. }
  wp_apply std.wp_SumNoOverflow.
  wp_if_destruct.
  2: { iApply "HΦ". iNamedSuffix 1 "'". simpl in *.
    opose proof (hashchain.wish_Proof_det _ _ _ Hwish_chain His_proof') as ->.
    word. }
  wp_apply ktcore.wp_VerifyLinkSig as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iNamedSuffix 1 "'". simpl in *. iApply "Hgenie".
    opose proof (hashchain.wish_Proof_det _ _ _ Hwish_chain His_proof') as ->.
    opose proof (hashchain.inj His_chain_prev His_chain_prev') as [-> ->].
    simplify_eq/=.
    opose proof (hashchain.det' His_chain His_chain_start') as ->.
    iExactEq "His_link_sig'". repeat f_equal. word. }
  iNamed "Hgenie".
  iApply "HΦ".
  iFrame "#%". simpl in *.
  iPureIntro.

  destruct newVals as [|dig digs] using rev_ind; [|clear IHdigs].
  { exfalso. simpl in *. word. }
  rewrite last_snoc /=.
  autorewrite with len in *.
  eexists. split; [|repeat split].
  - exact_eq His_chain. word.
  - word.
Qed.

Lemma wp_CheckStartVrf sl_servPk servPk ptr_vrf vrf :
  {{{
    is_pkg_init auditor ∗
    "#Hsl_servPk" ∷ sl_servPk ↦*□ servPk ∗
    "#Hown_vrf" ∷ server.StartVrf.own ptr_vrf vrf (□)
  }}}
  @! auditor.CheckStartVrf #sl_servPk #ptr_vrf
  {{{
    ptr_vrfPk (err : bool),
    RET (#ptr_vrfPk, #err);
    "Hgenie" ∷
      match err with
      | true => ¬ server.wish_CheckStartVrf servPk vrf
      | false =>
        "#Hwish_CheckStartVrf" ∷ server.wish_CheckStartVrf servPk vrf ∗
        "#Hown_vrf_pk" ∷ cryptoffi.own_vrf_pk ptr_vrfPk vrf.(server.StartVrf.VrfPk)
      end
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hown_vrf". destruct vrf. simpl.
  wp_auto.
  wp_apply cryptoffi.wp_VrfPublicKeyDecode as "* @ {Hsl_enc}".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iNamedSuffix 1 "'". simpl in *. by iApply "Hgenie". }
  iNamed "Hgenie".
  wp_apply ktcore.wp_VerifyVrfSig as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iNamedSuffix 1 "'". simpl in *. by iApply "Hgenie". }
  iNamed "Hgenie".
  iDestruct (cryptoffi.own_vrf_pk_valid with "Hown_vrf_pk") as "#His_vrf_pk".
  iApply "HΦ".
  iFrame "#%".
Qed.

Lemma wp_getNextDig sl_prevDig prevDig sl_updates updates :
  {{{
    is_pkg_init auditor ∗
    "#Hsl_prevDig" ∷ sl_prevDig ↦*□ prevDig ∗
    "#Hown_updates" ∷ ktcore.UpdateProofSlice1D.own sl_updates updates (□)
  }}}
  @! auditor.getNextDig #sl_prevDig #sl_updates
  {{{
    sl_dig (err : bool), RET (#sl_dig, #err);
    "Hgenie" ∷
      match err with
      | true => ¬ ∃ dig, ktcore.wish_ListUpdate prevDig updates dig
      | false =>
        ∃ dig,
        "#Hsl_dig" ∷ sl_dig ↦*□ dig ∗
        (* caller doesn't need to know map update elems. just subset. *)
        "%Hsub" ∷ ⌜merkle.inv_fn prevDig ⊆ merkle.inv_fn dig⌝ ∗
        "#Hwish_ListUpdate" ∷ ktcore.wish_ListUpdate prevDig updates dig
      end
  }}}.
Proof.
  wp_start as "@". wp_auto.
  iDestruct "Hown_updates" as "(%sl0_updates&Hsl_updates&Hown_updates)".
  iDestruct (own_slice_len with "Hsl_updates") as %[? ?].
  iDestruct (big_sepL2_length with "Hown_updates") as %?.
  iAssert (
    ∃ (i : w64) sl_dig dig (x : loc),
    let pref_updates := take (sint.nat i) updates in
    "i" ∷ i_ptr ↦ i ∗
    "%Hlt_i" ∷ ⌜0 ≤ sint.Z i ≤ length updates⌝ ∗
    "u" ∷ u_ptr ↦ x ∗
    "err" ∷ err_ptr ↦ false ∗
    "dig" ∷ dig_ptr ↦ sl_dig ∗
    "#Hsl_dig" ∷ sl_dig ↦*□ dig ∗
    "%Hsub" ∷ ⌜merkle.inv_fn prevDig ⊆ merkle.inv_fn dig⌝ ∗
    "#Hwish" ∷ ktcore.wish_ListUpdate prevDig pref_updates dig
  )%I with "[-HΦ]" as "IH".
  { iFrame "∗#".
    rewrite take_0.
    repeat iSplit; [word|word|done|].
    iExists [prevDig].
    repeat iSplit; try done. naive_solver. }

  wp_for "IH".
  wp_if_destruct.
  2: {
    replace (sint.nat i) with (length updates) in * by word.
    rewrite take_ge; [|lia].
    iApply "HΦ". iFrame "#%". }

  list_elem sl0_updates (sint.Z i) as ptr_upd.
  list_elem updates (sint.Z i) as upd.
  iDestruct (big_sepL2_lookup with "Hown_updates") as "#Hown_upd"; [done..|].
  iNamed "Hown_upd".
  case_decide as Ht; [|word]. clear Ht.
  wp_bind.
  wp_apply wp_load_slice_index; [word|..].
  { by iFrame "#". }
  iIntros "_". wp_auto.
  wp_apply merkle.wp_VerifyUpdate as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { wp_for_post. iApply "HΦ".
    iNamedSuffix 1 "0". iNamed "Hwish_aux0". iApply "Hgenie".
    iDestruct (big_sepL_lookup with "Hwish_upds") as "H"; [done|].
    iNamedSuffix "H" "0". iFrame "#". }
  iNamed "Hgenie".
  wp_apply bytes.wp_Equal as "_".
  { iFrame "#". }
  wp_if_destruct.
  2: { wp_for_post. iApply "HΦ".
    iNamedSuffix 1 "0". iNamed "Hwish".
    iDestruct (ktcore.wish_ListUpdate_aux_take (sint.nat i) with "Hwish_aux0") as "Hwish_aux1".
    iDestruct (ktcore.wish_ListUpdate_aux_det with "Hwish_aux Hwish_aux1") as %->.
    iNamed "Hwish_aux0".
    iDestruct (big_sepL_lookup with "Hwish_upds") as "@"; [done|].
    iDestruct (merkle.wish_Update_det with "His_proof Hwish_upd") as %[-> ->].
    rewrite last_lookup in Hlast.
    apply lookup_take_Some in Hlast as [Hlast _].
    replace (pred _) with (sint.nat i) in Hlast by len.
    by simplify_eq/=. }
  wp_for_post.
  iFrame "∗#".
  iSplit; [word|].
  iSplit.
  - iPureIntro.
    trans (merkle.inv_fn oldHash); try done.
    rewrite Hupd.
    by apply insert_subseteq.
  - replace (sint.nat (word.add _ _)) with (S $ sint.nat i) by word.
    erewrite take_S_r; [|done].
    destruct upd.
    iApply ktcore.wish_ListUpdate_grow; iFrame "#".
Qed.

Lemma wp_getNextLink γ σ sl_sigPk (prevEp : w64) sl_prevDig prevDig
    sl_prevLink prevLink ptr_p proof :
  {{{
    is_pkg_init auditor ∗
    "#Hsl_sigPk" ∷ sl_sigPk ↦*□ γ.(cfg.serv_sig_pk) ∗
    "#Hsl_prevDig" ∷ sl_prevDig ↦*□ prevDig ∗
    "#Hsl_prevLink" ∷ sl_prevLink ↦*□ prevLink ∗
    "#Hproof" ∷ ktcore.AuditProof.own ptr_p proof (□) ∗

    "%Heq_prevEp" ∷ ⌜uint.Z prevEp = start_epγ γ + length σ.(state.digs) - 1⌝ ∗
    "%Heq_prevDig" ∷ ⌜last σ.(state.digs) = Some prevDig⌝ ∗
    "#His_prevLink" ∷ ⌜hashchain.valid σ.(state.digs)
      (cutγ γ) prevLink (S $ uint.nat prevEp)⌝
  }}}
  @! auditor.getNextLink #sl_sigPk #prevEp #sl_prevDig #sl_prevLink #ptr_p
  {{{
    ep sl_dig sl_link err, RET (#ep, #sl_dig, #sl_link, #err);
    "Hgenie" ∷
      match err with
      | true => ¬ ∃ ep dig link, wish_getNextLink γ σ proof ep dig link
      | false =>
        ∃ dig link,
        "#Hsl_dig" ∷ sl_dig ↦*□ dig ∗
        "#Hsl_link" ∷ sl_link ↦*□ link ∗
        "#Hwish_getNextLink" ∷ wish_getNextLink γ σ proof ep dig link ∗
        "%Hsub" ∷ ⌜merkle.inv_fn prevDig ⊆ merkle.inv_fn dig⌝
      end
  }}}.
Proof.
  wp_start as "@". wp_auto.
  iNamed "Hproof".
  wp_apply std.wp_SumNoOverflow.
  wp_if_destruct.
  2: { iApply "HΦ". iNamedSuffix 1 "0". word. }
  wp_apply wp_getNextDig as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iNamedSuffix 1 "0". iApply "Hgenie".
    simplify_eq/=. iFrame "#". }
  iNamed "Hgenie".
  wp_apply hashchain.wp_GetNextLink as "* H".
  { iFrame "#". }
  iDestruct "H" as "(_&_&H)".
  iNamed "H". iPersist "Hsl_nextLink".
  wp_apply ktcore.wp_VerifyLinkSig as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iNamedSuffix 1 "0". iApply "Hgenie".
    simplify_eq/=.
    iDestruct (ktcore.wish_ListUpdate_det with "Hwish_ListUpdate His_upd0") as %<-.
    opose proof (hashchain.det' His_chain His_link0) as ->.
    iExactEq "His_sig0". f_equal. word. }
  iNamed "Hgenie".
  iApply "HΦ". iFrame "#%".
  iSplit; [word|].
  iPureIntro. exact_eq His_chain. f_equal. word.
Qed.

Definition wish_SignedLink servPk adtrPk ep link : iProp Σ :=
  "#Hwish_adtr_sig" ∷ ktcore.wish_LinkSig adtrPk ep
    link.(SignedLink.Link) link.(SignedLink.AdtrSig) ∗
  "#Hwish_serv_sig" ∷ ktcore.wish_LinkSig servPk ep
    link.(SignedLink.Link) link.(SignedLink.ServSig).

Definition wish_SignedVrf servPk adtrPk vrf : iProp Σ :=
  "#Hwish_adtr_sig" ∷ ktcore.wish_VrfSig adtrPk
    vrf.(SignedVrf.VrfPk) vrf.(SignedVrf.AdtrSig) ∗
  "#Hwish_serv_sig" ∷ ktcore.wish_VrfSig servPk
    vrf.(SignedVrf.VrfPk) vrf.(SignedVrf.ServSig).

Lemma wp_Auditor_Get a γ epoch Q :
  {{{
    is_pkg_init auditor ∗
    "Hlock" ∷ Auditor.lock_perm a γ ∗
    "#Hfupd" ∷ □ (|={⊤,∅}=> ∃ σ, own γ σ ∗
      (own γ σ ={∅,⊤}=∗ Q σ))
  }}}
  a @! (go.PointerType auditor.Auditor) @! "Get" #epoch
  {{{
    ptr_link ptr_vrf err σ, RET (#ptr_link, #ptr_vrf, #err);
    "Hlock" ∷ Auditor.lock_perm a γ ∗
    "HQ" ∷ Q σ ∗
    "#Herr" ∷
      match err with
      | true => ⌜uint.Z epoch < start_epγ γ + audit_offsetγ γ ∨
        uint.Z epoch >= start_epγ γ + length σ.(state.digs)⌝
      | false =>
        ∃ link vrf,
        "#Hown_link" ∷ SignedLink.own ptr_link link (□) ∗
        "#Hown_vrf" ∷ SignedVrf.own ptr_vrf vrf (□) ∗
        "#Hwish_link" ∷ wish_SignedLink γ.(cfg.serv_sig_pk) γ.(cfg.adtr_sig_pk) epoch link ∗
        "#Hwish_vrf" ∷ wish_SignedVrf γ.(cfg.serv_sig_pk) γ.(cfg.adtr_sig_pk) vrf ∗
        "%Heq_vrf" ∷ ⌜vrf.(SignedVrf.VrfPk) = vrf_pkγ γ⌝
      end
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hlock".
  wp_apply wp_with_defer as "* Hdefer".
  simpl. wp_auto.
  wp_apply (wp_RWMutex__RLock with "[$Hperm]") as "[Hlocked H]".
  iNamed "H". iNamed "Hown_hist". wp_auto.
  iApply ncfupd_wp.
  iMod "Hfupd" as "(%&Hadtr&Hfupd)".
  iCombine "Hadtr Hown_gs" gives %->.
  iMod ("Hfupd" with "Hadtr") as "HQ".
  iModIntro.

  iDestruct (own_slice_len with "Hsl_epochs") as %[? ?].
  wp_if_destruct.
  { wp_apply (wp_RWMutex__RUnlock with "[-HΦ HQ]") as "Hlock".
    { iFrame "∗∗ Hown_serv #%". }
    iApply "HΦ".
    iFrame "∗#".
    word. }
  wp_if_destruct.
  { wp_apply (wp_RWMutex__RUnlock with "[-HΦ HQ]") as "Hlock".
    { iFrame "∗∗ Hown_serv #%". }
    iApply "HΦ".
    iFrame "∗#".
    iPureIntro. word. }
  case_decide as Ht; [|word]. clear Ht.
  list_elem sl0_epochs (sint.nat (word.sub epoch start_ep)) as ptr_epoch.
  iDestruct (big_sepL_lookup with "Hepochs") as "@"; [done|].
  iNamed "Hown_serv".
  wp_apply (wp_load_slice_index with "[$Hsl_epochs]"); [word|done|].
  iIntros "Hsl_epochs". wp_auto.
  wp_apply wp_alloc as "* Hptr_link".
  wp_apply wp_alloc as "* Hptr_vrf".
  iPersist "Hptr_link Hptr_vrf".
  wp_apply (wp_RWMutex__RUnlock with "[-HΦ HQ]") as "Hlock".
  { iFrame "∗∗ Hstr_serv #%". }
  iApply "HΦ".
  iFrame "Hfld_mu ∗".
  iExists (SignedLink.mk' _ _ _), (SignedVrf.mk' _ _ _).
  simpl in *.
  replace (W64 (uint.nat _ + sint.nat _)%nat) with epoch by word.
  by iFrame "#".
Qed.

Lemma wp_Auditor_updOnce ptr_a γ σ Q ptr_proof proof :
  {{{
    is_pkg_init auditor ∗
    "Hadtr" ∷ Auditor.own ptr_a γ σ 1 ∗
    "#Hfupd" ∷ □ (|={⊤,∅}=> ∃ σ, own γ σ ∗
      (∀ new_digs,
      let σ' := set state.digs (.++ new_digs) σ in
      own γ σ' ={∅,⊤}=∗ Q σ')) ∗

    "#Hproof" ∷ ktcore.AuditProof.own ptr_proof proof (□) ∗
    "Hgood" ∷ match γ.(cfg.serv_good) with None => True | Some servγ =>
      ∃ ep dig link,
      let σ' := set state.digs (.++ [dig]) σ in
      "#Hwish_getNextLink" ∷ wish_getNextLink γ σ proof ep dig link ∗
      "#Halign_next" ∷ history.align_serv σ' γ servγ end
  }}}
  ptr_a @! (go.PointerType auditor.Auditor) @! "updOnce" #ptr_proof
  {{{
    err, RET #(ktcore.blame_to_u64 err);
    "%Hblame" ∷ ⌜ktcore.BlameSpec err
      {[ktcore.BlameServFull:=option_bool γ.(cfg.serv_good)]}⌝ ∗
    "Herr" ∷
      (if decide (err ≠ ∅)
      then
        "Hadtr" ∷ Auditor.own ptr_a γ σ 1 ∗
        "HQ" ∷ Q σ
      else
        ∃ new_dig,
        let σ' := set state.digs (.++ [new_dig]) σ in
        "Hadtr" ∷ Auditor.own ptr_a γ σ' 1 ∗
        "HQ" ∷ Q σ')
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hadtr". iNamed "Hown_hist". iNamed "Hown_serv". wp_auto.
  iDestruct (own_slice_len with "Hsl_epochs") as %[? ?].
  list_elem sl0_epochs
    (sint.nat (word.sub sl_epochs.(slice.len) (W64 1))) as ptr_epoch.
  iDestruct (big_sepL_lookup with "Hepochs") as "@"; [done|].
  case_decide as Ht; [|word]. clear Ht.
  wp_apply (wp_load_slice_index with "[$Hsl_epochs]"); [word|done|].
  iIntros "Hsl_epochs". wp_auto.
  wp_apply (wp_getNextLink γ σ) as "* @".
  { simpl. iFrame "#%".
    iSplit; [word|].
    iPureIntro. exact_eq His_link; [|word].
    rewrite take_ge; [done|]. word. }
  clear His_link.
  rewrite -wp_fupd.
  wp_if_destruct.
  { iMod "Hfupd" as "(%&Hadtr&Hfupd)".
    iCombine "Hadtr Hown_gs" gives %->.
    destruct σ.
    iSpecialize ("Hfupd" $! []).
    list_simplifier.
    iMod ("Hfupd" with "Hadtr") as "HQ".
    iModIntro.
    rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iSplit.
    2: { case_decide; try done. iFrame "∗ Hstr_serv #%". }
    iApply ktcore.blame_one.
    iIntros (?).
    case_match; try done.
    iApply "Hgenie".
    iNamed "Hgood".
    iFrame "#". }
  iNamedSuffix "Hgenie" "_n".

  iApply ncfupd_wp.
  rewrite /own.
  iMod "Hfupd" as "(%σ'&Hown_gs'&Hfupd)".
  destruct σ'.
  iCombine "Hown_gs Hown_gs'" as "Hown_gs" gives %?.
  rewrite Qp.half_half.
  simplify_eq/=.
  rewrite /own_aux. iNamed "Hown_gs". simpl.
  iMod (mono_list_auth_own_update_app [dig] with "Hgs_digs") as "[[Hhist Hhist'] #Hlb_hist]".
  iMod ("Hfupd" with "[$Hhist']") as "HQ".
  iAssert (own_aux _ (state.mk _) (1/2))%I with "[$Hhist]" as "Hown_gs".
  iModIntro.

  iPoseProof "Hwish_getNextLink_n" as "H".
  iNamedSuffix "H" "_n".
  simplify_eq/=.
  eassert (ktcore.mono_plain (vrf_pkγ γ)
    (drop (audit_offsetγ γ) (digs ++ [_]))) as Hmono_plain'.
  { rewrite drop_app_le; [|lia].
    unfold ktcore.mono_plain in *.
    rewrite !fmap_app.
    eapply list_reln_snoc; [done|].
    intros * Hlast_hist.
    rewrite !fmap_last in Hlast_hist.
    erewrite last_drop_Some in Hlast_hist; [|done|word].
    simplify_eq/=.
    by apply ktcore.plain_inv_mono. }
  clear Hmono_maps.
  iNamed "Hproof".
  wp_apply ktcore.wp_SignLink as "* @".
  { iFrame "#%".
    iPureIntro. split; [len|word]. }

  wp_apply wp_alloc as "* Hstr_epoch_n".
  iPersist "Hstr_epoch_n".
  wp_apply wp_slice_literal. iSplitR; first done. iIntros "* [Ht _]". wp_auto.
  replace (sint.nat (W64 0)) with 0%nat by word. simpl.
  wp_apply (wp_slice_append with "[$Hsl_epochs $Hcap_epochs $Ht]")
    as "* (Hsl_epochs&Hcap_epochs&_)".
  iModIntro.
  rewrite ktcore.rw_BlameNone.
  iApply "HΦ".
  iSplit. { iPureIntro. apply ktcore.blame_none. }
  case_decide; try done.
  iFrame "∗".
  iFrame "Hstr_serv #".
  simpl in *.
  replace (W64 (_ + (_ + _))%nat) with ep by word.
  iFrame "#%".
  autorewrite with len.
  repeat iSplit; try iPureIntro.
  - by rewrite last_snoc.
  - iApply big_sepL_impl; [done|].
    iIntros "!> * %Hlook H".
    rewrite /epoch.own /=.
    apply lookup_lt_Some in Hlook.
    rewrite take_app_le; [|word].
    iFrame.
  - exact_eq His_link_n; [|word].
    rewrite take_ge; [done|len].
  - word.
  - word.
  - word.
  - word.
  - case_match; try done.
    iNamed "Hgood".
    iDestruct (wish_getNextLink_det with "Hwish_getNextLink Hwish_getNextLink_n") as %?.
    destruct_and!. simplify_eq/=.
    iFrame "#".
Qed.

Lemma wp_Auditor_Update ptr_a γ Q :
  {{{
    is_pkg_init auditor ∗
    "Hlock" ∷ Auditor.lock_perm ptr_a γ ∗
    (* pers fupd so that Auditor can add mult links,
    or even run Update as a background thread. *)
    "#Hfupd" ∷ □ (|={⊤,∅}=> ∃ σ, own γ σ ∗
      (∀ new_digs,
      let σ' := set state.digs (.++ new_digs) σ in
      own γ σ' ={∅,⊤}=∗ Q σ'))
  }}}
  ptr_a @! (go.PointerType auditor.Auditor) @! "Update" #()
  {{{
    err σ, RET #(ktcore.blame_to_u64 err);
    "Hlock" ∷ Auditor.lock_perm ptr_a γ ∗
    "%Hblame" ∷ ⌜ktcore.BlameSpec err
      {[ktcore.BlameServFull:=option_bool γ.(cfg.serv_good)]}⌝ ∗
    "HQ" ∷ Q σ
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hlock".
  wp_apply wp_with_defer as "* Hdefer".
  (* TODO(goose): wp_with_defer adds [subst] expr.
  almost always call [simpl] after. *)
  simpl. wp_auto.
  wp_apply (wp_RWMutex__Lock with "[$Hperm]") as "[Hlocked H]".
  iNamed "H". iNamed "Hown_hist". iNamed "Hown_serv". wp_auto.
  iDestruct (own_slice_len with "Hsl_epochs") as %[? ?].
  wp_apply wp_CallAudit as "* @".
  { iFrame "#".
    case_match; try done.
    iNamed "Halign_hist".
    remember (uint.nat (word.sub _ _)) as ep.
    list_elem hist ep as e.
    iDestruct (mono_list_idx_own_get with "His_hist") as "Hidx"; [done|].
    iFrame "#". }
  rewrite -ncfupd_wp.
  iPoseProof "Hfupd" as "H".
  iMod "H" as "(%&Hadtr&Hclose)".
  iCombine "Hadtr Hown_gs" gives %->.
  destruct σ.
  iSpecialize ("Hclose" $! []).
  list_simplifier.
  iMod ("Hclose" with "Hadtr") as "HQ".
  iModIntro.
  case_bool_decide as Heq_err; wp_auto;
    rewrite ktcore.rw_Blame0 in Heq_err; subst.
  2: {
    wp_apply (wp_RWMutex__Unlock with "[-HΦ HQ]") as "Hlock".
    { iFrame "∗∗ Hstr_serv #%". }
    iApply "HΦ".
    iFrame "∗#%". }
  case_decide; try done.
  iNamed "Herr".

  iPersist "Hdefer a".
  iAssert (
    ∃ new_digs (i : w64) (a0 : loc),
    "i" ∷ i_ptr ↦ i ∗
    "p" ∷ p_ptr ↦ a0 ∗
    "%Hlt_i" ∷ ⌜0 ≤ sint.Z i ≤ length proofs⌝ ∗
    "err" ∷ err_ptr ↦ ktcore.blame_to_u64 ∅ ∗

    "HΦ" ∷ (∀ (err : ktcore.Blame) (σ0 : state.t),
             "Hlock" ∷ Auditor.lock_perm ptr_a γ ∗
             "%Hblame"
             ∷ ⌜ktcore.BlameSpec err
                  {[ktcore.BlameServFull := option_bool γ.(cfg.serv_good)]}⌝ ∗
             "HQ" ∷ Q σ0 -∗ Φ (# (ktcore.blame_to_u64 err))) ∗
    "Hlocked" ∷ own_RWMutex_Locked ptr_mu (Auditor.own_aux ptr_a γ) ∗

    "Hadtr" ∷ Auditor.own ptr_a γ (state.mk (digs ++ new_digs)) 1 ∗
    "%Hlen_new_digs" ∷ ⌜length new_digs = sint.nat i⌝ ∗
    "HQ" ∷ Q (state.mk (digs ++ new_digs))
  )%I with "[-]" as "IH".
  { iExists []. list_simplifier.
    iFrame "∗ Hstr_serv #%". simpl. word. }
  wp_for "IH".
  wp_if_destruct.
  2: {
    wp_apply (wp_RWMutex__Unlock with "[-HΦ HQ]") as "Hlock".
    { iFrame "∗ Hadtr". }
    iApply "HΦ".
    iFrame "∗#%". }

  iClear "HQ".
  iDestruct "Hsl_proofs" as "(%&Hsl0_proofs&Hsl_proofs)".
  iDestruct (own_slice_len with "Hsl0_proofs") as %[? ?].
  iDestruct (big_sepL2_length with "Hsl_proofs") as %?.
  list_elem proofs (sint.nat i) as proof.
  iDestruct (big_sepL2_lookup_2_some with "Hsl_proofs") as %[? ?]; [done|].
  iDestruct (big_sepL2_lookup with "Hsl_proofs") as "Hproof"; [done..|].
  case_decide as Ht; [|word]. clear Ht.
  wp_apply wp_load_slice_index as "_"; [word|..].
  { by iFrame "#". }
  iNamedSuffix "Hadtr" "0".
  wp_apply (wp_Auditor_updOnce with "[Hfld_hist0 Hown_hist0 Hown_gs0]") as "* @".
  { iFrame "∗ Hown_serv0 #%".
    case_match; try done.
    iDestruct (big_sepL_lookup with "Hgood") as "{Hgood} Htrans"; [done|].
    iDestruct ("Htrans" with "Halign_hist0 [][]") as "{Htrans} $".
    { simpl. len. }
    by iNamed "Halign_serv0". }
  case_bool_decide as Heq_err; wp_auto;
    rewrite ktcore.rw_Blame0 in Heq_err; subst.
  2: {
    case_decide; try done.
    iNamed "Herr".
    wp_for_post.
    wp_apply (wp_RWMutex__Unlock with "[-HΦ HQ]") as "Hlock".
    { iFrame "∗ Hadtr". }
    iApply "HΦ".
    iFrame "∗#%". }
  case_decide; try done.
  iNamed "Herr".
  wp_for_post.
  list_simplifier.
  iFrame.
  len.
Qed.

Lemma wp_New servGood (servAddr : w64) sl_servPk servPk :
  {{{
    is_pkg_init auditor ∗
    "#Hsl_servPk" ∷ sl_servPk ↦*□ servPk ∗
    "%Heq_servPk" ∷ ⌜match servGood with None => True | Some servγ =>
      servPk = servγ.(server.cfg.sig_pk) end⌝ ∗
    "#His_servPk" ∷ match servGood with None => True | Some servγ =>
      cryptoffi.is_sig_pk servPk (sigpred.P servγ.(server.cfg.sigγ)) end
  }}}
  @! auditor.New #servAddr #sl_servPk
  {{{
    ptr_a sl_sigPk err, RET (#ptr_a, #sl_sigPk, #(ktcore.blame_to_u64 err));
    "%Hblame" ∷ ⌜ktcore.BlameSpec err
      {[ktcore.BlameServFull:=option_bool servGood]}⌝ ∗
    "Herr" ∷ (if decide (err ≠ ∅) then True else
      ∃ γ,
      "#His_inv" ∷ is_inv γ ∗
      "Hlocks" ∷ ([∗] replicate (Z.to_nat rwmutex.actualMaxReaders)
        (Auditor.lock_perm ptr_a γ)) ∗
      "%Heq_servGood" ∷ ⌜γ.(cfg.serv_good) = servGood⌝ ∗

      "#Hsl_sigPk" ∷ sl_sigPk ↦*□ γ.(cfg.adtr_sig_pk) ∗
      "#His_sigPk" ∷ cryptoffi.is_sig_pk γ.(cfg.adtr_sig_pk)
        (sigpred.P γ.(cfg.sigγ)))
  }}}.
Proof.
  wp_start as "@". wp_auto.
  wp_apply (server.wp_Dial servGood) as "* @".
  wp_apply server.wp_CallStart as "* @".
  { iFrame "#". }
  case_bool_decide as Heq_err; wp_auto;
    rewrite ktcore.rw_Blame0 in Heq_err; subst.
  2: {
    iApply "HΦ".
    iFrame "%".
    by case_decide. }
  case_decide; try done.
  iNamed "Herr".
  wp_apply wp_CheckStartChain as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iSplit. 2: { by case_decide. }
    iApply ktcore.blame_one.
    iIntros (?).
    case_match; try done.
    simplify_eq/=.
    iApply "Hgenie".
    iNamed "Hgood".
    iFrame "#". }
  iNamed "Hgenie".
  iDestruct (server.wish_CheckStartChain_extract with "Hwish_CheckStartChain") as "@".
  wp_apply wp_CheckStartVrf as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iSplit. 2: { by case_decide. }
    iApply ktcore.blame_one.
    iIntros (?).
    case_match; try done.
    simplify_eq/=.
    iApply "Hgenie".
    iNamed "Hgood".
    iFrame "#". }
  iNamed "Hgenie".

  wp_apply wp_alloc as "* Hmu".
  iMod (mono_list_own_alloc digs) as (digsγ) "[Hauth_digs #Hlb_digs]".
  remember (sigpred.cfg.mk vrf.(server.StartVrf.VrfPk) digsγ
    (sigpred.digs_info.mk (S (uint.nat ep) - length digs)%nat cut
      (pred $ length digs)))
    as sigγ.
  assert (ktcore.mono_plain sigγ.(sigpred.cfg.vrf_pk)
    (drop sigγ.(sigpred.cfg.info).(sigpred.digs_info.audit_offset) digs)).
  { simplify_eq/=.
    apply last_Some in Hlast_digs as (digs'&->).
    replace (pred _) with (length digs'); [|len].
    rewrite drop_app_length /ktcore.mono_plain.
    apply server.list_reln_singleton. }
  iAssert (⌜0 < length digs ≤ S $ uint.nat ep⌝)%I as %?.
  { rewrite last_lookup in Hlast_digs.
    apply lookup_lt_Some in Hlast_digs.
    iNamed "Hwish_CheckStartChain".
    apply hashchain.fuel_bound' in His_chain_start as ?.
    word. }
  wp_apply (cryptoffi.wp_SigGenerateKey (sigpred.P sigγ)) as "* @".
  iPersist "Hsl_sigPk".
  iNamed "Hptr_chain".
  wp_apply ktcore.wp_SignLink as "* @".
  { iFrame "#". rewrite /linkP. simplify_eq/=.
    iNamed "Hwish_CheckStartChain".
    iFrame "#%". word. }

  wp_apply wp_alloc as "* Hstr_epoch".
  iPersist "Hstr_epoch".
  wp_apply wp_slice_literal. iSplitR; [done|].
  iIntros "* [Hsl_epochs Hcap_epochs]". wp_auto.
  replace (sint.nat (W64 0)) with 0%nat by word. simpl.
  iNamed "Hptr_vrf".
  wp_apply wp_alloc as "* Hstr_hist".
  wp_apply ktcore.wp_SignVrf as "* @".
  { iFrame "#". naive_solver. }
  wp_apply wp_alloc as "* Hstr_serv".
  rewrite -wp_fupd.
  wp_apply wp_alloc as "%ptr_a Hstr_adtr".
  iPersist "Hstr_serv".
  iStructNamed "Hstr_adtr". simpl in *.
  iPersist "sk serv mu hist".

  remember (cfg.mk servPk sigPk sigγ servGood) as γ.
  remember (state.mk digs) as σ.
  iDestruct "Hauth_digs" as "[Hauth_digs0 Hauth_digs1]".
  iMod (inv_alloc nroot _ (∃ σ, own γ σ) with "[Hauth_digs0]") as "#Ht".
  { iExists σ. subst. iFrame "∗#". }
  iAssert (is_inv γ)%I with "Ht" as "{Ht} #His_inv".

  iMod (init_RWMutex (Auditor.own_aux ptr_a γ) with "[-HΦ Hmu] Hmu") as "Hlocks".
  { iExists σ.
    subst. iModIntro.
    iNamed "Hwish_CheckStartVrf".
    iFrame "Hstr_hist #∗%".
    simpl in *.
    repeat iSplit; try done; try iPureIntro.
    - replace (_ + 0)%nat with (uint.nat ep) by word.
      iNamed "Hwish_CheckStartChain".
      iFrame "Hstr_epoch #".
      simpl in *.
      replace (W64 (uint.nat _)) with ep by word.
      rewrite take_ge; [|word].
      iFrame "#%".
    - word.
    - word.
    - word.
    - word.
    - case_match; try done.
      iNamedSuffix "Hgood" "0".
      subst.
      iDestruct (server.wish_CheckStartChain_det with
        "Hwish_StartChain0 Hwish_CheckStartChain") as %?.
      destruct_and!. subst.
      iFrame "#".
      iPureIntro. simpl. repeat split. word.
    - case_match; try done.
      iFrame "#". simpl in *.
      by iNamed "Hgood". }

  subst. iModIntro.
  iApply "HΦ".
  iSplit. { iPureIntro. apply ktcore.blame_none. }
  case_decide; try done.
  iFrame "#".
  simpl in *.
  iSplit; try done.
  iApply (big_sepL_replicate_impl with "Hlocks").
  iIntros "!> Hlock".
  iFrame "#∗".
Qed.

End proof.
End auditor.
