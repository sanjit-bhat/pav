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

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _, !globalsGS Σ} {go_ctx : GoContext}.
Context `{!pavG Σ}.

Definition own_aux γ σ q : iProp Σ :=
  "#Hgs_start_ep" ∷ ghost_var γ.(cfg.sigpredγ).(ktcore.sigpred_cfg.start_ep)
    (□) σ.(state.start_ep) ∗
  (* 1/2 in lock inv, 1/2 in GS inv. *)
  "Hgs_links" ∷ mono_list_auth_own γ.(cfg.sigpredγ).(ktcore.sigpred_cfg.links)
    (q/2) σ.(state.links).

Definition own γ σ : iProp Σ := own_aux γ σ 1.

Definition is_inv γ := inv nroot (∃ σ, own γ σ).

#[global] Instance own_timeless γ σ : Timeless (own γ σ).
Proof. apply _. Qed.

#[global] Instance own_aux_frac γ σ :
  fractional.Fractional (λ q, own_aux γ σ q).
Proof.
  intros ??. iSplit.
  - iIntros "@".
    rewrite Qp.div_add_distr.
    iDestruct "Hgs_links" as "[? ?]".
    iFrame "∗#".
  - iIntros "[H0 H1]".
    iNamedSuffix "H0" "0".
    iNamedSuffix "H1" "1".
    iCombine "Hgs_links0 Hgs_links1" as "?".
    rewrite -Qp.div_add_distr.
    iFrame "∗#".
Qed.

#[global] Instance own_aux_as_frac γ σ q :
  fractional.AsFractional (own_aux γ σ q) (λ q, own_aux γ σ q) q.
Proof. auto. Qed.

#[global] Instance own_aux_combine_sep_gives γ σ0 σ1 q0 q1 :
  CombineSepGives (own_aux γ σ0 q0) (own_aux γ σ1 q1) (⌜σ0 = σ1⌝).
Proof.
  rewrite /CombineSepGives.
  iIntros "[H0 H1]".
  iNamedSuffix "H0" "0".
  iNamedSuffix "H1" "1".
  iCombine "Hgs_start_ep0 Hgs_start_ep1" gives %[? ?].
  iDestruct (mono_list_auth_own_agree with "Hgs_links0 Hgs_links1") as %[? ?].
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
Context `{hG: heapGS Σ, !ffi_semantics _ _, !globalsGS Σ} {go_ctx : GoContext}.
Context `{!pavG Σ}.

Definition own ptr γ good : iProp Σ :=
  ∃ ptr_cli sl_sigPk sl_vrfPk sl_servVrfSig servVrfSig sl_adtrVrfSig adtrVrfSig,
  "#Hstr_serv" ∷ ptr ↦□ (auditor.serv.mk ptr_cli sl_sigPk sl_vrfPk sl_servVrfSig sl_adtrVrfSig) ∗
  "#His_rpc" ∷ server.is_rpc_cli ptr_cli good ∗
  "#Hsl_sigPk" ∷ sl_sigPk ↦*□ γ.(cfg.serv_sig_pk) ∗
  "#Hsl_vrfPk" ∷ sl_vrfPk ↦*□ γ.(cfg.vrf_pk) ∗
  "#Hsl_servVrfSig" ∷ sl_servVrfSig ↦*□ servVrfSig ∗
  "#His_servVrfSig" ∷ ktcore.wish_VrfSig γ.(cfg.serv_sig_pk) γ.(cfg.vrf_pk) servVrfSig ∗
  "#Hsl_adtrVrfSig" ∷ sl_adtrVrfSig ↦*□ adtrVrfSig ∗
  "#His_adtrVrfSig" ∷ ktcore.wish_VrfSig γ.(cfg.adtr_sig_pk) γ.(cfg.vrf_pk) adtrVrfSig.

Definition align_serv γ servγ : iProp Σ :=
  (* trusted Auditor.New assumption. *)
  "%Heq_sig_pk" ∷ ⌜γ.(cfg.serv_sig_pk) = servγ.(server.cfg.sig_pk)⌝ ∗
  "#His_sig_pk" ∷ cryptoffi.is_sig_pk γ.(cfg.serv_sig_pk)
    (ktcore.sigpred servγ.(server.cfg.sigpredγ)) ∗
  (* from signed vrf_pk. *)
  "%Heq_vrf_pk" ∷ ⌜γ.(cfg.vrf_pk) = servγ.(server.cfg.vrf_pk)⌝.

End proof.
End serv.

Module Auditor.
Record t :=
  mk' {
    hist: history.t;
  }.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _, !globalsGS Σ} {go_ctx : GoContext}.
Context `{!pavG Σ}.

Definition own ptr obj γ σ q : iProp Σ :=
  ∃ ptr_sk ptr_hist ptr_serv maps,
  "#Hfld_sk" ∷ ptr.[auditor.Auditor.t, "sk"] ↦□ ptr_sk ∗
  "#Hfld_hist" ∷ ptr.[auditor.Auditor.t, "hist"] ↦□ ptr_hist ∗
  "#Hfld_serv" ∷ ptr.[auditor.Auditor.t, "serv"] ↦□ ptr_serv ∗

  "#Hown_sk" ∷ cryptoffi.own_sig_sk ptr_sk γ.(cfg.adtr_sig_pk)
    (ktcore.sigpred γ.(cfg.sigpredγ)) ∗

  "Hown_hist" ∷ history.own ptr_hist obj.(hist) γ σ q ∗
  "Hown_gs_hist" ∷ own_aux γ σ q ∗
  "#Hinv_sigpred" ∷ ktcore.sigpred_links_inv σ.(state.start_ep) σ.(state.links)
    obj.(hist).(history.digs) obj.(hist).(history.cut) maps ∗
  "#Halign_hist" ∷ match γ.(cfg.serv_good) with None => True | Some servγ =>
    history.align_serv obj.(hist) σ servγ end ∗

  "#Hown_serv" ∷ serv.own ptr_serv γ γ.(cfg.serv_good) ∗
  "#Halign_serv" ∷ match γ.(cfg.serv_good) with None => True | Some servγ =>
    serv.align_serv γ servγ end.

Definition own_aux ptr γ q : iProp Σ := ∃ obj σ, own ptr obj γ σ q.

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
    (* TODO: why needed? *)
    Typeclasses Opaque auditor.own_aux.
    iDestruct "Hown_gs_hist" as "[? ?]".
    iFrame "#∗".
  - iIntros "[(%&%&H0)(%&%&H1)]".
    iNamedSuffix "H0" "0".
    iNamedSuffix "H1" "1".
    iCombine "Hfld_sk0 Hfld_sk1" gives %[? ?].
    iCombine "Hfld_hist0 Hfld_hist1" gives %[? ?].
    iCombine "Hfld_serv0 Hfld_serv1" gives %[? ?].
    simplify_eq/=.
    iCombine "Hown_hist0 Hown_hist1" as "?".
    iCombine "Hown_gs_hist0 Hown_gs_hist1" as "?".
    iFrame "∗#%".
Qed.

#[global] Instance own_aux_as_frac ptr γ q :
  fractional.AsFractional (own_aux ptr γ q) (λ q, own_aux ptr γ q) q.
Proof. auto. Qed.

End proof.
End Auditor.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _, !globalsGS Σ} {go_ctx : GoContext}.
Context `{!pavG Σ}.

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
    iDestruct (hashchain.is_chain_hash_len with "His_chain_prev") as %?.
    word. }
  iDestruct (hashchain.is_chain_invert PrevLink (uint.nat PrevEpochLen))
    as "(%&%&#His_chain_prev)"; [word|].
  wp_apply (hashchain.wp_Verify with "[$His_chain_prev]") as "* @".
  { iFrame "#". }
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
    iDestruct (hashchain.is_chain_inj with "His_chain_prev His_chain_prev'") as %[-> ->].
    simplify_eq/=.
    iDestruct (hashchain.is_chain_det with "His_chain His_chain_start'") as %->.
    iExactEq "His_link_sig'". repeat f_equal. word. }
  iNamed "Hgenie".
  iDestruct (hashchain.is_chain_hash_len with "His_chain_prev") as %?.
  iApply "HΦ".
  iFrame "#%". simpl in *.
  iPureIntro.

  destruct new_vals as [|dig digs] using rev_ind; [|clear IHdigs].
  { exfalso. simpl in *. word. }
  rewrite last_snoc /=.
  autorewrite with len in *.
  repeat split. word.
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
  wp_apply cryptoffi.wp_VrfPublicKeyDecode as "* @! {Hsl_enc}".
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

Lemma wp_getNextDig sl_prevDig prevDig prevMap sl_updates updates :
  {{{
    is_pkg_init auditor ∗
    "#Hsl_prevDig" ∷ sl_prevDig ↦*□ prevDig ∗
    "#His_prevMap" ∷ merkle.is_map prevMap prevDig ∗
    "#Hown_updates" ∷ ktcore.UpdateProofSlice1D.own sl_updates updates (□)
  }}}
  @! auditor.getNextDig #sl_prevDig #sl_updates
  {{{
    sl_dig (err : bool), RET (#sl_dig, #err);
    "Hgenie" ∷
      match err with
      | true => ¬ ∃ dig, ktcore.wish_ListUpdate prevDig updates dig
      | false =>
        ∃ dig map,
        "#Hsl_dig" ∷ sl_dig ↦*□ dig ∗
        "#His_map" ∷ merkle.is_map map dig ∗
        (* caller doesn't need to know map update elems. just subset. *)
        "%Hsub" ∷ ⌜prevMap ⊆ map⌝ ∗
        "#Hwish_ListUpdate" ∷ ktcore.wish_ListUpdate prevDig updates dig
      end
  }}}.
Proof.
  wp_start as "@". wp_auto.
  iDestruct "Hown_updates" as "(%sl0_updates&Hsl_updates&Hown_updates)".
  iDestruct (own_slice_len with "Hsl_updates") as %[? ?].
  iDestruct (big_sepL2_length with "Hown_updates") as %?.
  iAssert (
    ∃ (i : w64) sl_dig dig x map,
    let pref_updates := take (sint.nat i) updates in
    "i" ∷ i_ptr ↦ i ∗
    "%Hlt_i" ∷ ⌜0 ≤ sint.Z i ≤ length updates⌝ ∗
    "u" ∷ u_ptr ↦ x ∗
    "err" ∷ err_ptr ↦ false ∗
    "dig" ∷ dig_ptr ↦ sl_dig ∗
    "#Hsl_dig" ∷ sl_dig ↦*□ dig ∗
    "#His_map" ∷ merkle.is_map map dig ∗
    "%Hsub" ∷ ⌜prevMap ⊆ map⌝ ∗
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
  wp_pure; [word|].
  wp_apply wp_load_slice_elem as "_"; [word|..].
  { by iFrame "#". }
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
  - iDestruct (merkle.is_map_inj with "His_map His_map_old") as %<-.
    iPureIntro.
    trans map; try done.
    by apply insert_subseteq.
  - replace (sint.nat (word.add _ _)) with (S $ sint.nat i) by word.
    erewrite take_S_r; [|done].
    iApply ktcore.wish_ListUpdate_grow; iFrame "#".
Qed.

Lemma wp_getNextLink hist γ σ sl_sigPk (prevEp : w64) sl_prevDig prevDig
    sl_prevLink prevLink ptr_p proof prevMap :
  {{{
    is_pkg_init auditor ∗
    "#Hsl_sigPk" ∷ sl_sigPk ↦*□ γ.(cfg.serv_sig_pk) ∗
    "#Hsl_prevDig" ∷ sl_prevDig ↦*□ prevDig ∗
    "#Hsl_prevLink" ∷ sl_prevLink ↦*□ prevLink ∗
    "#Hproof" ∷ ktcore.AuditProof.own ptr_p proof (□) ∗

    "%Heq_prevEp" ∷ ⌜uint.Z prevEp = uint.Z σ.(state.start_ep) +
      length σ.(state.links) - 1⌝ ∗
    "%Heq_prevDig" ∷ ⌜last hist.(history.digs) = Some prevDig⌝ ∗
    "#His_prevLink" ∷ hashchain.is_chain hist.(history.digs)
      hist.(history.cut) prevLink (S $ uint.nat prevEp) ∗
    "#His_prevMap" ∷ merkle.is_map prevMap prevDig
  }}}
  @! auditor.getNextLink #sl_sigPk #prevEp #sl_prevDig #sl_prevLink #ptr_p
  {{{
    ep sl_dig sl_link err, RET (#ep, #sl_dig, #sl_link, #err);
    "Hgenie" ∷
      match err with
      | true => ¬ ∃ ep dig link, wish_getNextLink γ.(cfg.serv_sig_pk) hist σ proof ep dig link
      | false =>
        ∃ dig link map,
        "#Hsl_dig" ∷ sl_dig ↦*□ dig ∗
        "#Hsl_link" ∷ sl_link ↦*□ link ∗
        "#Hwish_getNextLink" ∷ wish_getNextLink γ.(cfg.serv_sig_pk) hist σ proof ep dig link ∗
        "#His_map" ∷ merkle.is_map map dig ∗
        "%Hsub" ∷ ⌜prevMap ⊆ map⌝
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
    iDestruct (hashchain.is_chain_det with "His_chain His_link0") as %->.
    iExactEq "His_sig0". f_equal. word. }
  iNamed "Hgenie".
  iApply "HΦ". iFrame "#%".
  iSplit; [word|].
  iExactEq "His_chain". rewrite /named. f_equal. word.
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
      | true => ⌜uint.Z epoch < uint.Z σ.(state.start_ep) ∨
        uint.Z epoch >= uint.Z σ.(state.start_ep) + length σ.(state.links)⌝
      | false =>
        ∃ link vrf,
        "#Hown_link" ∷ SignedLink.own ptr_link link (□) ∗
        "#Hown_vrf" ∷ SignedVrf.own ptr_vrf vrf (□) ∗
        "#Hwish_link" ∷ wish_SignedLink γ.(cfg.serv_sig_pk) γ.(cfg.adtr_sig_pk) epoch link ∗
        "#Hwish_vrf" ∷ wish_SignedVrf γ.(cfg.serv_sig_pk) γ.(cfg.adtr_sig_pk) vrf ∗
        "%Hlook_link" ∷ ⌜σ.(state.links) !!
          (uint.nat epoch - uint.nat σ.(state.start_ep))%nat =
          Some link.(SignedLink.Link)⌝ ∗
        "%Heq_vrf" ∷ ⌜vrf.(SignedVrf.VrfPk) = γ.(cfg.vrf_pk)⌝
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
  iCombine "Hadtr Hown_gs_hist" gives %->.
  iMod ("Hfupd" with "Hadtr") as "HQ".
  iModIntro.

  iDestruct (own_slice_len with "Hsl_epochs") as %[? ?].
  iDestruct (big_sepL2_length with "Hepochs") as %?.
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
    word. }

  simpl in *.
  wp_pure; [word|].
  list_elem σ.(state.links) (sint.nat (word.sub epoch σ.(state.start_ep))) as link.
  iDestruct (big_sepL2_lookup_2_some with "Hepochs") as %[? ?]; [done|].
  iDestruct (big_sepL2_lookup with "Hepochs") as "@"; [done..|].
  iNamed "Hown_serv".
  wp_apply (wp_load_slice_elem with "[$Hsl_epochs]") as "Hsl_epochs"; [word|done|].
  wp_apply wp_alloc as "* Hptr_link".
  wp_apply wp_alloc as "* Hptr_vrf".
  iPersist "Hptr_link Hptr_vrf".
  wp_apply (wp_RWMutex__RUnlock with "[-HΦ HQ]") as "Hlock".
  { iFrame "∗∗ Hstr_serv #%". }
  iApply "HΦ".
  iFrame "Hfld_mu ∗".
  iExists (SignedLink.mk' _ _ _), (SignedVrf.mk' _ _ _).
  simpl in *.
  replace (W64 (uint.nat _ + sint.nat _)) with epoch by word.
  iFrame "#".
  iPureIntro. split; [|done].
  exact_eq Hlink_lookup. f_equal. word.
Qed.

Lemma wp_Auditor_updOnce ptr_a a γ σ Q ptr_proof proof :
  {{{
    is_pkg_init auditor ∗
    "Hadtr" ∷ Auditor.own ptr_a a γ σ 1 ∗
    "#Hfupd" ∷ □ (|={⊤,∅}=> ∃ σ, own γ σ ∗
      (∀ new_links,
      let σ' := set state.links (.++ new_links) σ in
      own γ σ' ={∅,⊤}=∗ Q σ')) ∗

    "#Hproof" ∷ ktcore.AuditProof.own ptr_proof proof (□) ∗
    "Hgood" ∷ match γ.(cfg.serv_good) with None => True | Some servγ =>
      ∃ ep dig link,
      let hist' := set history.digs (.++ [dig]) a.(Auditor.hist) in
      let σ' := set state.links (.++ [link]) σ in
      "#Hwish_getNextLink" ∷ wish_getNextLink γ.(cfg.serv_sig_pk)
        a.(Auditor.hist) σ proof ep dig link ∗
      "#Halign_next" ∷ history.align_serv hist' σ' servγ end
  }}}
  ptr_a @! (go.PointerType auditor.Auditor) @! "updOnce" #ptr_proof
  {{{
    err, RET #(ktcore.blame_to_u64 err);
    "%Hblame" ∷ ⌜ktcore.BlameSpec err
      {[ktcore.BlameServFull:=option_bool γ.(cfg.serv_good)]}⌝ ∗
    "Herr" ∷
      (if decide (err ≠ ∅)
      then
        "Hadtr" ∷ Auditor.own ptr_a a γ σ 1 ∗
        "HQ" ∷ Q σ
      else
        ∃ new_dig new_link,
        let a' := set Auditor.hist
          (set history.digs (.++ [new_dig])) a in
        let σ' := set state.links (.++ [new_link]) σ in
        "Hadtr" ∷ Auditor.own ptr_a a' γ σ' 1 ∗
        "HQ" ∷ Q σ')
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hadtr". iNamed "Hown_hist". iNamed "Hown_serv". wp_auto.
  destruct a, hist. simpl in *.
  iDestruct (own_slice_len with "Hsl_epochs") as %[? ?].
  iDestruct (big_sepL2_length with "Hepochs") as %?.
  list_elem σ.(state.links)
    (sint.nat (word.sub sl_epochs.(slice.len_f) (W64 1))) as prevLink.
  iDestruct (big_sepL2_lookup_2_some with "Hepochs") as %[? ?]; [done|].
  iDestruct (big_sepL2_lookup with "Hepochs") as "@"; [done..|].
  wp_pure; [word|].
  wp_apply (wp_load_slice_elem with "[$Hsl_epochs]") as "Hsl_epochs"; [word|done|].

  simpl in *.
  iPoseProof "Hinv_sigpred" as "@".
  iDestruct (big_sepL_lookup with "Hlinks") as "@"; [done|].
  rewrite take_ge; [|word].
  iDestruct (big_sepL2_length with "Hmaps") as %?.
  iDestruct (big_sepL2_lookup_1_some with "Hmaps") as %[? Hlast_maps]; [done|].
  iDestruct (big_sepL2_lookup with "Hmaps") as "@"; [done..|].
  replace (sint.nat _) with (pred $ length maps) in Hlast_maps by word.
  replace (_ - _ + _)%nat with (pred $ length digs) in Hlook_dig by word.
  rewrite -!last_lookup in Hlook_dig, Hlast_maps.
  simplify_eq/=.
  wp_apply (wp_getNextLink (history.mk' digs cut) γ σ) as "* @".
  { simpl. iFrame "#%".
    iSplit; [word|].
    rewrite /named. iExactEq "His_link". f_equal. word. }
  rewrite -wp_fupd.
  wp_if_destruct.
  { iMod "Hfupd" as "(%&Hadtr&Hfupd)".
    iCombine "Hadtr Hown_gs_hist" gives %->.
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

  iPoseProof "Hwish_getNextLink_n" as "H".
  iNamedSuffix "H" "_n".
  simpl in *.
  iDestruct (ktcore.sigpred_links_inv_grow with "Hinv_sigpred His_map_n []") as "{Hinv_sigpred} Hinv_sigpred_n".
  { naive_solver. }
  { iExactEq "His_link_n". f_equal. word. }
  rewrite -ncfupd_wp.
  iMod "Hfupd" as "(%&Hadtr&Hfupd)".
  iCombine "Hadtr Hown_gs_hist" gives %->.
  destruct σ.
  iSpecialize ("Hfupd" $! [link]).
  simpl in *.
  iNamedSuffix "Hown_gs_hist" "0".
  iEval (rewrite /own) in "Hadtr".
  iNamedSuffix "Hadtr" "1".
  simpl in *.
  iCombine "Hgs_links0 Hgs_links1" as "Hgs_links".
  iMod (mono_list_auth_own_update_app [link] with "Hgs_links")
    as "((Hgs_links0&Hgs_links1)&#Hlb_links)".
  iMod ("Hfupd" with "[$Hgs_links1 //]") as "HQ".
  iModIntro.

  iNamed "Hproof".
  wp_apply ktcore.wp_SignLink as "* H".
  { iFrame "Hinv_sigpred_n #".
    replace (uint.nat _ - uint.nat _)%nat with (length links) by word.
    by rewrite lookup_snoc. }
  iNamedSuffix "H" "_my".
  wp_apply wp_alloc as "* Hstr_epoch_n".
  iPersist "Hstr_epoch_n".
  wp_apply wp_slice_literal as "* [Hsl_tmp _]".
  wp_apply (wp_slice_append with "[$Hsl_epochs $Hcap_epochs $Hsl_tmp]")
    as "* (Hsl_epochs&Hcap_epochs&_)".
  iModIntro.
  rewrite ktcore.rw_BlameNone.
  iApply "HΦ".
  iSplit. { iPureIntro. apply ktcore.blame_none. }
  case_decide; try done.
  iFrame "∗".
  iFrame "Hstr_serv #".
  simpl in *.
  replace (W64 (_ + (_ + _)%nat)) with ep by word.
  iFrame "#".
  simpl in *.
  iSplit.
  { iPureIntro.
    autorewrite with len.
    repeat split; try done; [|word..].
    by rewrite last_snoc. }
  case_match; try done.
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
      (∀ new_links,
      let σ' := set state.links (.++ new_links) σ in
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
  [wp_auto] should probably simpl. *)
  simpl. wp_auto.
  wp_apply (wp_RWMutex__Lock with "[$Hperm]") as "[Hlocked H]".
  iNamed "H". iNamed "Hown_hist". iNamed "Hown_serv". wp_auto.
  iDestruct (own_slice_len with "Hsl_epochs") as %[? ?].
  iDestruct (big_sepL2_length with "Hepochs") as %?.
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
  iCombine "Hadtr Hown_gs_hist" gives %->.
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
    ∃ (i : w64) (a0 : loc) a σ,
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

    "Hadtr" ∷ Auditor.own ptr_a a γ σ 1 ∗
    "%Heq_ep" ∷ ⌜(uint.Z start_ep + length links + sint.nat i =
      uint.Z σ.(state.start_ep) + length σ.(state.links))%Z⌝ ∗
    "HQ" ∷ Q σ
  )%I with "[-]" as "IH".
  { iFrame "∗ Hstr_serv #%". simpl. word. }
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
  wp_pure; [word|].
  wp_apply wp_load_slice_elem as "_"; [word|..].
  { by iFrame "#". }
  iNamedSuffix "Hadtr" "0".
  wp_apply (wp_Auditor_updOnce with "[Hfld_hist0 Hown_hist0 Hown_gs_hist0]") as "* @".
  { iFrame "∗ Hown_serv0 #%".
    case_match; try done.
    iDestruct (big_sepL_lookup with "Hgood") as "{Hgood} Htrans"; [done|].
    iDestruct ("Htrans" with "Halign_hist0 []") as "{Htrans} @"; [word|].
    iNamed "Halign_serv0".
    rewrite Heq_sig_pk.
    iFrame "#". }
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
  iFrame.
  simpl. len.
Qed.

Lemma wp_New servGood (servAddr : w64) sl_servPk servPk :
  {{{
    is_pkg_init auditor ∗
    "#Hsl_servPk" ∷ sl_servPk ↦*□ servPk ∗
    "%Heq_servPk" ∷ ⌜match servGood with None => True | Some servγ =>
      servPk = servγ.(server.cfg.sig_pk) end⌝ ∗
    "#His_servPk" ∷ match servGood with None => True | Some servγ =>
      cryptoffi.is_sig_pk servPk (ktcore.sigpred servγ.(server.cfg.sigpredγ)) end
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
        (ktcore.sigpred γ.(cfg.sigpredγ)))
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
  iMod (ghost_var_alloc vrf.(server.StartVrf.VrfPk)) as (vrfγ) "Hshot_vrf".
  iPersist "Hshot_vrf".
  iMod (ghost_var_alloc ep) as (start_epγ) "Hshot_start_ep".
  iPersist "Hshot_start_ep".
  iMod (mono_list_own_alloc [link]) as (linksγ) "[Hauth_links #Hlb_links]".
  wp_apply (cryptoffi.wp_SigGenerateKey
    (ktcore.sigpred (ktcore.sigpred_cfg.mk vrfγ start_epγ linksγ))) as "* @".
  iPersist "Hsl_sigPk".
  iDestruct (merkle.is_map_invert dig) as (m) "#His_map"; [word|].
  iNamed "Hptr_chain".
  iAssert (ktcore.sigpred_links_inv ep [link] digs cut [m])%I as "#Hinv_sigpred".
  { rewrite /ktcore.sigpred_links_inv /=.
    iNamed "Hwish_CheckStartChain".
    simplify_eq/=.
    iFrame "#".
    autorewrite with len in *.
    repeat iSplit; try iPureIntro; try done.
    - rewrite last_lookup in Heq_dig.
      apply lookup_lt_Some in Heq_dig.
      word.
    - iExactEq "His_chain_start". rewrite /named. f_equal; [|word].
      rewrite take_ge; [done|len].
    - replace (_ + _ - _ + _)%nat with (pred $ length (digs0 ++ digs1)); [|len].
      by rewrite -last_lookup last_app Heq_dig. }
  wp_apply ktcore.wp_SignLink as "* @".
  { iFrame "#". by replace (_ - _)%nat with 0%nat by word. }
  wp_apply wp_alloc as "* Hstr_epoch".
  iPersist "Hstr_epoch".
  unshelve (wp_apply wp_slice_literal as "* [Hsl_epochs Hcap_epochs]"); [apply _|].
  iNamed "Hptr_vrf".
  wp_apply wp_alloc as "* Hstr_hist".
  wp_apply ktcore.wp_SignVrf as "* @".
  { iFrame "#". }
  wp_apply wp_alloc as "* Hstr_serv".
  rewrite -wp_fupd.
  wp_apply wp_alloc as "%ptr_a Hstr_adtr".
  iPersist "Hstr_serv Hstr_adtr".
  iDestruct (struct_fields_split with "Hstr_adtr") as "{Hstr_adtr} H".
  iNamedSuffix "H" "_fld".
  simpl in *.

  remember (Auditor.mk' (history.mk' digs cut)) as obj.
  remember (ktcore.sigpred_cfg.mk _ _ _) as sigpredγ.
  remember (cfg.mk servPk sigPk sigpredγ vrf.(server.StartVrf.VrfPk) servGood) as γ.
  remember (state.mk ep [link]) as σ.
  iDestruct "Hauth_links" as "[Hauth_links0 Hauth_links1]".
  iMod (inv_alloc nroot _ (∃ σ, own γ σ) with "[Hauth_links0]") as "#Ht".
  { iExists σ. subst. iFrame "∗#". }
  iAssert (is_inv γ)%I with "Ht" as "{Ht} #His_inv".

  iMod (init_RWMutex (Auditor.own_aux ptr_a γ) with "[-HΦ Hmu] Hmu") as "Hlocks".
  { iExists obj, σ.
    subst. iModIntro.
    iNamed "Hwish_CheckStartVrf".
    iFrame "Hstr_hist #∗".
    simpl in *.
    repeat iSplit; try done; try iPureIntro.
    - replace (W64 (_ + _)) with ep by word.
      iNamed "Hwish_CheckStartChain".
      iFrame "Hstr_epoch #".
    - word.
    - case_match; try done.
      iNamedSuffix "Hgood" "0".
      subst.
      iDestruct (server.wish_CheckStartChain_det with
        "Hwish_StartChain0 Hwish_CheckStartChain") as %?.
      destruct_and!. subst.
      iFrame "#". iPureIntro. simpl. repeat split.
      rewrite last_lookup in Hlast_digs.
      apply lookup_lt_Some in Hlast_digs.
      autorewrite with len in *. word.
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
