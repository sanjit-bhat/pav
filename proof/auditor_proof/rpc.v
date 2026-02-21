From New.generatedproof.github_com.sanjit_bhat.pav Require Import auditor server.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import
  advrpc cryptoffi hashchain ktcore merkle.

From New.proof.github_com.sanjit_bhat.pav.server_proof Require Import
  serde server rpc.

Module auditor.
Import serde.server server.server rpc.server.

Module state.
Record t :=
  mk {
    start_ep: w64;
    links: list $ list w8;
  }.
End state.

(* cfg is the static state we know about this party, if good. *)
Module cfg.
Record t :=
  mk {
    serv_sig_pk: list w8;
    adtr_sig_pk: list w8;
    sigpredγ: ktcore.sigpred_cfg.t;
    vrf_pk: list w8;
    serv_good: option $ server.cfg.t;
  }.
End cfg.

Module epoch.
Record t :=
  mk' {
    link: list w8;
  }.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj ep γ : iProp Σ :=
  ∃ sl_link sl_servSig servSig sl_adtrSig adtrSig,
  "#Hstr_epoch" ∷ ptr ↦□ (auditor.epoch.mk sl_link sl_servSig sl_adtrSig) ∗
  "#Hsl_link" ∷ sl_link ↦*□ obj.(link) ∗
  "#Hsl_servSig" ∷ sl_servSig ↦*□ servSig ∗
  "#His_servSig" ∷ ktcore.wish_LinkSig γ.(cfg.serv_sig_pk) ep obj.(link) servSig ∗
  "#Hsl_adtrSig" ∷ sl_adtrSig ↦*□ adtrSig ∗
  "#His_adtrSig" ∷ ktcore.wish_LinkSig γ.(cfg.adtr_sig_pk) ep obj.(link) adtrSig.

End proof.
End epoch.

Module history.
Record t :=
  mk' {
    digs: list $ list w8;
    cut: option $ list w8;
  }.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj γ σ q : iProp Σ :=
  ∃ sl_lastDig lastDig sl_epochs sl0_epochs,
  let last_ep := uint.Z σ.(state.start_ep) + length σ.(state.links) - 1 in
  "Hstr_history" ∷ ptr ↦{#q} (auditor.history.mk sl_lastDig σ.(state.start_ep) sl_epochs) ∗
  "#Hsl_lastDig" ∷ sl_lastDig ↦*□ lastDig ∗
  "%Heq_lastDig" ∷ ⌜last obj.(digs) = Some lastDig⌝ ∗
  "Hsl_epochs" ∷ sl_epochs ↦*{#q} sl0_epochs ∗
  "Hcap_epochs" ∷ own_slice_cap loc sl_epochs (DfracOwn q) ∗
  "#Hepochs" ∷ ([∗ list] idx ↦ p;o ∈ sl0_epochs;σ.(state.links),
    epoch.own p (epoch.mk' o) (uint.nat σ.(state.start_ep) + idx) γ) ∗
  "%Hsome_links" ∷ ⌜length σ.(state.links) > 0⌝ ∗
  "%Hnoof_ep" ∷ ⌜last_ep = uint.Z $ W64 last_ep⌝.

Definition align_serv obj σ servγ : iProp Σ :=
  ∃ hist,
  "#His_hist" ∷ mono_list_lb_own servγ.(server.cfg.histγ) hist ∗
  "%Heq_ep" ∷ ⌜length hist = (uint.nat σ.(state.start_ep) + length σ.(state.links))%nat⌝ ∗
  "%Heq_digs" ∷ ⌜obj.(digs) = hist.*1⌝ ∗
  "%Heq_cut" ∷ ⌜obj.(cut) = None⌝.

#[global] Instance own_aux_combine_sep_as ptr obj0 obj1 γ σ0 σ1 q0 q1 :
  CombineSepAs (own ptr obj0 γ σ0 q0) (own ptr obj1 γ σ1 q1) (own ptr obj0 γ σ0 (q0 + q1)) | 60.
Proof.
  rewrite /CombineSepAs.
  iIntros "[H0 H1]".
  iNamedSuffix "H0" "0".
  iNamedSuffix "H1" "1".
  iCombine "Hstr_history0 Hstr_history1" as "?" gives %[? ?].
  simplify_eq/=.
  iCombine "Hsl_epochs0 Hsl_epochs1" as "?" gives %?.
  iCombine "Hcap_epochs0 Hcap_epochs1" as "?".
  iCombine "Hsl_lastDig0 Hsl_lastDig1" gives %?.
  simplify_eq/=.
  (* TODO: DfracOwn q0 ⋅ DfracOwn q1. not getting combined properly. *)
  iFrame "∗#%".
Qed.

#[global] Instance own_frac ptr obj γ σ :
  fractional.Fractional (λ q, own ptr obj γ σ q).
Proof.
  intros ??. iSplit.
  - iIntros "@".
    iDestruct "Hstr_history" as "[? ?]".
    iDestruct "Hsl_epochs" as "[? ?]".
    iDestruct "Hcap_epochs" as "[? ?]".
    iFrame "∗#%".
  - iIntros "[H0 H1]".
    by iCombine "H0 H1" as "H".
Qed.

#[global] Instance own_as_frac ptr obj γ σ q :
  fractional.AsFractional (own ptr obj γ σ q) (λ q, own ptr obj γ σ q) q.
Proof. auto. Qed.

End proof.
End history.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition wish_getNextLink sig_pk hist σ proof (ep : w64) dig link : iProp Σ :=
  ∃ prevDig,
  "%Heq_ep" ∷ ⌜uint.Z ep = (uint.Z σ.(state.start_ep) + length σ.(state.links))%Z⌝ ∗
  "%Heq_prevDig" ∷ ⌜last hist.(history.digs) = Some prevDig⌝ ∗
  "#His_upd" ∷ ktcore.wish_ListUpdate prevDig
    proof.(ktcore.AuditProof.Updates) dig ∗
  "#His_link" ∷ hashchain.is_chain (hist.(history.digs) ++ [dig])
    hist.(history.cut) link (S $ uint.nat ep) ∗
  "#His_sig" ∷ ktcore.wish_LinkSig sig_pk ep link
    proof.(ktcore.AuditProof.LinkSig).

Lemma wish_getNextLink_det sig_pk hist σ proof ep0 dig0 link0 ep1 dig1 link1 :
  wish_getNextLink sig_pk hist σ proof ep0 dig0 link0 -∗
  wish_getNextLink sig_pk hist σ proof ep1 dig1 link1 -∗
  ⌜ep0 = ep1 ∧ dig0 = dig1 ∧ link0 = link1⌝.
Proof.
  iNamedSuffix 1 "0".
  iNamedSuffix 1 "1".
  simplify_eq/=.
  iDestruct (ktcore.wish_ListUpdate_det with "His_upd0 His_upd1") as %->.
  iDestruct (hashchain.is_chain_det with "His_link0 His_link1") as %->.
  iPureIntro. repeat split. word.
Qed.

Lemma wp_CallAudit c good (prevEpoch : w64) :
  {{{
    is_pkg_init server ∗
    "#His_serv" ∷ is_rpc_cli c good ∗
    "#His_args" ∷ match good with None => True | Some γ =>
      ∃ (entry : list w8 * keys_ty),
      "#Hidx_ep" ∷ mono_list_idx_own γ.(cfg.histγ) (uint.nat prevEpoch) entry end
  }}}
  @! server.CallAudit #c #prevEpoch
  {{{
    sl_proofs err, RET (#sl_proofs, #(ktcore.blame_to_u64 err));
    "%Hblame" ∷ ⌜ktcore.BlameSpec err {[ktcore.BlameServFull:=option_bool good]}⌝ ∗
    "#Herr" ∷ (if decide (err ≠ ∅) then True else
      ∃ proofs,
      "#Hsl_proofs" ∷ ktcore.AuditProofSlice1D.own sl_proofs proofs (□) ∗

      "Hgood" ∷ match good with None => True | Some γ =>
        (* writing determ trans per epoch makes postcond easier to use
        than one trans across all epochs. epochs are indep. *)
        ([∗ list] idx ↦ proof ∈ proofs,
          □ ∀ adtr_hist adtrσ,
          history.align_serv adtr_hist adtrσ γ -∗
          ⌜uint.Z adtrσ.(state.start_ep) + length adtrσ.(state.links) - 1 =
            (uint.Z prevEpoch + idx)%Z⌝ -∗

          ∃ ep dig link,
          let adtr_hist' := set history.digs (.++ [dig]) adtr_hist in
          let adtrσ' := set state.links (.++ [link]) adtrσ in
          "#Hwish_getNextLink" ∷ wish_getNextLink γ.(cfg.sig_pk)
            adtr_hist adtrσ proof ep dig link ∗
          "#Halign_next" ∷ history.align_serv adtr_hist' adtrσ' γ) end)
  }}}.
Proof.
  wp_start as "@". wp_auto.
  wp_apply wp_alloc as "* Ha".
  wp_apply (AuditArg.wp_enc (AuditArg.mk' _) with "[$Ha]") as "* (Hsl_b&_&_&%Hwish)".
  { iDestruct own_slice_nil as "$".
    iDestruct own_slice_cap_nil as "$". }
  simpl in *.
  wp_apply wp_alloc as "* Hreply".
  wp_apply (wp_Audit_cli_call (Q_read_idx (uint.nat prevEpoch))
    with "[$Hsl_b $Hreply]") as "* @".
  { iFrame "#". case_match; try done.
    iModIntro.
    iNamed "His_args".
    by iApply op_read_idx. }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameUnknown.
    iApply "HΦ".
    iSplit; [|by case_decide].
    iPureIntro. apply ktcore.blame_unknown. }
  iNamed "Herr_net".
  iPersist "Hsl_reply".
  wp_apply (AuditReply.wp_dec with "[$Hsl_reply]") as "* Hgenie".
  wp_if_destruct.
  { rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iSplit; [|by case_decide].
    iApply ktcore.blame_one.
    iIntros (?).
    case_match; try done.
    iNamed "Hgood".
    iApply "Hgenie".
    naive_solver. }
  iDestruct "Hgenie" as (??) "(#Hreply&_&%His_dec)".
  destruct obj. iNamed "Hreply".
  wp_auto. simpl.
  wp_if_destruct.
  { rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iSplit; try done.
    iApply ktcore.blame_one.
    iIntros (?).
    case_match; try done.
    iNamed "Hgood".
    opose proof (AuditReply.wish_det _ _ _ _ His_dec His_reply) as [? _].
    simplify_eq/=.
    iDestruct "Hgood" as "[@|@]".
    - iApply "Hgenie". naive_solver.
    - opose proof (AuditArg.wish_det _ _ _ _ Hwish Hdec) as [? _].
      simplify_eq/=.
      iDestruct "HQ" as "[#Hnew_hist %]".
      iDestruct "Herr" as %?.
      lia. }

  rewrite /ktcore.BlameNone ktcore.rw_BlameNone.
  iApply "HΦ".
  iSplit.
  { iPureIntro. apply ktcore.blame_none. }
  case_decide; try done.
  iFrame "#".
  case_match; try done.
  iNamed "Hgood".
  opose proof (AuditReply.wish_det _ _ _ _ His_dec His_reply) as [? _].
  simplify_eq/=.
  iDestruct "Hgood" as "[@|@]"; try done.
  opose proof (AuditArg.wish_det _ _ _ _ Hwish Hdec) as [? _].
  simplify_eq/=.
  iDestruct "HQ" as "[#Hnew_hist %]".
  iNamed "Herr".

  iClear "His_args".
  iApply big_sepL_intro.
  iModIntro. iIntros (?? Hlook_proofs) "!> * @! %".
  rewrite /wish_getNextLink /history.align_serv.
  destruct adtr_hist, σ. simplify_eq/=.
  iDestruct (big_sepL_lookup with "His_upds") as "{His_upds} @"; [done|].
  iDestruct (big_sepL_lookup with "His_sigs") as "{His_sigs} @"; [done|].
  apply lookup_lt_Some in Hlook_proofs.
  iDestruct (mono_list_lb_valid with "Hnew_hist His_hist") as %[[? Hpref]|[new_hist ?]].
  { apply (f_equal length) in Hpref.
    autorewrite with len in *. word. }
  simplify_eq/=.
  autorewrite with len in *.
  pose proof Hlook1 as Ht.
  apply list_lookup_fmap_Some_1 in Ht as (new_ep&?&Hlook_new).
  iDestruct (mono_list_lb_own_le (hist ++ [new_ep]) with "Hnew_hist")
    as "{Hnew_hist His_hist} Hlb".
  { apply prefix_snoc.
    { by apply prefix_app_r. }
    rewrite -Hlook_new. f_equal. word. }

  iFrame "#".
  autorewrite with len.
  repeat iSplit; try done; try iPureIntro.
  - word.
  - apply list_lookup_fmap_Some_1 in Hlook0 as (?&?&Ht).
    rewrite lookup_app_l in Ht; [|word].
    replace (_ + _)%nat with (pred $ length hist) in Ht by word.
    rewrite -last_lookup in Ht.
    rewrite fmap_last Ht.
    naive_solver.
  - iExactEq "His_link". rewrite /named. f_equal; [|word].
    erewrite take_S_r.
    + f_equal.
      rewrite fmap_app take_app_length'; [done|].
      len.
    + rewrite -Hlook1. f_equal. word.
  - word.
  - rewrite fmap_app. naive_solver.
Qed.

End proof.
End auditor.
