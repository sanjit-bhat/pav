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
    digs: list $ list w8;
  }.
End state.

(* cfg is the static state we know about this party, if good. *)
Module cfg.
Record t :=
  mk {
    (* duplicate [serv_sig_pk] across [serv_good] bc we need to know
    it unconditionally. *)
    serv_sig_pk: list w8;
    adtr_sig_pk: list w8;
    sigγ: sigpred.cfg.t;
    serv_good: option $ server.cfg.t;
  }.
End cfg.

Notation vrf_pkγ γ := (γ.(cfg.sigγ).(sigpred.cfg.vrf_pk)).
Notation digsγ γ := (γ.(cfg.sigγ).(sigpred.cfg.digs)).
Notation start_epγ γ := (γ.(cfg.sigγ).(sigpred.cfg.info).(sigpred.digs_info.start_ep)).
Notation cutγ γ := (γ.(cfg.sigγ).(sigpred.cfg.info).(sigpred.digs_info.cut)).
Notation audit_offsetγ γ := (γ.(cfg.sigγ).(sigpred.cfg.info).(sigpred.digs_info.audit_offset)).

Module epoch.
Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr σ ep γ : iProp Σ :=
  ∃ sl_link link sl_servSig servSig sl_adtrSig adtrSig,
  "#Hstr_epoch" ∷ ptr ↦□ (auditor.epoch.mk sl_link sl_servSig sl_adtrSig) ∗
  "#Hsl_link" ∷ sl_link ↦*□ link ∗
  (* could derive this from LinkSig, but it's easier to state explicitly. *)
  "%His_link" ∷ ⌜hashchain.valid (take (S ep - start_epγ γ) σ.(state.digs)) (cutγ γ) link (S $ S ep)⌝ ∗
  "#Hsl_servSig" ∷ sl_servSig ↦*□ servSig ∗
  "#His_servSig" ∷ ktcore.wish_LinkSig γ.(cfg.serv_sig_pk) (W64 ep) link servSig ∗
  "#Hsl_adtrSig" ∷ sl_adtrSig ↦*□ adtrSig ∗
  "#His_adtrSig" ∷ ktcore.wish_LinkSig γ.(cfg.adtr_sig_pk) (W64 ep) link adtrSig.

End proof.
End epoch.

Module history.
Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

(* TODO: in-mem startEp and sigpred startEp are diff values.
we should give them diff names. *)
Definition own ptr γ σ q : iProp Σ :=
  ∃ sl_lastDig lastDig start_ep sl_epochs sl0_epochs,
  let last_ep := start_epγ γ + length σ.(state.digs) - 1 in
  "Hstr_history" ∷ ptr ↦{#q} (auditor.history.mk sl_lastDig start_ep sl_epochs) ∗
  "#Hsl_lastDig" ∷ sl_lastDig ↦*□ lastDig ∗
  "%Heq_lastDig" ∷ ⌜last σ.(state.digs) = Some lastDig⌝ ∗
  "Hsl_epochs" ∷ sl_epochs ↦*{#q} sl0_epochs ∗
  "Hcap_epochs" ∷ own_slice_cap loc sl_epochs (DfracOwn q) ∗
  "#Hepochs" ∷ ([∗ list] idx ↦ p ∈ sl0_epochs,
    epoch.own p σ (uint.nat start_ep + idx) γ) ∗
  "%Hsome_digs" ∷ ⌜length σ.(state.digs) > 0⌝ ∗
  "%Hnoof_ep" ∷ ⌜last_ep = uint.Z $ W64 last_ep⌝ ∗
  "%Heq_audit_start" ∷ ⌜uint.nat start_ep = (start_epγ γ + audit_offsetγ γ)%nat⌝.

Definition align_serv σ γ servγ : iProp Σ :=
  ∃ hist,
  "#His_hist" ∷ mono_list_lb_own (server.digsγ servγ) hist ∗
  "%Heq_digs" ∷ ⌜σ.(state.digs) = hist⌝ ∗
  "%Heq_start_ep" ∷ ⌜start_epγ γ = 0%nat⌝ ∗
  "%Heq_cut" ∷ ⌜cutγ γ = None⌝.

#[global] Instance own_aux_combine_sep_as ptr γ σ0 σ1 q0 q1 :
  CombineSepAs (own ptr γ σ0 q0) (own ptr γ σ1 q1) (own ptr γ σ0 (q0 + q1)) | 60.
Proof.
  rewrite /CombineSepAs.
  iIntros "[H0 H1]".
  iNamedSuffix "H0" "0".
  iNamedSuffix "H1" "1".
  iCombine "Hstr_history0 Hstr_history1" as "?" gives %?.
  simplify_eq/=.
  iCombine "Hsl_epochs0 Hsl_epochs1" as "?" gives %?.
  iCombine "Hcap_epochs0 Hcap_epochs1" as "?".
  iCombine "Hsl_lastDig0 Hsl_lastDig1" gives %?.
  simplify_eq/=.
  (* TODO: DfracOwn q0 ⋅ DfracOwn q1. not getting combined properly. *)
  iFrame "∗#%".
Qed.

#[global] Instance own_frac ptr γ σ :
  fractional.Fractional (λ q, own ptr γ σ q).
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

#[global] Instance own_as_frac ptr γ σ q :
  fractional.AsFractional (own ptr γ σ q) (λ q, own ptr γ σ q) q.
Proof. auto. Qed.

End proof.
End history.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition wish_getNextLink γ σ proof (ep : w64) dig link : iProp Σ :=
  ∃ prevDig,
  "%Heq_ep" ∷ ⌜uint.Z ep = (start_epγ γ + length σ.(state.digs))%Z⌝ ∗
  "%Heq_prevDig" ∷ ⌜last σ.(state.digs) = Some prevDig⌝ ∗
  "#His_upd" ∷ ktcore.wish_ListUpdate prevDig
    proof.(ktcore.AuditProof.Updates) dig ∗
  "%His_link" ∷ ⌜hashchain.valid (σ.(state.digs) ++ [dig]) (cutγ γ)
    link (S $ S $ uint.nat ep)⌝ ∗
  "#His_sig" ∷ ktcore.wish_LinkSig γ.(cfg.serv_sig_pk) ep link
    proof.(ktcore.AuditProof.LinkSig).

Lemma wish_getNextLink_det γ σ proof ep0 dig0 link0 ep1 dig1 link1 :
  wish_getNextLink γ σ proof ep0 dig0 link0 -∗
  wish_getNextLink γ σ proof ep1 dig1 link1 -∗
  ⌜ep0 = ep1 ∧ dig0 = dig1 ∧ link0 = link1⌝.
Proof.
  iNamedSuffix 1 "0".
  iNamedSuffix 1 "1".
  simplify_eq/=.
  iDestruct (ktcore.wish_ListUpdate_det with "His_upd0 His_upd1") as %->.
  destruct His_link0 as [His_link0 _].
  destruct His_link1 as [His_link1 _].
  rewrite -His_link1 in His_link0.
  opose proof (hashchain.det _ _ _ _ His_link0) as ->.
  iPureIntro. repeat split. word.
Qed.

Lemma wp_CallAudit c good (prevEpoch : w64) :
  {{{
    is_pkg_init server ∗
    "#His_serv" ∷ is_rpc_cli c good ∗
    "#His_args" ∷ match good with None => True | Some γ =>
      ∃ entry : list w8,
      "#Hidx_ep" ∷ mono_list_idx_own (server.digsγ γ) (uint.nat prevEpoch) entry end
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
          □ ∀ adtrγ adtrσ,
          history.align_serv adtrσ adtrγ γ -∗
          ⌜start_epγ adtrγ + length adtrσ.(state.digs) - 1 =
            (uint.Z prevEpoch + idx)%Z⌝ -∗
          ⌜adtrγ.(cfg.serv_sig_pk) = γ.(cfg.sig_pk)⌝ -∗

          ∃ ep dig link,
          let adtrσ' := set state.digs (.++ [dig]) adtrσ in
          "#Hwish_getNextLink" ∷ wish_getNextLink adtrγ adtrσ
            proof ep dig link ∗
          "#Halign_next" ∷ history.align_serv adtrσ' adtrγ γ) end)
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
  iModIntro. iIntros (?? Hlook_proofs) "!> * @ % %Heq_sig_pk".
  rewrite /wish_getNextLink /history.align_serv.
  destruct adtrσ, σ. simplify_eq/=.
  iDestruct (big_sepL_lookup with "His_upds") as "{His_upds} @"; [done|].
  iDestruct (big_sepL_lookup with "His_sigs") as "{His_sigs} @"; [done|].
  apply lookup_lt_Some in Hlook_proofs.
  iDestruct (mono_list_lb_valid with "Hnew_hist His_hist") as %[[? Hpref]|[new_hist ?]].
  { apply (f_equal length) in Hpref.
    autorewrite with len in *. word. }
  simplify_eq/=.
  autorewrite with len in *.
  iDestruct (mono_list_lb_own_le (hist ++ [dig1]) with "Hnew_hist")
    as "{Hnew_hist His_hist} Hlb".
  { apply prefix_snoc.
    { by apply prefix_app_r. }
    rewrite -Hlook1. f_equal. word. }

  rewrite Heq_sig_pk.
  iFrame "#".
  repeat iSplit; try done; try iPureIntro.
  - word.
  - rewrite lookup_app_l in Hlook0; [|word].
    replace (_ + _)%nat with (pred $ length hist) in Hlook0 by word.
    rewrite -last_lookup in Hlook0.
    rewrite Hlook0.
    naive_solver.
  - exact_eq His_link; [|done|word].
    erewrite take_S_r.
    2: { by erewrite <-Hlook1. }
    rewrite take_app_length'; [done|].
    len.
Qed.

End proof.
End auditor.
