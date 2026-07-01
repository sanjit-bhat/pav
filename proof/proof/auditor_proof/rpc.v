From New.generatedproof.github_com.sanjit_bhat.pav Require Import auditor.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import
  advrpc cryptoffi hashchain ktcore merkle server.

From New.proof.github_com.sanjit_bhat.pav.auditor_proof Require Import
  auditor rpc_serv serde.

Module auditor.
Import auditor.auditor rpc_serv.auditor serde.auditor.

Module Trust.
Inductive t :=
  | No
  | SigPred (γ : ktcore.Agree.t)
  | Full (γ : cfg.t).

Definition get_sigpred t :=
  match t with
  | SigPred γ => Some γ
  | Full γ => Some γ.(cfg.agreeγ)
  | _ => None
  end.

Definition get_full t := match t with Full γ => Some γ | _ => None end.

Lemma full_to_sigpred t γ :
  get_full t = Some γ →
  get_sigpred t = Some γ.(cfg.agreeγ).
Proof.
  rewrite /get_full /get_sigpred. intros.
  case_match; try done.
  naive_solver.
Qed.
End Trust.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_NewRpcServer a γ :
  {{{
    is_pkg_init auditor ∗
    "Hlocks" ∷ ([∗] replicate (Z.to_nat rwmutex.actualMaxReaders)
      (Auditor.lock_perm a γ))
  }}}
  @! auditor.NewRpcServer #a
  {{{
    ptr_adtr_rpc, RET #ptr_adtr_rpc;
    "#His_adtr_rpc" ∷ advrpc.is_Server ptr_adtr_rpc
  }}}.
Proof. Admitted.

Definition is_rpc_cli (c : loc) (good : Trust.t) : iProp Σ :=
  match Trust.get_full good with None => True | Some γ => is_inv γ end.

#[global] Instance is_rpc_cli_pers c good : Persistent (is_rpc_cli c good).
Proof. apply _. Qed.

Lemma wp_Dial (good : Trust.t) (addr : w64) :
  {{{ is_pkg_init advrpc }}}
  @! advrpc.Dial #addr
  {{{
    ptr_cli, RET #ptr_cli;
    "#His_cli" ∷ is_rpc_cli ptr_cli good
  }}}.
Proof. Admitted.

Lemma wp_Get_cli_call (Q : cfg.t → state.t → iProp Σ)
    c good sl_arg d0 arg ptr_reply (x : slice.t) :
  {{{
    is_pkg_init auditor ∗
    "#His_cli" ∷ is_rpc_cli c good ∗
    "Hsl_arg" ∷ sl_arg ↦*{d0} arg ∗
    "Hptr_reply" ∷ ptr_reply ↦ x ∗
    "#Hfupd" ∷ match Trust.get_full good with None => True | Some γ =>
      □ (|={⊤,∅}=> ∃ σ, own γ σ ∗
        (own γ σ ={∅,⊤}=∗ Q γ σ)) end
  }}}
  c @! (go.PointerType advrpc.Client) @! "Call" auditor.GetRpc #sl_arg #ptr_reply
  {{{
    sl_reply err0, RET #err0;
    "Hsl_arg" ∷ sl_arg ↦*{d0} arg ∗
    "Hptr_reply" ∷ ptr_reply ↦ sl_reply ∗

    "Herr_net" ∷ match err0 with true => True | false =>
    ∃ replyB,
    "Hsl_reply" ∷ sl_reply ↦* replyB ∗

    "Hgood" ∷ match Trust.get_full good with None => True | Some γ =>
    let agreeγ := γ.(cfg.agreeγ) in
    ∃ startEp startLink currLink vrf err1,
    "%His_reply" ∷ ⌜GetReply.wish replyB
      (GetReply.mk' startEp startLink currLink vrf err1) []⌝ ∗

    (("%Herr_adtr_dec" ∷ ⌜err1 = true⌝ ∗
      "Hgenie" ∷ ¬ ⌜∃ obj tail, GetArg.wish arg obj tail⌝) ∨

    ∃ epoch tail σ,
    "%Hdec" ∷ ⌜GetArg.wish arg (GetArg.mk' epoch) tail⌝ ∗
    "HQ" ∷ Q γ σ ∗

    "#Herr_adtr_args" ∷
      match err1 with
      | true =>
        ⌜uint.Z epoch < agreeγ.(ktcore.Agree.digs_start) + agreeγ.(ktcore.Agree.func_start) ∨
        uint.Z epoch >= agreeγ.(ktcore.Agree.digs_start) + length σ.(state.digs)⌝
      | false =>
        "#Hwish_startLink" ∷ wish_SignedLink γ.(cfg.serv_sig_pk) γ.(cfg.adtr_sig_pk) startEp startLink ∗
        "#Hwish_currLink" ∷ wish_SignedLink γ.(cfg.serv_sig_pk) γ.(cfg.adtr_sig_pk) epoch currLink ∗
        "#Hwish_vrf" ∷ wish_SignedVrf γ.(cfg.serv_sig_pk) γ.(cfg.adtr_sig_pk) vrf ∗
        "%Heq_vrf" ∷ ⌜vrf.(SignedVrf.VrfPk) = agreeγ.(ktcore.Agree.vrf_pk)⌝ ∗
        "%Heq_startEp" ∷ ⌜uint.nat startEp = (agreeγ.(ktcore.Agree.digs_start) + agreeγ.(ktcore.Agree.func_start))%nat⌝
      end) end end
  }}}.
Proof. Admitted.

Lemma wp_CallGet c good (epoch : w64) :
  {{{
    is_pkg_init auditor ∗
    "#His_cli" ∷ is_rpc_cli c good
  }}}
  @! auditor.CallGet #c #epoch
  {{{
    (startEp : w64) ptr_startLink ptr_currLink ptr_vrf err,
    RET (#startEp, #ptr_startLink, #ptr_currLink, #ptr_vrf, #(ktcore.blame_to_u64 err));
    "%Hblame" ∷ ⌜ktcore.BlameSpec err {[ktcore.BlameAdtrFull:=option_bool $ Trust.get_full good]}⌝ ∗
    "Herr" ∷ (if decide (err ≠ ∅) then True else
      ∃ startLink currLink vrf,
      "#Hown_startLink" ∷ SignedLink.own ptr_startLink startLink (□) ∗
      "#Hown_currLink" ∷ SignedLink.own ptr_currLink currLink (□) ∗
      "#Hown_vrf" ∷ SignedVrf.own ptr_vrf vrf (□) ∗

      "Hgood" ∷ match Trust.get_full good with None => True | Some γ =>
        let agreeγ := γ.(cfg.agreeγ) in
        "#Hwish_startLink" ∷ wish_SignedLink γ.(cfg.serv_sig_pk) γ.(cfg.adtr_sig_pk) startEp startLink ∗
        "#Hwish_currLink" ∷ wish_SignedLink γ.(cfg.serv_sig_pk) γ.(cfg.adtr_sig_pk) epoch currLink ∗
        "#Hwish_vrf" ∷ wish_SignedVrf γ.(cfg.serv_sig_pk) γ.(cfg.adtr_sig_pk) vrf ∗
        "%Heq_vrf" ∷ ⌜vrf.(SignedVrf.VrfPk) = agreeγ.(ktcore.Agree.vrf_pk)⌝ ∗
        "%Heq_startEp" ∷ ⌜uint.nat startEp = (agreeγ.(ktcore.Agree.digs_start) + agreeγ.(ktcore.Agree.func_start))%nat⌝ end)
  }}}.
Proof.
  wp_start as "@". wp_auto.
  wp_apply wp_alloc as "* Ha".
  wp_apply (GetArg.wp_enc (GetArg.mk' _) with "[$Ha]") as "* (Hsl_b&_&_&%Hwish)".
  { iDestruct own_slice_nil as "$".
    iDestruct own_slice_cap_nil as "$". }
  simpl in *.
  wp_apply wp_alloc as "* Hreply".
  wp_apply (wp_Get_cli_call (λ _ _, True%I)
    with "[$Hsl_b $Hreply]") as "* @".
  { iFrame "#".
    rewrite /is_rpc_cli.
    case_match; [|done].
    by iApply op_read. }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameUnknown.
    iApply "HΦ".
    iSplit; [|by case_decide].
    iPureIntro. apply ktcore.blame_unknown. }
  iNamed "Herr_net".
  iPersist "Hsl_reply".
  wp_apply (GetReply.wp_dec with "[$Hsl_reply]") as "* Hgenie".
  wp_if_destruct.
  { rewrite ktcore.rw_BlameAdtrFull.
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
  { rewrite ktcore.rw_BlameUnknown.
    iApply "HΦ".
    iSplit; [|by case_decide].
    iPureIntro. apply ktcore.blame_unknown. }

  rewrite /ktcore.BlameNone ktcore.rw_BlameNone.
  iApply "HΦ".
  iSplitR. { iPureIntro. apply ktcore.blame_none. }
  case_decide; try done.
  iFrame "#".
  case_match; try done.
  iNamed "Hgood".
  opose proof (GetReply.wish_det _ _ _ _ His_dec His_reply) as [? _].
  simplify_eq/=.
  iDestruct "Hgood" as "[@|@]"; try done.
  opose proof (GetArg.wish_det _ _ _ _ Hwish Hdec) as [? _].
  simplify_eq/=.
  iNamed "Herr_adtr_args".
  by iFrame "#%".
Qed.

End proof.
End auditor.
