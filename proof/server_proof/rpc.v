From New.generatedproof.github_com.sanjit_bhat.pav Require Import advrpc server.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi hashchain ktcore merkle.

From New.proof.github_com.sanjit_bhat.pav.server_proof Require Import
  serde server.

(* notes:
- BlameUnknown is like giving up.
it gives the caller a trivial postcond.
since the request might not have even hit the serv, it's not in front of a Q.
- the specs implicitly assume a good network pipeline to good serv.
under those conditions, the RPC client should encode args correctly,
the RPC server should decode args correctly,
the RPC server should encode replies correctly,
and the RPC client should decode replies correctly.
the specs capture this by not allowing errors from RPC serde. *)

Module server.
Import serde.server server.server.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _, !globalsGS Σ} {go_ctx : GoContext}.
Context `{!pavG Σ}.

(* TODO: make [is_rpc_cli] generic. currently, specialized to server. *)
Definition is_rpc_cli (c : loc) (good : option cfg.t) : iProp Σ :=
  match good with None => True | Some γ => is_inv γ end.

#[global] Instance is_rpc_cli_pers c good : Persistent (is_rpc_cli c good).
Proof. apply _. Qed.

(* TODO: trusted good param. *)
Lemma wp_Dial (good : option cfg.t) (addr : w64) :
  {{{ is_pkg_init advrpc }}}
  @! advrpc.Dial #addr
  {{{
    ptr_cli, RET #ptr_cli;
    "#His_cli" ∷ is_rpc_cli ptr_cli good
  }}}.
Proof. Admitted.

Lemma wp_CallPut c good uid sl_pk pk ver :
  {{{
    is_pkg_init server ∗
    "#His_cli" ∷ is_rpc_cli c good ∗
    "#Hsl_pk" ∷ sl_pk ↦*□ pk ∗
    "#His_put" ∷ match good with None => True | Some γ =>
      ∃ i uidγ,
      "%Hlook_uidγ" ∷ ⌜γ.(cfg.uidγ) !! uid = Some uidγ⌝ ∗
      "#Hidx" ∷ mono_list_idx_own uidγ i (ver, pk) end
  }}}
  @! server.CallPut #c #uid #sl_pk #ver
  {{{ RET #(); True }}}.
Proof. Admitted.

Lemma wp_History_cli_call (Q : cfg.t → state.t → iProp Σ)
    c good sl_arg d0 arg ptr_reply (x : slice.t) :
  {{{
    is_pkg_init server ∗
    "#His_cli" ∷ is_rpc_cli c good ∗
    "Hsl_arg" ∷ sl_arg ↦*{d0} arg ∗
    "Hptr_reply" ∷ ptr_reply ↦ x ∗
    "#Hfupd" ∷ match good with None => True | Some γ =>
      □ (|={⊤,∅}=> ∃ σ, own γ σ ∗ (own γ σ ={∅,⊤}=∗ Q γ σ)) end
  }}}
  c @! (go.PointerType advrpc.Client) @! "Call" server.HistoryRpc #sl_arg #ptr_reply
  {{{
    sl_reply err0, RET #err0;
    "Hsl_arg" ∷ sl_arg ↦*{d0} arg ∗
    "Hptr_reply" ∷ ptr_reply ↦ sl_reply ∗

    "Herr_net" ∷ match err0 with true => True | false =>
    ∃ replyB,
    "Hsl_reply" ∷ sl_reply ↦* replyB ∗

    "Hgood" ∷ match good with None => True | Some γ =>
    ∃ chainProof linkSig hist bound err1,
    "%His_reply" ∷ ⌜HistoryReply.wish replyB
      (HistoryReply.mk' chainProof linkSig hist bound err1) []⌝ ∗

    (* align with serv rpc rcvr, which doesn't know encoded args in precond. *)
    (("%Herr_serv_dec" ∷ ⌜err1 = true⌝ ∗
      "Hgenie" ∷ ¬ ⌜∃ obj tail, HistoryArg.wish arg obj tail⌝) ∨

    ∃ uid prevEpoch prevVerLen tail σ lastDig lastKeys,
    let numEps := length σ.(state.hist) in
    let pks := lastKeys !!! uid in
    "%Hdec" ∷ ⌜HistoryArg.wish arg
      (HistoryArg.mk' uid prevEpoch prevVerLen) tail⌝ ∗
    "HQ" ∷ Q γ σ ∗
    "%Hlast_hist" ∷ ⌜last σ.(state.hist) = Some (lastDig, lastKeys)⌝ ∗

    "#Herr_serv_args" ∷
      match err1 with
      | true => ⌜uint.nat prevEpoch ≥ numEps ∨
        uint.nat prevVerLen > length pks⌝
      | false =>
        ∃ lastLink,
        "%Hnoof_epochs" ∷ ⌜numEps = sint.nat (W64 numEps)⌝ ∗
        "%Hnoof_vers" ∷ ⌜length pks = sint.nat (W64 (length pks))⌝ ∗
        "#His_lastLink" ∷ hashchain.is_chain σ.(state.hist).*1 None lastLink numEps ∗

        "%Hwish_chainProof" ∷ ⌜hashchain.wish_Proof chainProof
          (drop (S (uint.nat prevEpoch)) σ.(state.hist).*1)⌝ ∗
        "#Hwish_linkSig" ∷ ktcore.wish_LinkSig γ.(cfg.sig_pk)
          (W64 $ (Z.of_nat numEps - 1)) lastLink linkSig ∗
        "#Hwish_hist" ∷ ktcore.wish_ListMemb γ.(cfg.vrf_pk) uid prevVerLen
          lastDig hist ∗
        "%Heq_hist" ∷ ⌜Forall2
          (λ x y, x = y.(ktcore.Memb.PkOpen).(ktcore.CommitOpen.Val))
          (drop (uint.nat prevVerLen) pks) hist⌝ ∗
        "#Hwish_bound" ∷ ktcore.wish_NonMemb γ.(cfg.vrf_pk) uid
          (W64 $ length pks) lastDig bound
      end) end end
  }}}.
Proof. Admitted.

Lemma wp_Audit_cli_call (Q : cfg.t → state.t → iProp Σ)
    c good sl_arg d0 arg ptr_reply (x : slice.t) :
  {{{
    is_pkg_init server ∗
    "#His_cli" ∷ is_rpc_cli c good ∗
    "Hsl_arg" ∷ sl_arg ↦*{d0} arg ∗
    "Hptr_reply" ∷ ptr_reply ↦ x ∗
    "#Hfupd" ∷ match good with None => True | Some γ =>
      □ (|={⊤,∅}=> ∃ σ, own γ σ ∗ (own γ σ ={∅,⊤}=∗ Q γ σ)) end
  }}}
  c @! (go.PointerType advrpc.Client) @! "Call" server.AuditRpc #sl_arg #ptr_reply
  {{{
    sl_reply err0, RET #err0;
    "Hsl_arg" ∷ sl_arg ↦*{d0} arg ∗
    "Hptr_reply" ∷ ptr_reply ↦ sl_reply ∗

    "Herr_net" ∷ match err0 with true => True | false =>
    ∃ replyB,
    "Hsl_reply" ∷ sl_reply ↦* replyB ∗

    "Hgood" ∷ match good with None => True | Some γ =>
    ∃ proofs err1,
    "%His_reply" ∷ ⌜AuditReply.wish replyB (AuditReply.mk' proofs err1) []⌝ ∗

    (("%Herr_serv_dec" ∷ ⌜err1 = true⌝ ∗
      "Hgenie" ∷ ¬ ⌜∃ obj tail, AuditArg.wish arg obj tail⌝) ∨

    ∃ prevEpoch tail σ,
    let numEps := length σ.(state.hist) in
    "%Hdec" ∷ ⌜AuditArg.wish arg (AuditArg.mk' prevEpoch) tail⌝ ∗
    "HQ" ∷ Q γ σ ∗
    "Herr" ∷
      match err1 with
      | true => ⌜uint.nat prevEpoch ≥ length σ.(state.hist)⌝
      | false =>
        "%Hnoof_eps" ∷ ⌜numEps = sint.nat (W64 $ numEps)⌝ ∗
        "%Hlen_proofs" ∷ ⌜(uint.Z prevEpoch + length proofs + 1)%Z = numEps⌝ ∗

        "#His_upds" ∷ ([∗ list] i ↦ aud ∈ proofs,
          ∃ dig0 dig1,
          let predEp := (uint.nat prevEpoch + i)%nat in
          "%Hlook0" ∷ ⌜σ.(state.hist).*1 !! predEp = Some dig0⌝ ∗
          "%Hlook1" ∷ ⌜σ.(state.hist).*1 !! (S predEp) = Some dig1⌝ ∗
          "#His_upd" ∷ ktcore.wish_ListUpdate dig0 aud.(ktcore.AuditProof.Updates) dig1) ∗
        "#His_sigs" ∷ ([∗ list] i ↦ aud ∈ proofs,
          ∃ link,
          let ep := (uint.nat prevEpoch + S i)%nat in
          "#His_link" ∷ hashchain.is_chain (take (S ep) σ.(state.hist).*1)
            None link (S ep) ∗
          "#His_sig" ∷ ktcore.wish_LinkSig γ.(cfg.sig_pk) (W64 ep) link aud.(ktcore.AuditProof.LinkSig))
      end) end end
  }}}.
Proof. Admitted.

Lemma wp_Start_cli_call (Q : cfg.t → state.t → iProp Σ)
    c good sl_arg d0 (arg : list w8) ptr_reply (x : slice.t) :
  {{{
    is_pkg_init server ∗
    "#His_cli" ∷ is_rpc_cli c good ∗
    "Hsl_arg" ∷ sl_arg ↦*{d0} arg ∗
    "Hptr_reply" ∷ ptr_reply ↦ x ∗
    "#Hfupd" ∷ match good with None => True | Some γ =>
      □ (|={⊤,∅}=> ∃ obj, own γ obj ∗ (own γ obj ={∅,⊤}=∗ Q γ obj)) end
  }}}
  c @! (go.PointerType advrpc.Client) @! "Call" server.StartRpc #sl_arg #ptr_reply
  {{{
    sl_reply err0, RET #err0;
    "Hsl_arg" ∷ sl_arg ↦*{d0} arg ∗
    "Hptr_reply" ∷ ptr_reply ↦ sl_reply ∗

    "Herr_net" ∷ match err0 with true => True | false =>
    ∃ replyB,
    "Hsl_reply" ∷ sl_reply ↦* replyB ∗

    "Hgood" ∷ match good with None => True | Some γ =>
    ∃ chain vrf obj last_link,
    let numEps := length obj.(state.hist) in
    "%His_reply" ∷ ⌜StartReply.wish replyB (StartReply.mk' chain vrf) []⌝ ∗

    "HQ" ∷ Q γ obj ∗
    "%Hnoof_eps" ∷ ⌜numEps = sint.nat (W64 $ numEps)⌝ ∗

    "%His_PrevEpochLen" ∷ ⌜uint.nat chain.(StartChain.PrevEpochLen) < numEps⌝ ∗
    "#His_PrevLink" ∷ hashchain.is_chain
      (take (uint.nat chain.(StartChain.PrevEpochLen)) obj.(state.hist).*1)
      None chain.(StartChain.PrevLink)
      (uint.nat chain.(StartChain.PrevEpochLen)) ∗
    "%His_ChainProof" ∷ ⌜hashchain.wish_Proof chain.(StartChain.ChainProof)
      (drop (uint.nat chain.(StartChain.PrevEpochLen)) obj.(state.hist).*1)⌝ ∗
    "#His_last_link" ∷ hashchain.is_chain obj.(state.hist).*1 None
      last_link numEps ∗
    "#His_LinkSig" ∷ ktcore.wish_LinkSig γ.(cfg.sig_pk)
      (W64 $ numEps - 1) last_link chain.(StartChain.LinkSig) ∗

    "%Heq_VrfPk" ∷ ⌜γ.(cfg.vrf_pk) = vrf.(StartVrf.VrfPk)⌝ ∗
    "#His_VrfPk" ∷ cryptoffi.is_vrf_pk vrf.(StartVrf.VrfPk) ∗
    "#His_VrfSig" ∷ ktcore.wish_VrfSig γ.(cfg.sig_pk) γ.(cfg.vrf_pk)
      vrf.(StartVrf.VrfSig)
    end end
  }}}.
Proof. Admitted.

Definition wish_CheckStartChain servPk chain digs cut (ep : w64) dig link : iProp Σ :=
  ∃ digs0 digs1,
  "#His_chain_prev" ∷ hashchain.is_chain digs0 cut chain.(server.StartChain.PrevLink)
    (uint.nat chain.(server.StartChain.PrevEpochLen)) ∗
  "%His_proof" ∷ ⌜hashchain.wish_Proof chain.(server.StartChain.ChainProof) digs1⌝ ∗
  "#His_chain_start" ∷ hashchain.is_chain digs cut link
    (uint.nat chain.(server.StartChain.PrevEpochLen) + length digs1) ∗
  "#His_link_sig" ∷ ktcore.wish_LinkSig servPk ep link chain.(server.StartChain.LinkSig) ∗

  "%Heq_digs" ∷ ⌜digs = digs0 ++ digs1⌝ ∗
  "%Heq_ep" ∷ ⌜uint.Z ep = uint.Z chain.(server.StartChain.PrevEpochLen) + length digs1 - 1⌝ ∗
  "%Heq_dig" ∷ ⌜last digs1 = Some dig⌝.

Lemma wish_CheckStartChain_det pk c digs0 digs1 cut0 cut1 e0 e1 d0 d1 l0 l1 :
  wish_CheckStartChain pk c digs0 cut0 e0 d0 l0 -∗
  wish_CheckStartChain pk c digs1 cut1 e1 d1 l1 -∗
  ⌜digs0 = digs1 ∧ cut0 = cut1 ∧ e0 = e1 ∧ d0 = d1 ∧ l0 = l1⌝.
Proof.
  iNamedSuffix 1 "0".
  iNamedSuffix 1 "1".
  iDestruct (hashchain.is_chain_inj with "His_chain_prev0 His_chain_prev1") as %[-> ->].
  opose proof (hashchain.wish_Proof_det _ _ _ His_proof0 His_proof1) as ->.
  simplify_eq/=.
  iDestruct (hashchain.is_chain_det with "His_chain_start0 His_chain_start1") as %->.
  iPureIntro.
  rewrite -Heq_ep0 in Heq_ep1.
  by simplify_eq/=.
Qed.

Lemma wish_CheckStartChain_extract servPk chain digs cut ep dig link:
  wish_CheckStartChain servPk chain digs cut ep dig link -∗
  "%Hlen_dig" ∷ ⌜length dig = Z.to_nat $ cryptoffi.hash_len⌝ ∗
  "%Hlast_digs" ∷ ⌜last digs = Some dig⌝.
Proof.
  iNamed 1. iPureIntro. subst. split.
  - destruct His_proof as [Hlens ?].
    destruct digs1 as [|dig' digs] using rev_ind; [done|clear IHdigs].
    rewrite last_snoc in Heq_dig.
    simplify_eq/=.
    by apply Forall_snoc in Hlens as [? ?].
  - by rewrite last_app Heq_dig.
Qed.

Definition wish_CheckStartVrf servPk vrf : iProp Σ :=
  "#His_vrf_pk" ∷ cryptoffi.is_vrf_pk vrf.(server.StartVrf.VrfPk) ∗
  "#His_vrf_sig" ∷ ktcore.wish_VrfSig servPk vrf.(server.StartVrf.VrfPk)
    vrf.(server.StartVrf.VrfSig).

Lemma wp_CallStart c good :
  {{{
    is_pkg_init server ∗
    "#His_cli" ∷ is_rpc_cli c good
  }}}
  @! server.CallStart #c
  {{{
    ptr_chain ptr_vrf err, RET (#ptr_chain, #ptr_vrf, #(ktcore.blame_to_u64 err));
    "%Hblame" ∷ ⌜ktcore.BlameSpec err {[ktcore.BlameServFull:=option_bool good]}⌝ ∗
    "#Herr" ∷ (if decide (err ≠ ∅) then True else
      ∃ chain vrf,
      "#Hptr_chain" ∷ StartChain.own ptr_chain chain (□) ∗
      "#Hptr_vrf" ∷ StartVrf.own ptr_vrf vrf (□) ∗

      "Hgood" ∷ match good with None => True | Some γ =>
        ∃ servHist ep dig link,
        "#Hlb_servHist" ∷ mono_list_lb_own γ.(cfg.histγ) servHist ∗
        (* epoch returned by CheckStartChain is only upper bound on (len digs).
        need exact equality so clients can certify their last ep. *)
        "%Heq_ep" ∷ ⌜uint.nat ep = (length servHist - 1)%nat⌝ ∗
        "#Hwish_StartChain" ∷ wish_CheckStartChain γ.(cfg.sig_pk) chain
          servHist.*1 None ep dig link ∗
        "%Heq_VrfPk" ∷ ⌜γ.(cfg.vrf_pk) = vrf.(StartVrf.VrfPk)⌝ ∗
        "#Hwish_StartVrf" ∷ wish_CheckStartVrf γ.(cfg.sig_pk) vrf end)
    }}}.
Proof.
  wp_start as "@". wp_auto.
  wp_apply wp_alloc as "* Ha".
  simpl in *.
  wp_apply (wp_Start_cli_call (Q_read_lb [])
    with "[$Ha]") as "* @".
  { iFrame "#".
    iDestruct (own_slice_nil DfracDiscarded) as "$".
    case_match; try done.
    iModIntro.
    iMod mono_list_lb_own_nil as "#?".
    by iApply op_read_lb. }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameUnknown.
    iApply "HΦ".
    iSplit; [|by case_decide].
    iPureIntro. apply ktcore.blame_unknown. }
  iNamed "Herr_net".
  iPersist "Hsl_reply".
  wp_apply (StartReply.wp_dec with "[$Hsl_reply]") as "* Hgenie".
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

  rewrite ktcore.rw_BlameNone.
  iApply "HΦ".
  iSplit. { iPureIntro. apply ktcore.blame_none. }
  case_decide; try done.
  iFrame "#".
  case_match; try done.
  iNamed "Hgood".
  opose proof (StartReply.wish_det _ _ _ _ His_dec His_reply) as [? _].
  simplify_eq/=.
  iDestruct "HQ" as "[#Hnew_hist %]".
  rewrite Heq_VrfPk.
  eremember (drop _ _) as digs1.
  list_elem digs1 (pred $ length digs1) as dig.
  { subst. len. }
  subst.
  rewrite -last_lookup in Hdig_lookup.
  iFrame "#%".

  repeat iSplit; try done.
  - word.
  - iExactEq "His_last_link". rewrite /named. f_equal. len.
  - by rewrite take_drop.
  - len.
Qed.

End proof.
End server.
