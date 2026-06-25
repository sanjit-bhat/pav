From New.generatedproof.github_com.sanjit_bhat.pav Require Import client server.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi hashchain ktcore merkle server.

From New.proof.github_com.sanjit_bhat.pav.client_proof Require Import
  base.

(* the [wp_CallHistory] here lives halfway between Client and Server.
it's in pkg server, but it's specialized to Client [wish_getNextEp]. *)

Module client.

Module cfg.
Record t :=
  mk {
    uid : w64;
    sig_pk : list w8;
    agreeγ : ktcore.Agree.t;
    serv_good : server.Trust.t;
    clis_good : bool;
  }.
End cfg.

Module state.
Record t :=
  mk {
    epoch : nat;
    keys : list $ option $ list w8;
    pend_pk : option $ list w8;
  }.
End state.

Section proof.
Context `{!heapGS Σ}.

Definition own γ (digs : list $ list w8) : iProp Σ :=
  let agreeγ := γ.(cfg.agreeγ) in
  "Hown_digs" ∷ mono_list_auth_own agreeγ.(ktcore.Agree.digs) 1 digs.

End proof.

Module ver.
Record t :=
  mk' {
    ver : nat;
  }.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Definition own ptr (pend_pk : option $ list w8) obj : iProp Σ :=
  ∃ w_ver hasPendPk sl_pendPk,
  "Hstr_ver" ∷ ptr ↦ (client.ver.mk w_ver hasPendPk sl_pendPk) ∗
  "%Heq_ver" ∷ ⌜uint.nat w_ver = obj.(ver)⌝ ∗
  "#HpendPk" ∷
    match pend_pk with
    | None =>
      "%Heq_hasPendPk" ∷ ⌜hasPendPk = false⌝
    | Some pk =>
      "%Heq_hasPendPk" ∷ ⌜hasPendPk = true⌝ ∗
      "#Heq_pendPk" ∷ sl_pendPk ↦*□ pk
    end.

Definition valid γ keys obj : iProp Σ :=
  ∃ digs,
  let agreeγ := γ.(cfg.agreeγ) in
  "#Hlb_ver_digs" ∷ mono_list_lb_own agreeγ.(ktcore.Agree.digs) digs ∗
  "%Hstaged" ∷ ⌜ktcore.staged_keys agreeγ.(ktcore.Agree.vrf_pk)
    (drop agreeγ.(ktcore.Agree.func_start) digs)
    γ.(cfg.uid) keys obj.(ver)⌝.

Definition uid_inv γ : iProp Σ :=
  ∃ (puts : list (nat * list w8)),
  "Hputs" ∷ mono_list_auth_own γ 1 puts.
(* is_uid_inv allows anyone, even malicious Client, to run Server Put.
TODO: for now, trusted connection to clis_good. *)
Definition is_uid_inv γ : iProp Σ := inv nroot (uid_inv γ).

Definition align_full γcli γserv (pend_pk : option $ list w8) obj : iProp Σ :=
  ∃ uidγ,
  "%Hlook_uidγ" ∷ ⌜γserv.(server.cfg.uidγ) !! γcli.(cfg.uid) = Some uidγ⌝ ∗
  "HgoodCli" ∷
    match γcli.(cfg.clis_good) with
    | true =>
      ∃ puts,
      "Hputs" ∷ mono_list_auth_own uidγ 1 puts ∗
      "%Hbound" ∷ ⌜∀ (ver' : nat) pk, (ver', pk) ∈ puts → ver' ≤ obj.(ver)⌝ ∗
      "%Heq_pend" ∷ ⌜∀ pk, (obj.(ver), pk) ∈ puts → pend_pk = Some pk⌝
    | false =>
      "#Huid_inv" ∷ is_uid_inv uidγ
    end.

End proof.
End ver.

Module epoch.
Record t :=
  mk' {
    epoch : w64;
    dig : list w8;
    link : list w8;
    sig : list w8;
  }.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj : iProp Σ :=
  ∃ sl_dig sl_link sl_sig,
  "#Hstr_epoch" ∷ ptr ↦□ (client.epoch.mk obj.(epoch) sl_dig sl_link sl_sig) ∗
  "#Hsl_dig" ∷ sl_dig ↦*□ obj.(dig) ∗
  "#Hsl_link" ∷ sl_link ↦*□ obj.(link) ∗
  "#Hsl_sig" ∷ sl_sig ↦*□ obj.(sig).

Definition valid γ digs obj : iProp Σ :=
  let agreeγ := γ.(cfg.agreeγ) in
  let num_eps := (agreeγ.(ktcore.Agree.digs_start) + length digs)%nat in
  "%Heq_ep" ∷ ⌜S $ uint.nat obj.(epoch) = num_eps⌝ ∗
  "%Hlast_dig" ∷ ⌜last digs = Some obj.(dig)⌝ ∗
  "%His_chain" ∷ ⌜hashchain.valid digs agreeγ.(ktcore.Agree.cut) obj.(link) num_eps⌝ ∗
  "#His_sig" ∷ ktcore.wish_LinkSig γ.(cfg.sig_pk) obj.(epoch) obj.(link) obj.(sig).

Definition align_sigpred servAgreeγ digs : iProp Σ :=
  "#Hserv_digs" ∷ mono_list_lb_own servAgreeγ.(ktcore.Agree.digs) digs ∗
  "%Hmono_plain" ∷ ⌜ktcore.mono_plain servAgreeγ.(ktcore.Agree.vrf_pk)
    (drop servAgreeγ.(ktcore.Agree.func_start) digs)⌝.

End proof.
End epoch.

Module serv.
Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Definition own γ ptr : iProp Σ :=
  let agreeγ := γ.(cfg.agreeγ) in
  ∃ ptr_cli sl_sigPk ptr_vrfPk sl_vrfSig vrfSig,
  "#Hstr_serv" ∷ ptr ↦□ (client.serv.mk ptr_cli sl_sigPk ptr_vrfPk sl_vrfSig) ∗
  "#His_rpc" ∷ server.is_rpc_cli ptr_cli γ.(cfg.serv_good) ∗
  "#Hsl_sigPk" ∷ sl_sigPk ↦*□ γ.(cfg.sig_pk) ∗
  "#Hown_vrfPk" ∷ cryptoffi.own_vrf_pk ptr_vrfPk agreeγ.(ktcore.Agree.vrf_pk) ∗
  "#Hsl_vrfSig" ∷ sl_vrfSig ↦*□ vrfSig ∗
  "#His_vrfSig" ∷ ktcore.wish_VrfSig γ.(cfg.sig_pk) agreeγ.(ktcore.Agree.vrf_pk) vrfSig.

Definition align_sigpred γcli servAgreeγ : iProp Σ :=
  let agreeγ := γcli.(cfg.agreeγ) in
  "#His_sigPk" ∷ cryptoffi.is_sig_pk γcli.(cfg.sig_pk) (sigpred.P servAgreeγ) ∗
  "%Heq_vrf_pk" ∷ ⌜agreeγ.(ktcore.Agree.vrf_pk) =
    servAgreeγ.(ktcore.Agree.vrf_pk)⌝ ∗
  "%Heq_digs_start" ∷ ⌜agreeγ.(ktcore.Agree.digs_start) =
    servAgreeγ.(ktcore.Agree.digs_start)⌝ ∗
  "%Heq_cut" ∷ ⌜agreeγ.(ktcore.Agree.cut) = servAgreeγ.(ktcore.Agree.cut)⌝ ∗
  "%Heq_func_start" ∷ ⌜servAgreeγ.(ktcore.Agree.func_start) ≤
    agreeγ.(ktcore.Agree.func_start)⌝.

Definition align_full γcli γserv : iProp Σ :=
  let agreeγ := γcli.(cfg.agreeγ) in
  let servAgreeγ := γserv.(server.cfg.agreeγ) in
  "%Heq_sig_pk" ∷ ⌜γcli.(cfg.sig_pk) = γserv.(server.cfg.sig_pk)⌝ ∗
  "%Heq_serv_digs_start" ∷ ⌜agreeγ.(ktcore.Agree.digs_start) = 0%nat⌝ ∗
  "%Heq_serv_cut" ∷ ⌜agreeγ.(ktcore.Agree.cut) = None⌝ ∗
  (* not required, but makes life easier. *)
  "%Heq_serv_func_start" ∷ ⌜servAgreeγ.(ktcore.Agree.func_start) = 0%nat⌝.

End proof.
End serv.

Module Client.
Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Definition own γ ptr σ : iProp Σ :=
  ∃ digs ptr_nextVer nextVer ptr_lastEp lastEp ptr_serv,
  "Hstr_client" ∷ ptr ↦ (client.Client.mk γ.(cfg.uid) ptr_nextVer ptr_lastEp ptr_serv) ∗
  "Hown_nextVer" ∷ ver.own ptr_nextVer σ.(state.pend_pk) nextVer ∗
  "#His_nextVer" ∷ ver.valid γ σ.(state.keys) nextVer ∗
  "Halign_nextVer" ∷ match server.Trust.get_full γ.(cfg.serv_good) with None => True | Some γserv =>
    ver.align_full γ γserv σ.(state.pend_pk) nextVer end ∗
  "#Hown_lastEp" ∷ epoch.own ptr_lastEp lastEp ∗
  "#His_lastEp" ∷ epoch.valid γ digs lastEp ∗
  "#Halign_lastEp" ∷ match server.Trust.get_sigpred γ.(cfg.serv_good) with None => True | Some γserv =>
    epoch.align_sigpred γserv digs end ∗
  "#Hown_serv" ∷ serv.own γ ptr_serv ∗
  "#Halign_serv_sigpred" ∷ match server.Trust.get_sigpred γ.(cfg.serv_good) with None => True | Some γserv =>
    serv.align_sigpred γ γserv end ∗
  "#Halign_serv_full" ∷ match server.Trust.get_full γ.(cfg.serv_good) with None => True | Some γserv =>
    serv.align_full γ γserv end ∗

  "Hown_gs" ∷ own γ digs ∗
  "%Heq_ep" ∷ ⌜S σ.(state.epoch) = (γ.(cfg.agreeγ).(ktcore.Agree.digs_start) + length digs)%nat⌝.

End proof.
End Client.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : client.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma know_keys γ ptr σ :
  let agreeγ := γ.(cfg.agreeγ) in
  Client.own γ ptr σ -∗
  ktcore.is_staged_keys agreeγ γ.(cfg.uid) σ.(state.keys).
Proof.
  rewrite /ktcore.is_staged_keys.
  iIntros "@".
  iNamed "His_nextVer".
  iFrame "#%".
Qed.

Lemma serv_is_adtr γ servAgreeγ ptr σ :
  let agreeγ := γ.(cfg.agreeγ) in
  server.Trust.get_sigpred γ.(cfg.serv_good) = Some servAgreeγ →
  Client.own γ ptr σ -∗
  ktcore.is_audit agreeγ servAgreeγ σ.(state.epoch) ∗
    ⌜servAgreeγ.(ktcore.Agree.func_start) ≤ agreeγ.(ktcore.Agree.func_start)⌝.
Proof.
  simpl. iIntros (Hgood) "@".
  rewrite Hgood /ktcore.is_audit.
  rewrite /own. iNamed "Hown_gs".
  iDestruct (mono_list_lb_own_get with "Hown_digs") as "$".
  iNamed "Halign_serv_sigpred".
  iFrame "%".
  iNamed "His_lastEp".
  iNamed "Halign_lastEp".
  iFrame "#%".
Qed.

(* arg order: Client state + getNextEp args + new Client state.
TODO: describe more once we finish proving related stuff.
especially all the implicit assertions this is making. *)
Definition wish_getNextEp γ digs chainProof sig newDigs next : iProp Σ :=
  ∃ nextEp nextDig nextLink,
  "%Heq_next" ∷ ⌜next = epoch.mk' nextEp nextDig nextLink sig⌝ ∗
  "%HnewDigs" ∷ ⌜hashchain.wish_Proof chainProof newDigs⌝ ∗
  "#His_next" ∷ epoch.valid γ (digs ++ newDigs) next.

Lemma wish_getNextEp_det γ digs proof sig newDigs0 newDigs1 next0 next1 :
  wish_getNextEp γ digs proof sig newDigs0 next0 -∗
  wish_getNextEp γ digs proof sig newDigs1 next1 -∗
  ⌜newDigs0 = newDigs1 ∧ next0 = next1⌝.
Proof.
  iNamedSuffix 1 "0".
  iNamedSuffix 1 "1".
  iNamedSuffix "His_next0" "0".
  iNamedSuffix "His_next1" "1".
  opose proof (hashchain.wish_Proof_det _ _ _ HnewDigs0 HnewDigs1) as ->.
  simplify_eq/=.
  opose proof (hashchain.det' His_chain0 His_chain1) as ->.
  by assert (nextEp = nextEp0) as -> by word.
Qed.

Lemma wp_getNextEp ptr_prev prev γ digs sl_sigPk sigPk sl_chainProof chainProof sl_sig sig :
  {{{
    is_pkg_init client ∗
    "#Hown_prev" ∷ epoch.own ptr_prev prev ∗
    "#His_prev" ∷ epoch.valid γ digs prev ∗
    "#Hsl_sigPk" ∷ sl_sigPk ↦*□ sigPk ∗
    "%Heq_sigPk" ∷ ⌜sigPk = γ.(cfg.sig_pk)⌝ ∗
    "#Hsl_chainProof" ∷ sl_chainProof ↦*□ chainProof ∗
    "#Hsl_sig" ∷ sl_sig ↦*□ sig
  }}}
  @! client.getNextEp #ptr_prev #sl_sigPk #sl_chainProof #sl_sig
  {{{
    ptr_next (err : bool), RET (#ptr_next, #err);
    "Hgenie" ∷
      match err with
      | true => ¬ ∃ newDigs next, wish_getNextEp γ digs chainProof sig newDigs next
      | false =>
        ∃ newDigs next,
        "#Hwish_getNextEp" ∷ wish_getNextEp γ digs chainProof sig newDigs next ∗
        "#Hown_next" ∷ epoch.own ptr_next next
      end
  }}}.
Proof.
  wp_start as "@".
  iNamedSuffix "Hown_prev" "_prev".
  iNamedSuffix "His_prev" "_prev".
  wp_auto.
  wp_apply hashchain.wp_Verify as "* @".
  { iFrame "#%". }
  iPersist "Hsl_newVal Hsl_newLink".
  wp_if_destruct.
  { iApply "HΦ". iIntros "@". simpl in *. iApply "Hgenie". naive_solver. }
  iNamed "Hgenie".
  wp_apply std.wp_SumNoOverflow.
  wp_if_destruct.
  2: { iApply "HΦ". iIntros "@". iNamed "His_next".
    opose proof (hashchain.wish_Proof_det _ _ _ Hwish_chain HnewDigs) as <-.
    autorewrite with len in *. word. }
  wp_apply ktcore.wp_VerifyLinkSig as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iIntros "@". iNamed "His_next". iApply "Hgenie".
    opose proof (hashchain.wish_Proof_det _ _ _ Hwish_chain HnewDigs) as <-.
    simplify_eq/=.
    opose proof (hashchain.det' His_chain His_chain0) as ->.
    iExactEq "His_sig". repeat f_equal.
    autorewrite with len in *. word. }
  iNamed "Hgenie".
  iPersist "prev".
  wp_bind (If _ _ _).
  wp_apply (wp_wand _ _ _
    (λ v,
    ∃ sl_nextDig nextDig,
    "->" ∷ ⌜v = execute_val⌝ ∗
    "nextDig" ∷ nextDig_ptr ↦ sl_nextDig ∗
    "%HnextDig" ∷ ⌜last (digs ++ newVals) = Some nextDig⌝ ∗
    "#Hsl_nextDig" ∷ sl_nextDig ↦*□ nextDig
    )%I
    with "[nextDig]"
  ) as "* @".
  { wp_if_destruct.
    - destruct newVals; simpl in *; try done.
      list_simplifier.
      by iFrame "∗#%".
    - destruct newVals using rev_ind; simpl in *; [word|]. clear IHnewVals.
      rewrite (assoc _) !last_snoc /=.
      by iFrame "∗#". }
  rewrite -wp_fupd.
  wp_apply wp_alloc as "* Hptr_next".
  iPersist "Hptr_next".

  iModIntro.
  iApply "HΦ".
  iExists _, (epoch.mk' _ _ _ _).
  iFrame "Hptr_next #%". simpl in *.
  repeat iExists _. repeat iSplit; [done|len|].
  iPureIntro. exact_eq His_chain. len.
Qed.

End proof.
End client.

Module server.
Import serde.server server.server client.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_CallHistory c good (uid prevEpoch prevVerLen : w64) :
  {{{
    is_pkg_init server ∗
    "#His_cli" ∷ is_rpc_cli c good ∗
    "#His_args" ∷ match server.Trust.get_full good with None => True | Some γ =>
      let agreeγ := γ.(server.cfg.agreeγ) in
      ∃ (dig : list w8),
      "#Hidx_ep" ∷ mono_list_idx_own agreeγ.(ktcore.Agree.digs) (uint.nat prevEpoch) dig ∗
      "%Hlt_ver" ∷ ⌜uint.nat prevVerLen ≤
        length $ ktcore.to_pks agreeγ.(ktcore.Agree.vrf_pk) uid dig⌝ end
  }}}
  @! server.CallHistory #c #uid #prevEpoch #prevVerLen
  {{{
    sl_chainProof sl_linkSig sl_hist ptr_bound err,
    RET (#sl_chainProof, #sl_linkSig, #sl_hist, #ptr_bound, #(ktcore.blame_to_u64 err));
    "%Hblame" ∷ ⌜ktcore.BlameSpec err {[ktcore.BlameServFull:=option_bool $ server.Trust.get_full good]}⌝ ∗
    "Herr" ∷ (if decide (err ≠ ∅) then True else
      ∃ chainProof linkSig hist bound,
      "#Hsl_chainProof" ∷ sl_chainProof ↦*□ chainProof ∗
      "#Hsl_linkSig" ∷ sl_linkSig ↦*□ linkSig ∗
      "#Hsl_hist" ∷ ktcore.MembSlice1D.own sl_hist hist (□) ∗
      "#Hptr_bound" ∷ ktcore.NonMemb.own ptr_bound bound (□) ∗

      "Hgood" ∷ match server.Trust.get_full good with None => True | Some γ =>
        ∀ γcli digs,
        let agreeγ := γ.(server.cfg.agreeγ) in
        epoch.align_sigpred agreeγ digs -∗
        serv.align_sigpred γcli agreeγ -∗
        serv.align_full γcli γ -∗
        ⌜length digs = S $ uint.nat prevEpoch⌝ -∗

        ∃ newDigs next,
        let pks := ktcore.to_pks agreeγ.(ktcore.Agree.vrf_pk) uid next.(epoch.dig) in
        "#Hwish_getNextEp" ∷ wish_getNextEp γcli digs chainProof linkSig
          newDigs next ∗
        "%Hnoof_vers" ∷ ⌜length pks = sint.nat (W64 (length pks))⌝ ∗

        "#Hwish_hist" ∷ ktcore.wish_ListMemb agreeγ.(ktcore.Agree.vrf_pk) uid
          (uint.nat prevVerLen) next.(epoch.dig) hist ∗
        "%Heq_hist" ∷ ⌜drop (uint.nat prevVerLen) pks =
          ktcore.CommitOpen.Val <$> (ktcore.Memb.PkOpen <$> hist)⌝ ∗
        "#Hwish_bound" ∷ ktcore.wish_NonMemb agreeγ.(ktcore.Agree.vrf_pk) uid
          (length pks) next.(epoch.dig) bound end)
  }}}.
Proof.
  iIntros (Φ) "H HΦ".
  wp_apply (wp_CallHistory with "H") as "* @".
  iApply "HΦ". iFrame "%".
  case_decide as Ht; try done. clear Ht. iNamed "Herr".
  iFrame "#".
  case_match eqn:Ht; try done. clear Ht. iNamed "Hgood".
  iIntros (?) "*@@@%".
  iExists _, (epoch.mk' (W64 $ length servDigs - 1) _ _ _). simpl.
  rewrite /wish_getNextEp /epoch.valid /=.
  rewrite Heq_sig_pk Heq_serv_digs_start Heq_serv_cut.
  iFrame "#%".
  iAssert (mono_list_lb_own t.(server.cfg.agreeγ).(ktcore.Agree.digs) servDigs)%I as "Hserv_digs'".
  { iDestruct (ktcore.get_link_sigpred with "His_sigPk Hwish_linkSig") as "@".
    opose proof (hashchain.inj His_lastLink _) as [-> _].
    { exact_eq Hinv. word. }
    done. }
  iAssert (⌜digs `prefix_of` servDigs⌝)%I as %(?&?).
  { iDestruct (mono_list_lb_valid with "Hserv_digs Hserv_digs'")
      as %[?|Hpref]; [done|].
    by apply prefix_length_eq in Hpref as ->; [|lia]. }
  replace (digs ++ _) with servDigs.
  2: { subst. f_equal. by rewrite drop_app_length'. }
  iFrame "%".
  repeat iExists _.
  iSplit; [done|].
  word.
Qed.

End proof.
End server.
