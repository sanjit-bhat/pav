From New.generatedproof.github_com.sanjit_bhat.pav Require Import client.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof Require Import bytes.
From New.proof.github_com.goose_lang Require Import std.
From New.proof.github_com.sanjit_bhat.pav Require Import
  advrpc auditor cryptoffi hashchain ktcore merkle server.

From New.proof.github_com.sanjit_bhat.pav.client_proof Require Import
  base rpc.

Module client.
Import rpc.client rpc.server.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : client.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_checkMemb ptr_pk pk (uid ver : w64) sl_dig dig ptr_memb memb :
  {{{
    is_pkg_init client ∗
    "#Hown_vrf_pk" ∷ cryptoffi.own_vrf_pk ptr_pk pk ∗
    "#Hsl_dig" ∷ sl_dig ↦*□ dig ∗
    "#Hown_memb" ∷ ktcore.Memb.own ptr_memb memb (□)
  }}}
  @! client.checkMemb #ptr_pk #uid #ver #sl_dig #ptr_memb
  {{{
    (err : bool), RET #err;
    "Hgenie" ∷
      match err with
      | true => ¬ ktcore.wish_Memb pk uid (uint.nat ver) dig memb
      | false =>
        "#Hwish_Memb" ∷ ktcore.wish_Memb pk uid (uint.nat ver) dig memb ∗
        "%Hsome_hidden" ∷ ⌜ktcore.in_hidden pk (merkle.inv_fn dig) uid
          (uint.nat ver) (Some memb.(ktcore.Memb.PkOpen).(ktcore.CommitOpen.Val))⌝
      end
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hown_memb". iNamed "Hown_PkOpen".
  wp_auto.
  wp_apply ktcore.wp_CheckMapLabel as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iIntros "@".
    rewrite w64_to_nat_id. by iApply "Hgenie". }
  iNamed "Hgenie".
  iPersist "Hsl_label".
  wp_apply ktcore.wp_GetMapVal as "* @".
  { iFrame "#". }
  iPersist "Hsl_mapVal".
  wp_apply merkle.wp_VerifyMemb as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iNamedSuffix 1 "0". iApply "Hgenie".
    opose proof (ktcore.map_label_det His_Label His_Label0) as ->.
    opose proof (ktcore.map_val_det His_MapVal His_MapVal0) as ->.
    iFrame "#". }
  iNamedSuffix "Hgenie" "_merk".
  wp_apply bytes.wp_Equal as "_".
  { iFrame "#". }
  wp_if_destruct.
  2: { iApply "HΦ". iNamedSuffix 1 "0".
    opose proof (ktcore.map_label_det His_Label His_Label0) as ->.
    opose proof (ktcore.map_val_det His_MapVal His_MapVal0) as ->.
    by iDestruct (merkle.wish_Memb_det with "His_proof_merk Hwish_memb0") as %->. }
  iApply "HΦ".
  iFrame "#%".
  rewrite w64_to_nat_id. iFrame "#".
  iPureIntro. rewrite /ktcore.in_hidden.
  apply ktcore.map_label_iff in His_Label.
  apply ktcore.map_val_iff in His_MapVal.
  naive_solver.
Qed.

Lemma wp_checkMembs ptr_pk pk (uid prefixLen : w64) sl_dig dig sl_hist sl0_hist hist :
  let num_vers := (uint.nat prefixLen + length hist)%nat in
  {{{
    is_pkg_init client ∗
    "#Hown_vrf_pk" ∷ cryptoffi.own_vrf_pk ptr_pk pk ∗
    "#Hsl_dig" ∷ sl_dig ↦*□ dig ∗
    "#Hsl_hist" ∷ sl_hist ↦*□ sl0_hist ∗
    "#Hown_hist" ∷ ([∗ list] ptr;memb ∈ sl0_hist;hist,
      ktcore.Memb.own ptr memb (□)) ∗
    "%Hnoof_ver" ∷ ⌜num_vers = uint.nat (W64 num_vers)⌝
  }}}
  @! client.checkMembs #ptr_pk #uid #prefixLen #sl_dig #sl_hist
  {{{
    (err : bool), RET #err;
    "Hgenie" ∷
      match err with
      | true => ¬ ktcore.wish_ListMemb pk uid (uint.nat prefixLen) dig hist
      | false =>
        "#Hwish_ListMemb" ∷ ktcore.wish_ListMemb pk uid (uint.nat prefixLen) dig hist ∗
        "%Hpks_hidden" ∷ ⌜ktcore.pks_in_hidden_from pk (merkle.inv_fn dig) uid
          (uint.nat prefixLen) (ktcore.CommitOpen.Val <$> (ktcore.Memb.PkOpen <$> hist))⌝
      end
  }}}.
Proof.
  simpl. wp_start as "@". wp_auto.
  iDestruct (own_slice_len with "Hsl_hist") as %[? _].
  iDestruct (big_sepL2_length with "Hown_hist") as %?.
  iAssert (
    ∃ (i : w64) (x0 : loc) (x1 : w64),
    "err" ∷ err_ptr ↦ false ∗
    "memb" ∷ memb_ptr ↦ x0 ∗
    "ver" ∷ ver_ptr ↦ x1 ∗
    "i" ∷ i_ptr ↦ i ∗

    "%Hlt_i" ∷ ⌜0%Z ≤ sint.Z i ≤ length hist⌝ ∗
    "#Hwish" ∷ ([∗ list] ver ↦ memb ∈ take (sint.nat i) hist,
      ktcore.wish_Memb pk uid (uint.nat prefixLen + ver) dig memb) ∗
    "%Hpks" ∷ ⌜ktcore.pks_in_hidden_from pk (merkle.inv_fn dig) uid (uint.nat prefixLen)
      (ktcore.CommitOpen.Val <$> (ktcore.Memb.PkOpen <$> (take (sint.nat i) hist)))⌝
  )%I with "[err memb ver i]" as "IH".
  { iFrame. iSplit; [word|naive_solver]. }
  wp_for "IH".
  wp_if_destruct.
  2: {
    iApply "HΦ".
    assert (sint.nat i = length hist) as -> by word.
    rewrite take_ge; [|word].
    rewrite take_ge in Hpks; [|word].
    iFrame "#%". }

  list_elem sl0_hist (sint.Z i) as ptr_memb.
  list_elem hist (sint.Z i) as memb.
  iDestruct (big_sepL2_lookup with "Hown_hist") as "#Hown_memb"; [done..|].
  case_decide as Ht; [|word]. clear Ht.
  wp_apply (wp_load_slice_index with "[$Hsl_hist]") as "_"; [word|done|].
  wp_apply wp_checkMemb as "* @".
  { iFrame "#". }
  wp_if_destruct; wp_for_post.
  { iApply "HΦ". iIntros "#H0". iApply "Hgenie".
    iDestruct (big_sepL_lookup with "H0") as "#H1"; [done|].
    iExactEq "H1". repeat f_equal. word. }
  iNamed "Hgenie".
  iFrame "∗#".
  iSplit; [word|].
  replace (sint.nat (word.add _ _)) with (S (sint.nat i)) by word.
  erewrite take_S_r; [|done].
  iSplit.
  - rewrite big_sepL_snoc.
    iFrame "#".
    iExactEq "Hwish_Memb".
    repeat f_equal. len.
  - iPureIntro. rewrite !fmap_app /=.
    apply ktcore.pks_in_hidden_from_snoc; try done.
    exact_eq Hsome_hidden. len.
Qed.

Lemma wp_checkNonMemb ptr_pk pk (uid ver : w64) sl_dig dig ptr_nonMemb nonMemb :
  {{{
    is_pkg_init client ∗
    "#Hown_vrf_pk" ∷ cryptoffi.own_vrf_pk ptr_pk pk ∗
    "#Hsl_dig" ∷ sl_dig ↦*□ dig ∗
    "#Hown_nonMemb" ∷ ktcore.NonMemb.own ptr_nonMemb nonMemb (□)
  }}}
  @! client.checkNonMemb #ptr_pk #uid #ver #sl_dig #ptr_nonMemb
  {{{
    (err : bool), RET #err;
    "Hgenie" ∷
      match err with
      | true => ¬ ktcore.wish_NonMemb pk uid (uint.nat ver) dig nonMemb
      | false =>
        "#Hwish_NonMemb" ∷ ktcore.wish_NonMemb pk uid (uint.nat ver) dig nonMemb ∗
        "%Hnone_hidden" ∷ ⌜ktcore.in_hidden pk (merkle.inv_fn dig) uid
          (uint.nat ver) None⌝
      end
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hown_nonMemb".
  wp_auto.
  wp_apply ktcore.wp_CheckMapLabel as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iIntros "@".
    rewrite w64_to_nat_id. by iApply "Hgenie". }
  iNamed "Hgenie".
  iPersist "Hsl_label".
  wp_apply merkle.wp_VerifyNonMemb as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iNamedSuffix 1 "0". iApply "Hgenie".
    opose proof (ktcore.map_label_det His_Label His_Label0) as ->.
    iFrame "#". }
  iNamedSuffix "Hgenie" "_merk".
  wp_apply bytes.wp_Equal as "_".
  { iFrame "#". }
  wp_if_destruct.
  2: { iApply "HΦ". iNamedSuffix 1 "0".
    opose proof (ktcore.map_label_det His_Label His_Label0) as ->.
    by iDestruct (merkle.wish_NonMemb_det with "His_proof_merk Hwish_nonMemb0") as %->. }
  iApply "HΦ".
  iFrame "#%".
  rewrite w64_to_nat_id. iFrame "#".
  iPureIntro. rewrite /ktcore.in_hidden.
  apply ktcore.map_label_iff in His_Label.
  naive_solver.
Qed.

Lemma wp_checkAuditLink sl_servPk servPk sl_adtrPk adtrPk (ep : w64) ptr_link link :
  {{{
    is_pkg_init client ∗
    "#Hsl_servPk" ∷ sl_servPk ↦*□ servPk ∗
    "#Hsl_adtrPk" ∷ sl_adtrPk ↦*□ adtrPk ∗
    "#Hown_link" ∷ auditor.SignedLink.own ptr_link link (□)
  }}}
  @! client.checkAuditLink #sl_servPk #sl_adtrPk #ep #ptr_link
  {{{
    (err : bool), RET #err;
    "Hgenie" ∷
      match err with
      | true => ¬ auditor.wish_SignedLink servPk adtrPk ep link
      | false =>
        "#Hwish_SignedLink" ∷ auditor.wish_SignedLink servPk adtrPk ep link
      end
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hown_link".
  wp_auto.
  wp_apply ktcore.wp_VerifyLinkSig as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iIntros "@". by iApply "Hgenie". }
  iNamedSuffix "Hgenie" "_adtr_link".
  wp_apply ktcore.wp_VerifyLinkSig as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iIntros "@". by iApply "Hgenie". }
  iNamedSuffix "Hgenie" "_serv_link".
  iApply "HΦ".
  iFrame "#".
Qed.

Lemma wp_checkAuditVrf sl_servPk servPk sl_adtrPk adtrPk ptr_vrf vrf :
  {{{
    is_pkg_init client ∗
    "#Hsl_servPk" ∷ sl_servPk ↦*□ servPk ∗
    "#Hsl_adtrPk" ∷ sl_adtrPk ↦*□ adtrPk ∗
    "#Hown_vrf" ∷ auditor.SignedVrf.own ptr_vrf vrf (□)
  }}}
  @! client.checkAuditVrf #sl_servPk #sl_adtrPk #ptr_vrf
  {{{
    (err : bool), RET #err;
    "Hgenie" ∷
      match err with
      | true => ¬ auditor.wish_SignedVrf servPk adtrPk vrf
      | false =>
        "#Hwish_SignedVrf" ∷ auditor.wish_SignedVrf servPk adtrPk vrf
      end
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hown_vrf".
  wp_auto.
  wp_apply ktcore.wp_VerifyVrfSig as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iIntros "@". by iApply "Hgenie". }
  iNamedSuffix "Hgenie" "_adtr_vrf".
  wp_apply ktcore.wp_VerifyVrfSig as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iIntros "@". by iApply "Hgenie". }
  iNamedSuffix "Hgenie" "_serv_vrf".
  iApply "HΦ".
  iFrame "#".
Qed.

(* Client.getHistory can run before New completes,
so it only requires parts of the Client inv.
for ease of use, it still takes in a full γ,
even tho some of the γ fields may not be properly set. *)
Lemma wp_Client_getHistory ptr_c uid (prevVerLen : w64) γ x0 x1 ptr_lastEp lastEp digs ptr_serv :
  let agreeγ := γ.(cfg.agreeγ) in
  {{{
    is_pkg_init client ∗
    "Hstr_Client" ∷ ptr_c ↦ (client.Client.mk x0 x1 ptr_lastEp ptr_serv) ∗
    "#Hown_lastEp" ∷ epoch.own ptr_lastEp lastEp ∗
    "#His_lastEp" ∷ epoch.valid γ digs lastEp ∗
    "#Halign_lastEp" ∷ match server.Trust.get_sigpred γ.(cfg.serv_good) with None => True | Some γserv =>
      epoch.align_sigpred γserv digs end ∗
    "#Hown_serv" ∷ serv.own γ ptr_serv ∗
    "#Halign_serv_sigpred" ∷ match server.Trust.get_sigpred γ.(cfg.serv_good) with None => True | Some γserv =>
      serv.align_sigpred γ γserv end ∗
    "#Halign_serv_full" ∷ match server.Trust.get_full γ.(cfg.serv_good) with None => True | Some γserv =>
      serv.align_full γ γserv end ∗

    "His_ver" ∷ match server.Trust.get_full γ.(cfg.serv_good) with None => True | Some _ =>
      ∃ i dig,
      "%Hlook_dig" ∷ ⌜digs !! i = Some dig⌝ ∗
      "%Hlt_ver" ∷ ⌜uint.nat prevVerLen ≤
        length $ ktcore.to_pks agreeγ.(ktcore.Agree.vrf_pk) uid dig⌝ end
  }}}
  ptr_c @! (go.PointerType client.Client) @! "getHistory" #uid #prevVerLen
  {{{
    ptr_nextEp sl_pks err,
    RET (#ptr_nextEp, #sl_pks, #(ktcore.blame_to_u64 err));
    "%Hblame" ∷ ⌜ktcore.BlameSpec err {[ktcore.BlameServFull:=option_bool $ server.Trust.get_full γ.(cfg.serv_good)]}⌝ ∗
    "Herr" ∷ (if decide (err ≠ ∅) then True else
      ∃ nextEp new_digs last_dig sl0_pks pks,
      "#Hown_nextEp" ∷ epoch.own ptr_nextEp nextEp ∗
      "#His_nextEp" ∷ epoch.valid γ (digs ++ new_digs) nextEp ∗
      "#Halign_nextEp" ∷ match server.Trust.get_sigpred γ.(cfg.serv_good) with None => True | Some γserv =>
        epoch.align_sigpred γserv (digs ++ new_digs) end ∗

      "#Hsl_pks" ∷ sl_pks ↦*□ sl0_pks ∗
      "#Hsl0_pks" ∷ ([∗ list] sl_pk;pk ∈ sl0_pks;pks,
        "#Hsl_pk" ∷ sl_pk ↦*□ pk) ∗
      "%Hlast_dig" ∷ ⌜last (digs ++ new_digs) = Some last_dig⌝ ∗
      "%Hmembs" ∷ ⌜ktcore.pks_in_hidden_from agreeγ.(ktcore.Agree.vrf_pk)
        (merkle.inv_fn last_dig) uid (uint.nat prevVerLen) pks⌝ ∗
      "%HnonMemb" ∷ ⌜ktcore.in_hidden agreeγ.(ktcore.Agree.vrf_pk)
        (merkle.inv_fn last_dig) uid (uint.nat prevVerLen + length pks) None⌝)
  }}}.
Proof. Admitted.

Lemma wp_New serv_good clis_good uid (servAddr : w64) sl_servPk servPk :
  {{{
    is_pkg_init client ∗
    "Halign_uid" ∷ match server.Trust.get_full serv_good with None => True | Some γserv =>
      ∃ uidγ,
      "%Hlook_uidγ" ∷ ⌜γserv.(server.cfg.uidγ) !! uid = Some uidγ⌝ ∗
      "HgoodCli" ∷
        match clis_good with
        | true => "Hputs" ∷ mono_list_auth_own uidγ 1 ([] : list (nat * list w8))
        | false => "#Huid_inv" ∷ ver.is_uid_inv uidγ
        end end ∗
    "#Hsl_servPk" ∷ sl_servPk ↦*□ servPk ∗
    "%Heq_servPk" ∷ ⌜match server.Trust.get_full serv_good with None => True | Some servγ =>
      servPk = servγ.(server.cfg.sig_pk) end⌝ ∗
    "#His_servPk" ∷ match server.Trust.get_sigpred serv_good with None => True | Some servγ =>
      cryptoffi.is_sig_pk servPk (sigpred.P servγ) end
  }}}
  @! client.New #uid #servAddr #sl_servPk
  {{{
    ptr_c (ep : w64) err, RET (#ptr_c, #ep, #(ktcore.blame_to_u64 err));
    "%Hblame" ∷ ⌜ktcore.BlameSpec err
      {[ktcore.BlameServFull:=option_bool $ server.Trust.get_full serv_good;
        ktcore.BlameClients:=clis_good]}⌝ ∗
    "Herr" ∷ (if decide (err ≠ ∅) then True else
      ∃ γ,
      let agreeγ := γ.(cfg.agreeγ) in
      "%Heq_uid" ∷ ⌜γ.(cfg.uid) = uid⌝ ∗
      "%Heq_sig_pk" ∷ ⌜γ.(cfg.sig_pk) = servPk⌝ ∗
      "%Heq_serv_good" ∷ ⌜γ.(cfg.serv_good) = serv_good⌝ ∗
      "%Heq_clis_good" ∷ ⌜γ.(cfg.clis_good) = clis_good⌝ ∗
      "%Heq_agree_ep" ∷ ⌜(agreeγ.(ktcore.Agree.digs_start) +
        agreeγ.(ktcore.Agree.func_start))%nat = uint.nat ep⌝ ∗
      "Hclient" ∷ Client.own γ ptr_c (state.mk (uint.nat ep) [None] None))
  }}}.
Proof.
  wp_start as "@". wp_auto.
  wp_apply server.wp_Dial as "* @".
  wp_apply server.wp_CallStart as "* @".
  { iFrame "#". }
  case_bool_decide as Heq_err; wp_auto;
    rewrite ktcore.rw_Blame0 in Heq_err; subst.
  2: {
    iApply "HΦ".
    iSplit; [|by case_decide].
    iPureIntro.
    eapply ktcore.blame_add_interp; [done|].
    apply map_singleton_subseteq_l.
    by simpl_map. }
  case_decide as Ht; try done. clear Ht.
  iNamed "Herr".
  wp_apply auditor.wp_CheckStartChain as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iSplit. 2: { by case_decide. }
    iApply ktcore.blame_one.
    iIntros (?).
    destruct (server.Trust.get_full _); try done.
    simplify_eq/=.
    iApply "Hgenie".
    iNamed "Hgood".
    iFrame "#". }
  iNamed "Hgenie".
  iDestruct (server.wish_CheckStartChain_extract with "Hwish_CheckStartChain") as "@".
  wp_apply auditor.wp_CheckStartVrf as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iSplit. 2: { by case_decide. }
    iApply ktcore.blame_one.
    iIntros (?).
    destruct (server.Trust.get_full _); try done.
    simplify_eq/=.
    iApply "Hgenie".
    iNamed "Hgood".
    iFrame "#". }
  iNamed "Hgenie".

  iNamed "Hptr_chain". iNamed "Hptr_vrf".
  wp_apply wp_alloc as "%ptr_nextVer Hstr_ver".
  wp_apply wp_alloc as "%ptr_lastEp0 Hstr_epoch".
  wp_apply wp_alloc as "%ptr_serv Hstr_serv".
  wp_apply wp_alloc as "%ptr_c Hstr_Client".
  iPersist "Hstr_epoch Hstr_serv".
  iMod (mono_list_own_alloc digs) as (digsγ) "[Hauth_digs #Hlb_digs]".
  (* fake func_start out until later, so we can call getHistory. *)
  set (ktcore.Agree.mk vrf.(server.StartVrf.VrfPk) digsγ
    (S (uint.nat ep) - length digs) cut (length digs)) as fakeAgreeγ.
  set (cfg.mk uid servPk fakeAgreeγ serv_good clis_good) as fakeγ.
  iAssert (serv.own fakeγ ptr_serv)%I as "#Hown_serv".
  { iNamed "Hwish_CheckStartVrf". iFrame "#". }
  iAssert (match server.Trust.get_sigpred serv_good with None => True | Some γserv =>
    serv.align_sigpred fakeγ γserv end)%I as "#Halign_serv_sigpred".
  { destruct (server.Trust.get_sigpred _); try done.
    rewrite /serv.align_sigpred /=.
    iFrame "#".
    iNamed "Hwish_CheckStartVrf".
    iDestruct (ktcore.get_vrf_sigpred with "His_servPk His_vrf_sig") as "H".
    rewrite /vrfP. iNamed "H".
    iFrame "%".
    iNamed "Hwish_CheckStartChain".
    iDestruct (ktcore.get_link_sigpred with "His_servPk His_link_sig") as "H".
    iNamedSuffix "H" "0".
    opose proof (hashchain.inj His_chain_start Hinv0) as [<- ->].
    iPureIntro. repeat split; word. }
  iAssert (match server.Trust.get_full serv_good with None => True | Some γserv =>
    serv.align_full fakeγ γserv end)%I as "#Halign_serv_full".
  { destruct (server.Trust.get_full _) eqn:?; try done.
    erewrite server.Trust.full_to_sigpred; [|done].
    iFrame "%".
    iNamed "Halign_serv_sigpred". iNamed "Hgood".
    iPureIntro. simplify_eq/=. split; try done. word. }
  iClear "Hgood".

  wp_apply (wp_Client_getHistory with "[$Hstr_Client]") as "* @".
  { iFrame "#".
    instantiate (1:=digs).
    instantiate (1:=epoch.mk' _ _ _ _).
    iFrame "#".
    iSplitL; [|iSplitL].
    - rewrite /epoch.valid /=.
      iNamed "Hwish_CheckStartChain".
      eapply hashchain.fuel_bound' in His_chain_start as ?.
      ereplace (?[x] - _ + _)%nat with ?x by word.
      by iFrame "#%".
    - rewrite /epoch.align_sigpred.
      destruct (server.Trust.get_sigpred _); try done.
      iNamed "Hwish_CheckStartChain".
      iDestruct (ktcore.get_link_sigpred with "His_servPk His_link_sig") as "H".
      iNamedSuffix "H" "0".
      opose proof (hashchain.inj His_chain_start Hinv0) as [<- _].
      iFrame "#%".
    - destruct (server.Trust.get_full _); try done.
      rewrite last_lookup in Hlast_digs.
      iFrame "%".
      word. }
  case_bool_decide as Heq_err; wp_auto;
    rewrite ktcore.rw_Blame0 in Heq_err; subst.
  2: {
    iApply "HΦ".
    iSplit; [|by case_decide].
    iPureIntro.
    eapply ktcore.blame_add_interp; [done|].
    apply map_singleton_subseteq_l.
    by simpl_map. }
  case_decide as Ht; try done. clear Ht.
  iNamed "Herr".
  iNamedSuffix "Hown_nextEp" "1".
  wp_auto.
  wp_if_destruct.
  2: {
    rewrite ktcore.rw_BlameServClients.
    iApply "HΦ".
    iSplitL. 2: { case_decide; try done. set_solver. }
    iApply ktcore.blame_two.
    iSplit; [done|].
    iIntros ([? ->]).
    case_match; try done.
    simplify_eq/=.
    (*
    iNamed "Halign_pend_pend".
    iNamed "HgoodCli".
    iDestruct ("Hgood" with "Halign_last [//]") as "H".
    iNamedSuffix "H" "0".

    apply Forall2_length in Heq_hist0.
    autorewrite with len in *.
    remember (lastKeys !!! _) as pks.
    list_elem pks (S $ uint.nat ver) as pk.
    case_decide.
    { apply lookup_lt_Some in Hpk_lookup. word. }
    iNamed "Hpend_gs0".
    simplify_eq/=.
    iDestruct (big_sepL_lookup with "Hidx_pks") as "[% #Hidx_bad]"; [done|].
    iDestruct (mono_list_auth_idx_lookup with "Hputs Hidx_bad") as %Hlook_bad.
    iPureIntro.
    apply list_elem_of_lookup_2 in Hlook_bad.
    eapply Hbound in Hlook_bad.
    word. } *)
Admitted.
(* TODO: same issue as before: for contra, need put records from inv.
for producer of put records:
- need to be under Server guard to see Server inv.
- under guard, need fupd to open inv.
- it may be possible to "bring fupd from higher up into lower level".
for consumer of put records:
- if there's a fupd under Server guard, that causes issues.
need fupd above BlameSpec, which no longer makes it pers.
this blocks us from sending excl rsrc to both BameSpec and err=true proof branches. *)

Lemma wp_Client_Put γ ptr_c σ sl_pk pk :
  {{{
    is_pkg_init client ∗
    "Hclient" ∷ Client.own γ ptr_c σ ∗
    "#Hsl_pk" ∷ sl_pk ↦*□ pk ∗
    "%Heq_pend" ∷
      ⌜match σ.(state.pend_pk) with
      | None => True
      | Some pk' => pk = pk'
      end⌝
  }}}
  ptr_c @! (go.PointerType client.Client) @! "Put" #sl_pk
  {{{
    RET #();
    let σ' := set state.pend_pk (λ _, Some pk) σ in
    "Hclient" ∷ Client.own γ ptr_c σ'
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hclient". iNamed "Hown_nextVer". iNamed "Hown_serv".
  destruct γ, σ. simpl in *.
  wp_auto. simpl.
  iPersist "c pk".
  wp_bind (If _ _ _).
  wp_apply (wp_wand _ _ _
    (λ v,
    ∃ sl_pendPk',
    "->" ∷ ⌜v = execute_val⌝ ∗
    "Hstr_client" ∷ ptr_c ↦ {|
                          client.Client.uid' := uid;
                          client.Client.nextVer' := ptr_nextVer;
                          client.Client.lastEp' := ptr_lastEp;
                          client.Client.serv' := ptr_serv
                        |} ∗
    "Hstr_ver" ∷ ptr_nextVer ↦ {|
                             client.ver.ver' := w_ver;
                             client.ver.hasPendPk' := true;
                             client.ver.pendPk' := sl_pendPk'
                           |} ∗
    "#Hsl_pendPk'" ∷ sl_pendPk' ↦*□ pk
    )%I
    with "[Hstr_client Hstr_ver]"
  ) as "* @".
  { wp_if_destruct.
    - destruct pend_pk; iNamed "HpendPk"; try done.
      simplify_eq/=.
      wp_apply bytes.wp_Equal as "_".
      { iFrame "#". }
      wp_apply std.wp_Assert.
      { by case_bool_decide. }
      by iFrame "∗#".
    - by iFrame "∗#". }

  destruct serv_good; iNamed "Halign_nextVer".
  2: {
    wp_apply server.wp_CallPut.
    { iFrame "#". }
    iApply "HΦ".
    by iFrame "∗ Hstr_serv #%". }
  simpl in *. destruct clis_good; iNamed "HgoodCli".
  - iMod (mono_list_auth_own_update_app [(nextVer.(ver.ver), pk)]
      with "Hputs") as "[Hputs #Hlb]".
    iDestruct (mono_list_idx_own_get (length puts) with "Hlb") as "#Hidx".
    { by rewrite lookup_snoc. }
    wp_apply (server.wp_CallPut _ (Some _)).
    { rewrite Heq_ver. iFrame "#%". }
    iApply "HΦ".
    iFrame "∗ Hstr_serv #%". simpl in *.
    iPureIntro. repeat split; try done.
    + intros. decompose_list_elem_of; [naive_solver|].
      by simplify_eq/=.
    + intros. decompose_list_elem_of; [naive_solver|].
      by simplify_eq/=.
  - iApply fupd_wp.
    iInv "Huid_inv" as ">@" "Hclose".
    iMod (mono_list_auth_own_update_app [(nextVer.(ver.ver), pk)]
      with "Hputs") as "[Hputs #Hlb]".
    iMod ("Hclose" with "[Hputs]") as "_"; [iFrame|].
    iModIntro.
    iDestruct (mono_list_idx_own_get (length puts) with "Hlb") as "#Hidx".
    { by rewrite lookup_snoc. }
    wp_apply (server.wp_CallPut _ (Some _)).
    { rewrite Heq_ver. iFrame "#%". }
    iApply "HΦ".
    by iFrame "∗ Hstr_serv #%".
Qed.

Lemma wp_Client_Get γ ptr_c σ (uid : w64) :
  {{{
    is_pkg_init client ∗
    "Hclient" ∷ Client.own γ ptr_c σ
  }}}
  ptr_c @! (go.PointerType client.Client) @! "Get" #uid
  {{{
    (ep : w64) is_reg (sl_pk : slice.t) err,
    RET (#ep, #is_reg, #sl_pk, #(ktcore.blame_to_u64 err));
    "%Hblame" ∷ ⌜ktcore.BlameSpec err
      {[ktcore.BlameServFull:=option_bool γ.(cfg.serv_good)]}⌝ ∗
    "Herr" ∷
      (if decide (err ≠ ∅)
      then "Hclient" ∷ Client.own γ ptr_c σ
      else
        ∃ new_digs opt_pk,
        let σ' := set state.digs (.++ new_digs) σ in
        "Hclient" ∷ Client.own γ ptr_c σ' ∗
        let agreeγ := γ.(cfg.agreeγ) in
        "%Heq_ep" ∷ ⌜uint.Z ep = agreeγ.(ktcore.Agree.digs_start) + length σ'.(state.digs) - 1⌝ ∗
        "#Hopt_pk" ∷
          match opt_pk with
          | None => "->" ∷ ⌜is_reg = false⌝
          | Some pk =>
            "->" ∷ ⌜is_reg = true⌝ ∗
            "#Hsl_pk" ∷ sl_pk ↦*□ pk
          end ∗
        "#Hptr_kt" ∷ agreeγ ↪KT[uint.nat ep, uid] opt_pk)
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hclient". iNamed "Hown_serv". iNamed "Hown_last".
  wp_auto.
  wp_apply wp_CallHistory as "* @".
  { iFrame "#".
    case_match; try done.
    iNamed "His_last". iNamed "Halign_last".
    list_elem σ.(state.digs) (uint.nat last0.(epoch.epoch)) as dig.
    iDestruct (mono_list_idx_own_get with "His_hist") as "$"; [done|].
    word. }
  case_bool_decide as Heq_err; wp_auto;
    rewrite ktcore.rw_Blame0 in Heq_err; subst.
  2: {
    iApply "HΦ".
    iSplit; [done|].
    case_decide; try done.
    iFrame "∗#%". }
  case_decide; try done.
  iNamed "Herr".
  wp_apply wp_getNextEp as "* @".
  { by iFrame "#". }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iSplit. 2: { case_decide; try done. iFrame "∗ Hstr_epoch Hstr_serv #". }
    iApply ktcore.blame_one.
    iIntros (?).
    case_match; try done.
    iApply "Hgenie".
    iDestruct ("Hgood" with "[$][$][]") as "@".
    { iNamed "His_last". iNamed "Halign_last". word. }
    iFrame "#". }
  iNamed "Hgenie".
  iNamedSuffix "Hown_next" "_next".
  wp_auto.
  iDestruct "Hsl_hist" as (?) "[Hsl0_hist Hsl_hist]".
  iDestruct (own_slice_len with "Hsl0_hist") as %[? ?].
  iDestruct (big_sepL2_length with "Hsl_hist") as %?.
  wp_apply wp_checkMembs as "* @".
  { iFrame "#". word. }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iSplit. 2: { case_decide; try done. iFrame "∗ Hstr_epoch Hstr_serv #". }
    iApply ktcore.blame_one.
    iIntros (?).
    case_match; try done.
    iApply "Hgenie".
    iDestruct ("Hgood" with "[$][$][]") as "H".
    { iNamed "His_last". iNamed "Halign_last". word. }
    iNamedSuffix "H" "0".
    iDestruct (wish_getNextEp_det with "Hwish_getNextEp Hwish_getNextEp0") as %[-> ->].
    iFrame "#". }
  iNamed "Hgenie".
  wp_apply wp_checkNonMemb as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iSplit. 2: { case_decide; try done. iFrame "∗ Hstr_epoch Hstr_serv #". }
    iApply ktcore.blame_one.
    iIntros (?).
    case_match; try done.
    iApply "Hgenie".
    iDestruct ("Hgood" with "[$][$][]") as "H".
    { iNamed "His_last". iNamed "Halign_last". word. }
    iNamedSuffix "H" "0".
    iDestruct (wish_getNextEp_det with "Hwish_getNextEp Hwish_getNextEp0") as %[-> ->].
    apply (f_equal length) in Heq_hist0.
    autorewrite with len in *.
    iExactEq "Hwish_bound0". repeat f_equal. word. }
  iNamed "Hgenie".
  iPersist "hist boundVer".
  rewrite -wp_fupd.
  wp_bind (If _ _ _).
  wp_apply (wp_wand _ _ _
    (λ v,
    ∃ isReg sl_pk,
    "->" ∷ ⌜v = execute_val⌝ ∗
    "isReg" ∷ isReg_ptr ↦ isReg ∗
    "pk" ∷ pk_ptr ↦ sl_pk ∗
    "#Hlast_hist" ∷
      match last hist with
      | None => "->" ∷ ⌜isReg = false⌝
      | Some x =>
        "->" ∷ ⌜isReg = true⌝ ∗
        "#Hsl_pk" ∷ sl_pk ↦*□ x.(ktcore.Memb.PkOpen).(ktcore.CommitOpen.Val)
      end
    )%I
    with "[isReg pk]"
  ) as "* @".
  { wp_if_destruct.
    - destruct (last hist) eqn:Hlast.
      { apply last_Some in Hlast as [? Hlast].
        apply (f_equal length) in Hlast.
        autorewrite with len in *. word. }
      by iFrame.
    - destruct (last hist) as [memb|] eqn:Hlast.
      2: { apply last_None in Hlast.
        apply (f_equal length) in Hlast.
        simpl in *. word. }
      remember (word.sub sl_hist.(slice.len) (W64 1)) as idx.
      rewrite last_lookup in Hlast.
      replace (pred _) with (sint.nat idx) in Hlast by word.
      list_elem ptr0 (sint.nat idx) as ptr_memb.
      iDestruct (big_sepL2_lookup with "Hsl_hist") as "H"; [done..|].
      iNamedSuffix "H" "0".
      iNamedSuffix "Hown_PkOpen0" "1".

      case_decide as Ht; [|word]. clear Ht.
      wp_apply wp_load_slice_index; [word|..].
      { by iFrame "#". }
      iIntros "_". wp_auto.
      by iFrame "∗#". }

  iMod (mono_list_auth_own_update_app newDigs with "Hown_digs")
    as "[Hown_digs #Hlb_digs]".
  iModIntro. iApply "HΦ".
  iSplit. { iPureIntro. apply ktcore.blame_none. }
  case_decide; try done.
  iPoseProof "Hwish_getNextEp" as "@".
  simplify_eq/=.
  iFrame "∗". simpl.
  iExists (ktcore.CommitOpen.Val <$> (ktcore.Memb.PkOpen <$> last hist)).
  iSplitL.
  { iExists (epoch.mk' _ _ _ _).
    iFrame "Hstr_epoch_next Hstr_serv #".
    case_match; try done.
    iDestruct ("Hgood" with "[$][$][]") as "H".
    { iNamed "His_last". iNamed "Halign_last". word. }
    iNamedSuffix "H" "0".
    iDestruct (wish_getNextEp_det with "Hwish_getNextEp Hwish_getNextEp0") as %[-> ->].
    iFrame "#".
    iNamed "Halign_pend_hist". iPureIntro.
    simpl. repeat eexists; [|done].
    by apply lookup_app_l_Some. }

  iSplit.
  { iNamedSuffix "His_next" "_next". simpl in *.
    autorewrite with len in *. word. }
  iSplit.
  { destruct (last hist); iNamed "Hlast_hist"; simpl; [|done].
    by iFrame "#". }
  iFrame "#".
  iNamedSuffix "His_next" "_next". simpl in *.
  rewrite last_lookup in Hlast_dig_next.
  iExists _.
  iSplit. { iPureIntro. exact_eq Hlast_dig_next. f_equal. word. }
  iPureIntro.
  apply ktcore.pks_in_hidden_from_0 in Hpks_hidden.
  erewrite ktcore.inv_fn_inp_pks_exact; cycle 1; [done|done|..].
  { exact_eq Hnone_hidden. len. }
  by rewrite !fmap_last.
Qed.

Lemma wp_Client_SelfMon γ ptr_c σ :
  {{{
    is_pkg_init client ∗
    "Hclient" ∷ Client.own γ ptr_c σ
  }}}
  ptr_c @! (go.PointerType client.Client) @! "SelfMon" #()
  {{{
    (ep : w64) (isChanged : bool) err,
    RET (#ep, #isChanged, #(ktcore.blame_to_u64 err));
    (* TODO: in alicebob proof, BlameSpec won't work with mult Auditors.
    there's only one place to plug in an Auditor trust param. *)
    "%Hblame" ∷ ⌜ktcore.BlameSpec err
      ({[
        ktcore.BlameServFull:=option_bool γ.(cfg.serv_good);
        ktcore.BlameClients:=γ.(cfg.clis_good)
      ]})⌝ ∗
    "Herr" ∷
      (if decide (err ≠ ∅)
      then "Hclient" ∷ Client.own γ ptr_c σ
      else
        ∃ new_digs prev_key,
        let agreeγ := γ.(cfg.agreeγ) in
        let σ0 := set state.digs (.++ new_digs) σ in
        let new_keys_len := (length σ0.(state.digs) - agreeγ.(ktcore.Agree.func_start) -
          length σ.(state.keys))%nat in
        "%Heq_ep" ∷ ⌜uint.Z ep = agreeγ.(ktcore.Agree.digs_start) + length σ0.(state.digs) - 1⌝ ∗
        "%Hprev_key" ∷ ⌜last σ.(state.keys) = Some prev_key⌝ ∗
        "Hchanged" ∷
          match isChanged with
          | false =>
            let σ1 := set state.keys (.++ replicate new_keys_len prev_key) σ0 in
            "Hclient" ∷ Client.own γ ptr_c σ1 ∗
            "#His_staged" ∷ ktcore.is_staged_keys γ.(cfg.agreeγ) γ.(cfg.uid) σ1.(state.keys)
          | true =>
            ∃ (num_prev_keys : nat),
            let num_next_keys := (new_keys_len - num_prev_keys)%nat in
            let σ1 :=
              set state.keys
                (.++ replicate num_prev_keys prev_key ++
                  replicate num_next_keys σ.(state.pend_pk))
              (set state.pend_pk (λ _, None) σ0) in
            "Hclient" ∷ Client.own γ ptr_c σ1 ∗
            "#His_staged" ∷ ktcore.is_staged_keys γ.(cfg.agreeγ) γ.(cfg.uid) σ1.(state.keys) ∗
            "%Hpend" ∷ ⌜is_Some σ.(state.pend_pk)⌝ ∗
            "%Hsome_next_keys" ∷ ⌜num_next_keys > 0⌝
          end)
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hclient".
  destruct c.
  iNamed "Hown_pend".
  destruct pend.
  iNamed "Hown_last".
  destruct last0.
  iNamed "Hown_serv".
  destruct serv.
  destruct info.
  simplify_eq/=.
  wp_auto.
  wp_apply wp_CallHistory as "* @".
  { iFrame "#".
    iModIntro.
    case_match; try done.
    iNamed "Halign_last". simplify_eq/=.
    list_elem hist (uint.nat epoch) as e.
    iDestruct (mono_list_idx_own_get with "His_hist") as "Hidx_hist0"; [done|].
    iNamed "Halign_pend_hist". simplify_eq/=.
    iMod (server.hist_pks_prefix uid with "His_rpc Hidx_hist Hidx_hist0")
      as %?%prefix_length; [word|].
    iClear "Hidx_hist His_hist".
    iFrame "#". word. }
  case_bool_decide as Heq_err; wp_auto;
    rewrite ktcore.rw_Blame0 in Heq_err; subst.
  2: {
    iApply "HΦ".
    iSplit. {
      iPureIntro.
      eapply ktcore.blame_add_interp; [done|].
      apply map_singleton_subseteq_l.
      by simpl_map. }
    case_decide; try done.
    iFrame "∗#%". }
  case_decide; try done.
  iNamed "Herr".
  (* TODO: change spec to have objs come as first args. *)
  wp_apply (wp_getNextEp _ (epoch.mk' _ _ _ _ _ _) (servInfo.mk _ vrf_pk)) as "* @".
  { by iFrame "Hstr_epoch #". }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iSplit. 2: { case_decide; try done. by iFrame "∗#%". }
    iApply ktcore.blame_one.
    iIntros (?).
    case_match; try done.
    simplify_eq/=.
    iApply "Hgenie".
    iDestruct ("Hgood" with "Halign_last [//]") as "@".
    iFrame "#". }
  iNamed "Hgenie".
  iNamedSuffix "Hown_next" "_next".
  iDestruct "Hsl_hist" as (?) "[Hsl0_hist Hsl_hist]".
  iDestruct (own_slice_len with "Hsl0_hist") as %[? ?].
  iDestruct (big_sepL2_length with "Hsl_hist") as %?.
  wp_auto.
  wp_apply std.wp_SumNoOverflow.
  wp_if_destruct.
  2: { rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iSplit. 2: { case_decide; try done. by iFrame "∗#%". }
    iApply ktcore.blame_one.
    iIntros (?).
    case_match; try done.
    simplify_eq/=.
    iDestruct ("Hgood" with "Halign_last [//]") as "H".
    iNamedSuffix "H" "0".
    iDestruct (wish_getNextEp_det with "Hwish_getNextEp Hwish_getNextEp0") as %[-> ->].
    apply Forall2_length in Heq_hist0.
    autorewrite with len in *.
    word. }
  wp_apply wp_checkMembs as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iSplit. 2: { case_decide; try done. by iFrame "∗#%". }
    iApply ktcore.blame_one.
    iIntros (?).
    case_match; try done.
    simplify_eq/=.
    iApply "Hgenie".
    iDestruct ("Hgood" with "Halign_last [//]") as "H".
    iNamedSuffix "H" "0".
    iDestruct (wish_getNextEp_det with "Hwish_getNextEp Hwish_getNextEp0") as %[-> ->].
    iFrame "#". }
  iNamed "Hgenie".
  wp_apply wp_checkNonMemb as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iSplit. 2: { case_decide; try done. by iFrame "∗#%". }
    iApply ktcore.blame_one.
    iIntros (?).
    case_match; try done.
    simplify_eq/=.
    iApply "Hgenie".
    iDestruct ("Hgood" with "Halign_last [//]") as "H".
    iNamedSuffix "H" "0".
    iDestruct (wish_getNextEp_det with "Hwish_getNextEp Hwish_getNextEp0") as %[-> ->].
    apply Forall2_length in Heq_hist0.
    autorewrite with len in *.
    iExactEq "Hwish_bound0". repeat f_equal. word. }
  iNamed "Hgenie".

  wp_if_destruct.
  2: {
    destruct pendingPk; iNamed "HpendingPk"; try done.
    wp_if_destruct.
    2: { rewrite ktcore.rw_BlameServClients.
      iApply "HΦ".
      iSplit. 2: { case_decide; [|set_solver]. by iFrame "∗#%". }
      iApply ktcore.blame_two.
      iSplit; [done|].
      iIntros ([? ->]).
      case_match; try done.
      simplify_eq/=.
      iNamed "Halign_pend_pend".
      iNamed "HgoodCli".
      iDestruct ("Hgood" with "Halign_last [//]") as "H".
      iNamedSuffix "H" "0".

      apply Forall2_length in Heq_hist0.
      autorewrite with len in *.
      remember (lastKeys !!! _) as pks.
      list_elem pks (uint.nat ver) as pk.
      case_decide.
      { apply lookup_lt_Some in Hpk_lookup. word. }
      iNamed "Hpend_gs0".
      simplify_eq/=.
      iDestruct (big_sepL_lookup with "Hidx_pks") as "[% #Hidx_bad]"; [done|].
      iDestruct (mono_list_auth_idx_lookup with "Hputs Hidx_bad") as %Hlook_bad.
      iPureIntro.
      apply list_elem_of_lookup_2 in Hlook_bad.
      ereplace (W64 (uint.nat ?[w])) with (?w) in Hlook_bad by word.
      by apply Heq_pend in Hlook_bad. }

    iApply "HΦ".
    iSplit. { iPureIntro. apply ktcore.blame_none. }
    case_decide; try done.
    iPoseProof "Hwish_getNextEp" as "@".
    simplify_eq/=.
    iFrame "∗ Hstr_epoch_next #%". simpl in *.
    iSplit; [|done].
    iSplit; [done|].
    case_match; try done.
    simplify_eq/=.
    iDestruct ("Hgood" with "Halign_last [//]") as "H".
    iNamedSuffix "H" "0".
    iDestruct (wish_getNextEp_det with "Hwish_getNextEp Hwish_getNextEp0") as %[-> ->].
    iNamed "Halign_pend_hist".
    Opaque mono_list_idx_own.
    iFrame "#%". word. }
  destruct pendingPk; iNamed "HpendingPk"; try done.

  wp_if_destruct.
  { rewrite ktcore.rw_BlameServClients.
    iApply "HΦ".
    iSplit. 2: { case_decide; [|set_solver]. by iFrame "∗#%". }
    iApply ktcore.blame_two.
    iSplit; [done|].
    iIntros ([? ->]).
    case_match; try done.
    simplify_eq/=.
    iNamed "Halign_pend_pend".
    iNamed "HgoodCli".
    iDestruct ("Hgood" with "Halign_last [//]") as "H".
    iNamedSuffix "H" "0".

    apply Forall2_length in Heq_hist0.
    autorewrite with len in *.
    remember (lastKeys !!! _) as pks.
    list_elem pks (S $ uint.nat ver) as pk.
    case_decide.
    { apply lookup_lt_Some in Hpk_lookup. word. }
    iNamed "Hpend_gs0".
    simplify_eq/=.
    iDestruct (big_sepL_lookup with "Hidx_pks") as "[% #Hidx_bad]"; [done|].
    iDestruct (mono_list_auth_idx_lookup with "Hputs Hidx_bad") as %Hlook_bad.
    iPureIntro.
    apply list_elem_of_lookup_2 in Hlook_bad.
    eapply Hbound in Hlook_bad.
    word. }

  wp_if_destruct.
  { iApply "HΦ".
    iSplit. { iPureIntro. apply ktcore.blame_none. }
    case_decide; try done.
    iPoseProof "Hwish_getNextEp" as "@".
    simplify_eq/=.
    iFrame "∗ Hstr_epoch_next #%". simpl in *.
    iSplit; [|naive_solver].
    iSplit; [done|].
    case_match; try done.
    simplify_eq/=.
    iDestruct ("Hgood" with "Halign_last [//]") as "H".
    iNamedSuffix "H" "0".
    iDestruct (wish_getNextEp_det with "Hwish_getNextEp Hwish_getNextEp0") as %[-> ->].
    iNamed "Halign_pend_hist".
    Opaque mono_list_idx_own.
    iFrame "#%". word. }

  list_elem ptr0 0 as ptr_memb.
  list_elem hist 0 as memb.
  iDestruct (big_sepL2_lookup with "Hsl_hist") as "H"; [done..|].
  iNamedSuffix "H" "0".
  iNamedSuffix "Hown_PkOpen0" "1".
  wp_pure; [word|].
  wp_apply wp_load_slice_elem as "_"; [word|..].
  { by iFrame "#". }
  wp_apply bytes.wp_Equal as "_".
  { iFrame "#". }
  wp_if_destruct.
  2: { rewrite ktcore.rw_BlameServClients.
    iApply "HΦ".
    iSplit. 2: { case_decide; [|set_solver]. by iFrame "∗#%". }
    iApply ktcore.blame_two.
    iSplit; [done|].
    iIntros ([? ->]).
    case_match; try done.
    simplify_eq/=.
    iNamed "Halign_pend_pend".
    iNamed "HgoodCli".
    iDestruct ("Hgood" with "Halign_last [//]") as "H".
    iNamedSuffix "H" "0".

    opose proof (Forall2_lookup_r _ _ _ _ _ Heq_hist0 ltac:(done)) as (?&Hlook_pks&?).
    simplify_eq/=.
    rewrite lookup_drop in Hlook_pks.
    apply Forall2_length in Heq_hist0 as ?.
    autorewrite with len in *.
    case_decide; [word|].
    iNamed "Hpend_gs0".
    simplify_eq/=.
    iDestruct (big_sepL_lookup with "Hidx_pks") as "[% #Hidx_bad]"; [done|].
    iDestruct (mono_list_auth_idx_lookup with "Hputs Hidx_bad") as %Hlook_bad.
    iPureIntro.
    apply list_elem_of_lookup_2 in Hlook_bad.
    ereplace (W64 (uint.nat ?[w] + Z.to_nat 0)%nat) with (?w) in Hlook_bad by word.
    apply Heq_pend in Hlook_bad.
    simplify_eq/=. }

  iApply "HΦ".
  iSplit. { iPureIntro. apply ktcore.blame_none. }
  case_decide; try done.
  iPoseProof "Hwish_getNextEp" as "@".
  simplify_eq/=.
  (* TODO[word]: w64 getting unfolded to Naive.wrap. *)
  iExists (word.add ver sl_hist.(slice.len_f)).
  iFrame "Hstr_client Hstr_nextVer Hstr_epoch_next".
  simpl in *. iFrame "#%".
  iExists _.
  iSplit. 2: { iPureIntro. right. repeat split. word. }
  iSplit; [done|].
  case_match; try done.
  simplify_eq/=.
  iDestruct ("Hgood" with "Halign_last [//]") as "H".
  iNamedSuffix "H" "0".
  iDestruct (wish_getNextEp_det with "Hwish_getNextEp Hwish_getNextEp0") as %[-> ->].
  iFrame "#".
  iSplit.
  - iNamed "Halign_pend_pend". iFrame "%". simpl in *.
    destruct isGoodClis; [|done].
    iNamed "HgoodCli".
    iFrame.
    iPureIntro. split.
    + intros ?? Ht. apply Hbound in Ht. word.
    + intros ? Ht. apply Hbound in Ht. word.
  - rewrite last_lookup in Hlast_servHist0.
    iDestruct (mono_list_idx_own_get with "Hlb_servHist0") as "$"; [done|].
    simpl in *.
    apply Forall2_length in Heq_hist0.
    autorewrite with len in *.
    iSplit; word.
Qed.

End proof.
End client.
