From New.generatedproof.github_com.sanjit_bhat.pav Require Import client.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof Require Import bytes.
From New.proof.github_com.goose_lang Require Import std.
From New.proof.github_com.sanjit_bhat.pav Require Import
  advrpc auditor cryptoffi hashchain ktcore merkle server.

From New.proof.github_com.sanjit_bhat.pav.client_proof Require Import
  base rpc_serv.

Module client.
Import rpc_serv.client rpc_serv.server.

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

    "#His_ver" ∷ match server.Trust.get_full γ.(cfg.serv_good) with None => True | _ =>
      ∃ ver_idx ver_dig,
      "%Hlook_ver_dig" ∷ ⌜digs !! ver_idx = Some ver_dig⌝ ∗
      "%Hlt_ver" ∷ ⌜uint.nat prevVerLen ≤
        length $ ktcore.to_pks agreeγ.(ktcore.Agree.vrf_pk) uid ver_dig⌝ end
  }}}
  ptr_c @! (go.PointerType client.Client) @! "getHistory" #uid #prevVerLen
  {{{
    ptr_nextEp sl_pks err,
    RET (#ptr_nextEp, #sl_pks, #(ktcore.blame_to_u64 err));
    "Hstr_Client" ∷ ptr_c ↦ (client.Client.mk x0 x1 ptr_lastEp ptr_serv) ∗
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
        (merkle.inv_fn last_dig) uid (uint.nat prevVerLen + length pks) None⌝ ∗
      "%Hnoof_vers" ∷ ⌜let num_vers := (uint.nat prevVerLen + length pks)%nat in
        num_vers = uint.nat (W64 num_vers)⌝ ∗

      "#Hperm_pks" ∷ match server.Trust.get_full γ.(cfg.serv_good) with None => True | _ =>
        if decide (length pks = 0%nat) then True else
          ∃ uidγ,
          "%Hlook_uidγ" ∷ ⌜γ.(cfg.uidγs) !! uid = Some uidγ⌝ ∗
          "#Hidx_pks" ∷ ([∗ list] off ↦ pk ∈ pks,
            ∃ i,
            let ver := (uint.nat prevVerLen + off)%nat in
            "#Hidx_pk" ∷ mono_list_idx_own uidγ i (ver, pk)) end)
  }}}.
Proof.
  simpl. wp_start as "@". wp_auto.
  iNamed "Hown_serv". iNamed "Hown_lastEp". wp_auto.
  wp_apply wp_CallHistory as "* @".
  { iFrame "#".
    destruct (server.Trust.get_full _) eqn:Ht; try done.
    erewrite server.Trust.full_to_sigpred; [|done].
    clear Ht.
    iNamed "His_lastEp". iNamed "Halign_lastEp". iNamed "His_ver".
    iNamed "Halign_serv_sigpred". iNamed "Halign_serv_full".
    rewrite last_lookup in Hlast_dig.
    replace (pred _) with (uint.nat lastEp.(epoch.epoch)) in Hlast_dig; [|word].
    iDestruct (mono_list_idx_own_get with "Hserv_digs") as "$"; [done|].
    apply lookup_lt_Some in Hlook_ver_dig as ?.
    rewrite Heq_serv_func_start drop_0 in Hmono_plain.
    opose proof (ktcore.mono_plain_lookup uid _ Hlook_ver_dig Hlast_dig _) as Hpref; [done|word|].
    apply prefix_length in Hpref.
    rewrite Heq_vrf_pk in Hlt_ver.
    word. }
  case_bool_decide as Heq_err; wp_auto;
    rewrite ktcore.rw_Blame0 in Heq_err; subst.
  2: { iApply "HΦ". iFrame "∗%". by case_decide. }
  case_decide as Ht; try done. clear Ht.
  iNamed "Herr".
  wp_apply wp_getNextEp as "* @".
  { by iFrame "#". }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iFrame.
    iSplit; [|by case_decide].
    iApply ktcore.blame_one.
    iIntros (?).
    destruct (server.Trust.get_full _) eqn:Ht; try done.
    erewrite server.Trust.full_to_sigpred; [|done].
    clear Ht.
    iApply "Hgenie".
    iDestruct ("Hgood" with "[$][$][$][]") as "@".
    { iNamed "His_lastEp". iNamed "Halign_serv_full". word. }
    iFrame "#". }
  iNamedSuffix "Hgenie" "0".
  iAssert (match server.Trust.get_sigpred γ.(cfg.serv_good) with None => True | Some γserv =>
    epoch.align_sigpred γserv (digs ++ newDigs) end)%I as "#Halign_nextEp".
  { destruct (server.Trust.get_sigpred _); try done.
    iNamed "Hwish_getNextEp0". iNamed "His_next". iNamed "Halign_serv_sigpred".
    iDestruct (ktcore.get_link_sigpred with "His_sigPk His_sig") as "@".
    rewrite -Heq_ep in His_chain.
    opose proof (hashchain.inj His_chain Hinv) as [<- _].
    iFrame "#%". }
  wp_apply wp_SumNoOverflow.
  iDestruct "Hsl_hist" as (sl0_hist) "[Hsl_hist Hsl0_hist]".
  iDestruct (own_slice_len with "Hsl_hist") as %?.
  iDestruct (big_sepL2_length with "Hsl0_hist") as %?.
  wp_if_destruct.
  2: {
    rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iFrame.
    iSplit; [|by case_decide].
    iApply ktcore.blame_one.
    iIntros (?).
    destruct (server.Trust.get_full _) eqn:Ht; try done.
    erewrite server.Trust.full_to_sigpred; [|done].
    clear Ht.
    iDestruct ("Hgood" with "Halign_lastEp[$][$][]") as "@".
    { iNamed "His_lastEp". iNamed "Halign_serv_full". word. }
    apply (f_equal length) in Heq_hist.
    autorewrite with len in *.
    word. }
  iNamedSuffix "Hown_next0" "0". wp_auto.
  wp_apply wp_checkMembs as "* @".
  { iFrame "#". word. }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iFrame.
    iSplit; [|by case_decide].
    iApply ktcore.blame_one.
    iIntros (?).
    destruct (server.Trust.get_full _) eqn:Ht; try done.
    erewrite server.Trust.full_to_sigpred; [|done].
    clear Ht.
    iDestruct ("Hgood" with "Halign_lastEp[$][$][]") as "@".
    { iNamed "His_lastEp". iNamed "Halign_serv_full". word. }
    iApply "Hgenie".
    iNamed "Halign_serv_sigpred".
    rewrite Heq_vrf_pk.
    by iDestruct (wish_getNextEp_det with "Hwish_getNextEp0 Hwish_getNextEp") as %[<- <-]. }
  iNamedSuffix "Hgenie" "0".
  wp_apply wp_checkNonMemb as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameServFull.
    iApply "HΦ".
    iFrame.
    iSplit; [|by case_decide].
    iApply ktcore.blame_one.
    iIntros (?).
    destruct (server.Trust.get_full _) eqn:Ht; try done.
    erewrite server.Trust.full_to_sigpred; [|done].
    clear Ht.
    iDestruct ("Hgood" with "Halign_lastEp[$][$][]") as "@".
    { iNamed "His_lastEp". iNamed "Halign_serv_full". word. }
    iApply "Hgenie".
    iNamed "Halign_serv_sigpred".
    rewrite Heq_vrf_pk.
    iDestruct (wish_getNextEp_det with "Hwish_getNextEp0 Hwish_getNextEp") as %[<- <-].
    apply (f_equal length) in Heq_hist.
    autorewrite with len in *.
    iAssert (⌜uint.nat prevVerLen ≤ length $ ktcore.to_pks
      t.(server.cfg.agreeγ).(ktcore.Agree.vrf_pk) uid next.(epoch.dig)⌝)%I as "%".
    { iNamed "Hwish_getNextEp0". iNamed "His_next". iNamed "Halign_nextEp".
      iNamed "His_ver". iNamed "Halign_serv_full".
      rewrite last_lookup in Hlast_dig.
      autorewrite with len in *.
      replace (pred _) with (uint.nat next.(epoch.epoch)) in Hlast_dig; [|word].
      apply lookup_lt_Some in Hlook_ver_dig as ?.
      apply (lookup_app_l_Some _ newDigs) in Hlook_ver_dig.
      rewrite Heq_serv_func_start drop_0 in Hmono_plain.
      opose proof (ktcore.mono_plain_lookup uid _ Hlook_ver_dig Hlast_dig _) as Hpref; [done|word|].
      apply prefix_length in Hpref.
      word. }
    iExactEq "Hwish_bound". f_equal. word. }
  iNamedSuffix "Hgenie" "0".

  rewrite -wp_fupd.
  wp_apply wp_slice_make3 as "* (Hsl_pks&Hcap_pks&_)"; [word|].
  iAssert (
    ∃ (i : w64) (x : loc) sl_pks sl0_pks,
    let pks_of_hist := ktcore.CommitOpen.Val <$> (ktcore.Memb.PkOpen <$> hist) in
    "i" ∷ i_ptr ↦ i ∗
    "%Heq_i" ∷ ⌜0 ≤ sint.Z i ≤ length hist⌝ ∗
    "x" ∷ x_ptr ↦ x ∗
    "pks" ∷ pks_ptr ↦ sl_pks ∗
    "Hsl_pks" ∷ sl_pks ↦* sl0_pks ∗
    "Hcap_pks" ∷ own_slice_cap slice.t sl_pks (DfracOwn 1) ∗
    "#Hsl0_pks" ∷ ([∗ list] sl_pk;pk ∈ sl0_pks;take (sint.nat i) pks_of_hist,
      "#Hsl_pk" ∷ sl_pk ↦*□ pk)
  )%I with "[pks Hsl_pks Hcap_pks i x]" as "IH".
  { iFrame. iSplit; [word|naive_solver]. }
  wp_for "IH".
  wp_if_destruct.
  { list_elem sl0_hist (sint.nat i) as ptr_memb.
    list_elem hist (sint.nat i) as memb.
    iDestruct (big_sepL2_lookup with "Hsl0_hist") as "#Hown_memb"; [done..|].
    case_decide as Ht; [|word]. clear Ht.
    wp_apply (wp_load_slice_index with "[$Hsl_hist]"); [word|done|].
    iIntros "_". wp_auto.
    iNamed "Hown_memb". iNamed "Hown_PkOpen". wp_auto.
    wp_apply wp_slice_literal. iSplitR; [done|].
    iIntros "* [Ht _]". wp_auto.
    replace (sint.nat (W64 0)) with 0%nat by word. simpl.
    wp_apply (wp_slice_append with "[$Hsl_pks $Hcap_pks $Ht]") as "* (Hsl_pks&Hcap_pks&_)".
    wp_for_post.
    iFrame.
    iSplitR; [word|].
    replace (sint.nat (word.add i _)) with (S $ sint.nat i); [|word].
    erewrite take_S_r.
    2: { rewrite !list_lookup_fmap Hmemb_lookup //. }
    iApply big_sepL2_snoc. iFrame "#". }

  replace (sint.nat i) with (length hist); [|word].
  rewrite -!fmap_take take_ge; [|word].
  iApply "HΦ".
  iFrame.
  iSplitR. { iPureIntro. apply ktcore.blame_none. }
  case_decide as Ht; try done. clear Ht.
  iPersist "Hsl_pks".
  iPoseProof "Hwish_getNextEp0" as "@".
  iFrame "#%".
  iSplitR. { by iNamed "His_next". }
  iSplitR. { iPureIntro. exact_eq Hnone_hidden0. len. }
  iSplitR; [len|].
  rewrite /server.is_rpc_cli.
  destruct (server.Trust.get_full _) eqn:Ht; try done.
  erewrite server.Trust.full_to_sigpred; [|done].
  clear Ht.
  case_decide; try done.
  autorewrite with len in *.

  iDestruct ("Hgood" with "Halign_lastEp[$][$][]") as "@".
  { iNamed "His_lastEp". iNamed "Halign_serv_full". word. }
  iDestruct (wish_getNextEp_det with "Hwish_getNextEp0 Hwish_getNextEp") as %[<- <-].
  iNamed "His_next". iNamed "Halign_nextEp".
  rewrite last_lookup in Hlast_dig.
  iDestruct (mono_list_idx_own_get with "Hserv_digs") as "#Hidx_digs"; [done|].
  iMod (server.digs_to_put_perms with "[$][$]") as "H".
  iModIntro.
  iDestruct ("H" $! uid with "[]") as (?) "(%&#Hidx_pks)".
  { apply (f_equal length) in Heq_hist.
    autorewrite with len in *. word. }
  iNamed "Halign_serv_full".
  rewrite Heq_uidγs.
  iFrame "%".
  iApply big_sepL_intro.
  iIntros "!> * %Hlook".
  iApply (big_sepL_lookup with "Hidx_pks").
  by rewrite -Heq_hist lookup_drop in Hlook.
Qed.

(* TODO: rename clis_good. mis-leading. we are a good client.
this referring to smth else. whether our uid compromised. *)
Lemma wp_New serv_good clis_good uidγs uid uidγ (servAddr : w64) sl_servPk servPk :
  {{{
    is_pkg_init client ∗
    "%Hlook_uidγ" ∷ ⌜uidγs !! uid = Some uidγ⌝ ∗
    "Hclis_good" ∷
      match clis_good with
      | true => "Hown_uid" ∷ mono_list_auth_own uidγ 1 ([] : list (nat * list w8))
      | false => "#Hinv_uid" ∷ ver.is_uid_inv uidγ
      end ∗
    "%Heq_uidγs" ∷ ⌜match server.Trust.get_full serv_good with None => True | Some γserv =>
      uidγs = γserv.(server.cfg.uidγs) end⌝ ∗
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
      "%Heq_uidγs" ∷ ⌜γ.(cfg.uidγs) = uidγs⌝ ∗
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
  set (cfg.mk uid servPk fakeAgreeγ uidγs serv_good clis_good) as fakeγ.
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
    iNamed "Hwish_CheckStartChain".
    iSplitL; [|iSplitL].
    - rewrite /epoch.valid /=.
      eapply hashchain.fuel_bound' in His_chain_start as ?.
      ereplace (?[x] - _ + _)%nat with ?x by word.
      by iFrame "#%".
    - rewrite /epoch.align_sigpred.
      destruct (server.Trust.get_sigpred _); try done.
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

  iPoseProof "Hown_nextEp" as "H".
  iNamedSuffix "H" "1".
  wp_auto.
  iDestruct (own_slice_len with "Hsl_pks") as %?.
  iDestruct (big_sepL2_length with "Hsl0_pks") as %?.
  rewrite -wp_fupd.
  wp_if_destruct.
  2: {
    iModIntro.
    rewrite ktcore.rw_BlameServClients.
    iApply "HΦ".
    iSplit.
    2: { destruct (decide (_ ≠ ∅)); try done. set_solver. }
    iApply ktcore.blame_two.
    iSplit; [done|].
    iIntros ([? ->]).
    iNamed "Hclis_good".
    destruct (server.Trust.get_full _); try done.
    case_decide; [word|].
    iNamed "Hperm_pks".
    list_elem pks 0%nat as pk.
    iDestruct (big_sepL_lookup with "Hidx_pks") as "@"; [done|].
    simplify_eq/=.
    by iDestruct (mono_list_auth_idx_lookup with "Hown_uid Hidx_pk") as %?. }
  iClear "Hperm_pks".
  assert (pks = []) as ->.
  { apply nil_length_inv. word. }
  replace (_ + _)%nat with 0%nat in HnonMemb by word.

  iApply "HΦ".
  iClear "Hlb_digs".
  iMod (mono_list_auth_own_update_app new_digs with "Hauth_digs") as "[Hauth_digs #Hlb_digs]".
  iModIntro.
  iSplit. { iPureIntro. apply ktcore.blame_none. }
  case_decide as Ht; try done. clear Ht.
  set (set ktcore.Agree.func_start
    (λ _, uint.nat nextEp.(epoch.epoch) - fakeAgreeγ.(ktcore.Agree.digs_start))%nat
    fakeAgreeγ) as agreeγ.
  set (set cfg.agreeγ (λ _, agreeγ) fakeγ) as γ.
  iClear "Hwish_CheckStartChain Hwish_CheckStartVrf Hstr_serv Hstr_epoch Hstr_epoch1".
  iExists γ. simpl.
  iPoseProof "His_nextEp" as "@".
  simpl in *. autorewrite with len in *.
  repeat iSplit; try done.
  { iPureIntro.
    opose proof (last_length_Some digs _) as ?; [done|].
    simpl in *. word. }
  iFrame "∗".
  iFrame "∗ Hown_serv Hown_nextEp His_nextEp #". simpl.
  iExists (ver.mk' 0).
  repeat iSplit; try done; try iPureIntro.
  - simpl.
    replace (_ - (_ - _))%nat with (pred $ length (digs ++ new_digs)); [|len].
    erewrite last_drop_Some'; [|done].
    rewrite Hlast_dig in Hlast_dig0.
    simplify_eq/=.
    by eapply (ktcore.staged_init _ _ _ []).
  - iFrame "%". simpl.
    destruct clis_good; [|done].
    iFrame.
    iPureIntro. set_solver.
  - destruct (server.Trust.get_sigpred _); try done.
    iNamed "Halign_serv_sigpred".
    iFrame "#%". simpl in *.
    iDestruct (ktcore.get_link_sigpred with "His_sigPk His_sig") as "H".
    iNamedSuffix "H" "0".
    word.
  - len.
Qed.

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
  wp_auto. simpl.
  iPersist "c pk".
  wp_bind (If _ _ _).
  wp_apply (wp_wand _ _ _
    (λ v,
    ∃ sl_pendPk',
    "->" ∷ ⌜v = execute_val⌝ ∗
    "Hstr_client" ∷ ptr_c ↦ {|
                          client.Client.uid' := γ.(cfg.uid);
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
    - destruct σ.(state.pend_pk); iNamed "HpendPk"; try done.
      simplify_eq/=.
      wp_apply bytes.wp_Equal as "_".
      { iFrame "#". }
      wp_apply std.wp_Assert.
      { by case_bool_decide. }
      by iFrame "∗#".
    - by iFrame "∗#". }

  iAssert (
    |={⊤}=> ∃ uidγ i,
    "Hputs_nextVer" ∷ ver.own_puts γ (Some pk) nextVer ∗
    "%Hlook_uidγ" ∷ ⌜γ.(cfg.uidγs) !! γ.(cfg.uid) = Some uidγ⌝ ∗
    "#Hidx_put" ∷ mono_list_idx_own uidγ i (nextVer.(ver.ver), pk))%I
    with "[Hputs_nextVer]" as "> @".
  { iNamed "Hputs_nextVer".
    iFrame "%".
    destruct γ.(cfg.clis_good); iNamed "HgoodCli".
    - iMod (mono_list_auth_own_update_app [(nextVer.(ver.ver), pk)]
        with "Hputs") as "[Hputs #Hlb]".
      iDestruct (mono_list_idx_own_get (length puts) with "Hlb") as "$".
      { by rewrite lookup_snoc. }
      iFrame.
      iPureIntro. split.
      + intros. decompose_list_elem_of; [naive_solver|].
        by simplify_eq/=.
      + intros. decompose_list_elem_of; [|by simplify_eq/=].
        destruct σ.(state.pend_pk); naive_solver.
    - iFrame "#".
      iInv "Huid_inv" as ">@" "Hclose".
      iMod (mono_list_auth_own_update_app [(nextVer.(ver.ver), pk)]
        with "Hputs") as "[Hputs #Hlb]".
      iMod ("Hclose" with "[Hputs]") as "_"; [iFrame|].
      iDestruct (mono_list_idx_own_get (length puts) with "Hlb") as "$"; [|done].
      { by rewrite lookup_snoc. } }

  wp_apply server.wp_CallPut.
  { rewrite Heq_ver. iFrame "#%".
    destruct (server.Trust.get_full _); try done.
    by iNamed "Halign_serv_full". }
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
    (ep : w64) hasPk (sl_pk : slice.t) err,
    RET (#ep, #hasPk, #sl_pk, #(ktcore.blame_to_u64 err));
    "%Hblame" ∷ ⌜ktcore.BlameSpec err
      {[ktcore.BlameServFull:=option_bool $ server.Trust.get_full γ.(cfg.serv_good)]}⌝ ∗
    "Herr" ∷
      (if decide (err ≠ ∅)
      then "Hclient" ∷ Client.own γ ptr_c σ
      else
        ∃ opt_pk,
        let agreeγ := γ.(cfg.agreeγ) in
        let σ' := set state.epoch (λ _, uint.nat ep) σ in
        "Hclient" ∷ Client.own γ ptr_c σ' ∗
        "%Heq_ep" ∷ ⌜(σ.(state.epoch) ≤ σ'.(state.epoch))%nat⌝ ∗
        "#Hopt_pk" ∷
          match opt_pk with
          | None => "%Heq_hasPk" ∷ ⌜hasPk = false⌝
          | Some pk =>
            "%Heq_hasPk" ∷ ⌜hasPk = true⌝ ∗
            "#Hsl_pk" ∷ sl_pk ↦*□ pk
          end ∗
        "#Hptr_kt" ∷ agreeγ ↪KT[σ'.(state.epoch), uid] opt_pk)
  }}}.
Proof.
  wp_start as "@". wp_auto.
  iNamed "Hclient".
  wp_apply (wp_Client_getHistory with "[$Hstr_client]") as "* @".
  { iFrame "#".
    destruct (server.Trust.get_full _) eqn:Ht; try done.
    erewrite server.Trust.full_to_sigpred; [|done].
    clear Ht.
    iNamed "His_lastEp".
    rewrite last_lookup in Hlast_dig.
    iFrame "%".
    word. }
  case_bool_decide as Heq_err; wp_auto;
    rewrite ktcore.rw_Blame0 in Heq_err; subst.
  2: {
    iApply "HΦ".
    iSplitR.
    2: { case_decide; try done. iFrame "∗#%". }
    iPureIntro.
    eapply ktcore.blame_add_interp; [done|].
    apply map_singleton_subseteq_l.
    by simpl_map. }
  case_decide as Ht; try done. clear Ht.
  iNamed "Herr".
  iNamed "Hown_nextEp". wp_auto.
  rewrite -wp_fupd.
  iPersist "pks".
  wp_bind (If _ _ _).
  wp_apply (wp_wand _ _ _
    (λ v,
    ∃ hasPk sl_pk,
    let opt_pk := last pks in
    "->" ∷ ⌜v = execute_val⌝ ∗
    "hasPk" ∷ hasPk_ptr ↦ hasPk ∗
    "pk" ∷ pk_ptr ↦ sl_pk ∗
    "#Hopt_pk" ∷
      match opt_pk with
      | None => "->" ∷ ⌜hasPk = false⌝
      | Some pk =>
        "->" ∷ ⌜hasPk = true⌝ ∗
        "#Hsl_pk" ∷ sl_pk ↦*□ pk
      end
    )%I
    with "[hasPk pk]"
  ) as "* @".
  { iDestruct (own_slice_len with "Hsl_pks") as %?.
    iDestruct (big_sepL2_length with "Hsl0_pks") as %?.
    wp_if_destruct.
    { iFrame. destruct pks; simpl in *; [done|word]. }
    list_elem sl0_pks (sint.Z (word.sub sl_pks.(slice.len) (W64 1))) as sl_pk.
    list_elem pks (sint.Z (word.sub sl_pks.(slice.len) (W64 1))) as pk.
    iDestruct (big_sepL2_lookup with "Hsl0_pks") as "@"; [done..|].
    destruct (decide (_ ≤ _ < _)) as [Ht|Ht]; [|word]. clear Ht.
    wp_apply (wp_load_slice_index with "[$Hsl_pks]") as "_"; [word|done|].
    iFrame.
    replace (sint.nat _) with (pred $ length pks) in Hpk_lookup by word.
    rewrite -last_lookup in Hpk_lookup.
    rewrite Hpk_lookup.
    by iFrame "#". }

  iApply "HΦ".
  rewrite /own. iNamed "Hown_gs".
  iMod (mono_list_auth_own_update_app new_digs with "Hown_digs") as "[Hown_digs #His_digs]".
  iModIntro.
  iSplitR. { iPureIntro. apply ktcore.blame_none. }
  destruct (decide (_ ≠ _)) as [Ht|Ht]; try done. clear Ht.
  iFrame "Hopt_pk".
  iFrame "∗ Hown_serv His_nextVer #". simpl.
  iNamed "His_nextEp".
  autorewrite with len in *.
  iSplitR; [word|].
  iSplitR; [word|].

  simplify_eq/=.
  replace (_ - _)%nat with (pred $ length (digs ++ new_digs)); [|len].
  rewrite -last_lookup.
  iFrame "%".
  apply ktcore.pks_in_hidden_from_0 in Hmembs.
  ereplace (_ + ?[x])%nat with (?x) in HnonMemb by word.
  by erewrite ktcore.inv_fn_inp_pks_exact.
Qed.

Lemma wp_checkPend ptr_pend pend_pk obj sl_pks sl0_pks pks :
  {{{
    is_pkg_init client ∗
    "Hown_nextVer" ∷ ver.own ptr_pend pend_pk obj ∗
    "#Hsl_pks" ∷ sl_pks ↦*□ sl0_pks ∗
    "#Hsl0_pks" ∷ ([∗ list] sl_pk;pk ∈ sl0_pks;pks,
      "#Hsl_pk" ∷ sl_pk ↦*□ pk)
  }}}
  @! client.checkPend #ptr_pend #sl_pks
  {{{
    isChanged err, RET (#isChanged, #err);
    "Hown_nextVer" ∷ ver.own ptr_pend pend_pk obj ∗
    "Herr" ∷
      match err with
      | true =>
        "%Herr" ∷ ⌜(1 < length pks)%nat ∨ ∃ pk, pks = [pk] ∧ pend_pk ≠ Some pk⌝
      | false =>
        match isChanged with
        | false => "%Heq_pks" ∷ ⌜pks = []⌝
        | true =>
          ∃ pk,
          "%Heq_pks" ∷ ⌜pks = [pk]⌝ ∗
          "%Heq_pend" ∷ ⌜pend_pk = Some pk⌝
        end
      end
  }}}.
Proof.
  wp_start as "@". wp_auto.
  iDestruct (own_slice_len with "Hsl_pks") as %?.
  iDestruct (big_sepL2_length with "Hsl0_pks") as %?.
  wp_if_destruct.
  { iApply "HΦ". iFrame. destruct pks; simpl in *; [done|word]. }
  wp_if_destruct.
  { iApply "HΦ". iFrame. iLeft. word. }
  iNamed "Hown_nextVer". wp_auto.
  assert (∃ pk, pks = [pk]) as (pk&->).
  { destruct pks; simpl in *; [word|].
    destruct pks; simpl in *; [naive_solver|word]. }
  wp_if_destruct;
    destruct pend_pk; iNamed "HpendPk"; try done.
  2: {
    iApply "HΦ". iFrame "∗#%".
    iPureIntro. naive_solver. }
  assert (∃ x, sl0_pks = [x]) as (sl_pk&->).
  { destruct sl0_pks; simpl in *; [word|].
    destruct sl0_pks; simpl in *; [naive_solver|word]. }
  simpl. iNamed "Hsl0_pks". iClear "Hsl0_pks".
  case_decide as Ht; [|word]. clear Ht.
  wp_apply (wp_load_slice_index with "[$Hsl_pks]") as "_"; [word|done|].
  wp_apply bytes.wp_Equal as "_".
  { iFrame "#". }
  iApply "HΦ". iFrame "∗#%".
  case_bool_decide; iPureIntro; naive_solver.
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
    "%Hblame" ∷ ⌜ktcore.BlameSpec err
      ({[
        ktcore.BlameServFull:=option_bool $ server.Trust.get_full γ.(cfg.serv_good);
        ktcore.BlameClients:=γ.(cfg.clis_good)
      ]})⌝ ∗
    "Herr" ∷
      (if decide (err ≠ ∅)
      then "Hclient" ∷ Client.own γ ptr_c σ
      else
        ∃ last_key num_new_keys,
        let agreeγ := γ.(cfg.agreeγ) in
        let σ0 := set state.epoch (λ _, uint.nat ep) σ in
        "%Heq_ep" ∷ ⌜(σ.(state.epoch) ≤ σ0.(state.epoch))%nat⌝ ∗
        "%Hlast_key" ∷ ⌜last σ.(state.keys) = Some last_key⌝ ∗
        "%Heq_keys_len" ∷ ⌜S σ0.(state.epoch) = (agreeγ.(ktcore.Agree.digs_start) +
          agreeγ.(ktcore.Agree.func_start) + length σ.(state.keys) + num_new_keys)%nat⌝ ∗
        "Hchanged" ∷
          match isChanged with
          | false =>
            let σ1 := set state.keys (.++ replicate num_new_keys last_key) σ0 in
            "Hclient" ∷ Client.own γ ptr_c σ1
          | true =>
            ∃ num_last_key num_pend_key,
            (* [S num_pend_key] guarantees at least one pend key. *)
            let σ1 :=
              set state.keys
                (.++ replicate num_last_key last_key ++
                  replicate (S num_pend_key) σ.(state.pend_pk))
              (set state.pend_pk (λ _, None) σ0) in
            "Hclient" ∷ Client.own γ ptr_c σ1 ∗
            "%Hnum_new_keys" ∷ ⌜num_new_keys = (num_last_key + S num_pend_key)%nat⌝ ∗
            "%HSome_pend" ∷ ⌜is_Some σ.(state.pend_pk)⌝
          end)
  }}}.
Proof.
  wp_start as "@". wp_auto.
  iNamed "Hclient". iNamed "Hown_nextVer". wp_auto.
  rewrite /own. iNamed "Hown_gs".
  iNamed "His_nextVer".
  iDestruct (mono_list_auth_lb_valid with "Hown_digs Hlb_ver_digs") as %[_ Hpref].
  wp_apply (wp_Client_getHistory with "[$Hstr_client]") as "* @".
  { iFrame "#".
    destruct (server.Trust.get_full _) eqn:Ht; try done.
    erewrite server.Trust.full_to_sigpred; [|done].
    clear Ht.
    iNamed "Halign_lastEp". iNamed "Halign_serv_sigpred". iNamed "Halign_serv_full".
    apply ktcore.staged_extract in Hstaged as (last_dig&_&Hlast_dig&_&_&Ht).
    rewrite Heq_serv_func_start drop_0 in Hmono_plain.
    opose proof (Ht _) as Hnum_vers.
    { rewrite Heq_vrf_pk.
      unfold ktcore.mono_plain in *.
      rewrite !fmap_drop.
      apply list_reln_drop.
      eapply list_reln_prefix; [done|].
      by repeat apply prefix_fmap. }
    rewrite last_lookup lookup_drop in Hlast_dig.
    eapply prefix_lookup_Some in Hlast_dig; [|done].
    iFrame "%".
    word. }
  case_bool_decide as Heq_err; wp_auto;
    rewrite ktcore.rw_Blame0 in Heq_err; subst.
  2: {
    iApply "HΦ".
    iSplitR.
    2: { case_decide; try done. iFrame "∗#%". }
    iPureIntro.
    eapply ktcore.blame_add_interp; [done|].
    apply map_singleton_subseteq_l.
    by simpl_map. }
  case_decide as Ht; try done. clear Ht.
  iNamed "Herr".
  iNamed "Hown_nextEp". wp_auto.
  rewrite Heq_ver in Hmembs HnonMemb |-*.
  wp_apply (wp_checkPend with "[$Hstr_ver]") as "* @".
  { iFrame "#%". }
  iClear "HpendPk".
  wp_if_destruct; iNamed "Herr".
  { rewrite ktcore.rw_BlameServClients.
    iApply "HΦ".
    iSplit.
    2: {
      destruct (decide (_ ≠ ∅)); [|set_solver].
      iFrame "∗ Hown_serv Hown_lastEp #%". }
    iApply ktcore.blame_two.
    iSplit; [done|].
    iNamed "Hputs_nextVer".
    iIntros ([? ->]).
    iNamed "HgoodCli".
    destruct (server.Trust.get_full _); try done.
    destruct Herr as [?|(pk&->&?)].
    - destruct (decide (_ = 0%nat)) as [Ht|Ht]; [word|]. clear Ht.
      iNamed "Hperm_pks".
      simplify_eq/=.
      list_elem pks 1%nat as pk.
      iDestruct (big_sepL_lookup with "Hidx_pks") as "@"; [done|].
      iDestruct (mono_list_auth_idx_lookup with "Hputs Hidx_pk") as %Hlook.
      apply list_elem_of_lookup_2 in Hlook.
      eapply Hbound in Hlook. word.
    - simpl in *.
      iNamed "Hperm_pks". iDestruct "Hidx_pks" as "[H _]". iNamed "H".
      simplify_eq/=.
      iDestruct (mono_list_auth_idx_lookup with "Hputs Hidx_pk") as %Hlook.
      apply list_elem_of_lookup_2 in Hlook.
      ereplace (?[x] + 0)%nat with ?x in Hlook by lia.
      by eapply Heq_pend in Hlook. }
  iClear "Hperm_pks".

  iMod (mono_list_auth_own_update_app new_digs with "Hown_digs") as "[Hown_digs #Hlb_digs]".
  wp_if_destruct; iNamed "Herr"; simplify_eq/=.
  2: {
    iApply "HΦ".
    iSplitR. { iPureIntro. apply ktcore.blame_none. }
    case_decide as Ht; try done. clear Ht.
    pose proof Hstaged as Ht.
    apply ktcore.staged_extract in Ht as (last_dig'&old_key&Hlast_dig'&Hold_key&?&_).
    destruct Hpref as [rem_digs ->].
    list_simplifier.
    ereplace (?[x] + 0)%nat with ?x in HnonMemb by lia.
    eapply (ktcore.staged_grow_last _ _ (rem_digs ++ new_digs) last_dig) in Hstaged;
      cycle 1; [|done..|].
    { rewrite -Hlast_dig !(assoc _) !last_app.
      repeat case_match; try done.
      rewrite Hlast_dig'.
      by apply last_drop_Some'' in Hlast_dig'. }
    iFrame "∗ Hown_serv #%". simpl.
    iNamed "His_nextEp".
    opose proof (last_length_Some _ _).
    { eexists. exact Hlast_dig'. }
    autorewrite with len in *.
    rewrite drop_app_le; [|word].
    iFrame "%".
    word. }

  iNamed "Hown_nextVer". rewrite Heq_pend. iNamed "HpendPk". wp_auto.
  iApply "HΦ".
  iSplitR. { iPureIntro. apply ktcore.blame_none. }
  case_decide as Ht; try done. clear Ht.
  pose proof Hstaged as Ht.
  apply ktcore.staged_extract in Ht as (last_dig'&old_key&Hlast_dig'&Hold_key&?&_).
  destruct Hpref as [rem_digs ->].
  list_simplifier.
  ereplace (?[x] + 1)%nat with (S ?x) in HnonMemb by lia.
  eapply ktcore.pks_in_hidden_from_singleton in Hmembs.
  eapply (ktcore.staged_grow_new _ _ (rem_digs ++ new_digs) last_dig)
    in Hstaged as (num_old&num_new&?&Hstaged);
    cycle 1; [|done..|].
  { rewrite -Hlast_dig !(assoc _) !last_app.
    repeat case_match; try done.
    rewrite Hlast_dig'.
    by apply last_drop_Some'' in Hlast_dig'. }
  iFrame "∗ Hown_serv #%". simpl in *.
  iNamed "His_nextEp".
  opose proof (last_length_Some _ _).
  { eexists. exact Hlast_dig'. }
  autorewrite with len in *.
  rewrite drop_app_le; [|word].
  set (ver.mk' (S nextVer.(ver.ver))) as nextVer'.
  replace (S _) with (nextVer'.(ver.ver)) in Hstaged; [|done].
  iFrame "%".
  iExists (length rem_digs + length new_digs)%nat.
  repeat iSplit; try done.
  - word.
  - word.
  - simpl. word.
  - iNamed "Hputs_nextVer".
    iFrame "%".
    destruct (γ.(cfg.clis_good)); try done.
    iNamed "HgoodCli".
    iFrame. simpl.
    iPureIntro. split.
    + intros. etrans. { by eapply Hbound. } lia.
    + intros * Helem. eapply Hbound in Helem. lia.
  - word.
Qed.

Lemma wp_Client_Audit γ ptr_c σ adtr_good (adtrAddr : w64) sl_adtrPk adtrPk :
  {{{
    is_pkg_init client ∗
    "Hclient" ∷ Client.own γ ptr_c σ ∗
    "#Hsl_adtrPk" ∷ sl_adtrPk ↦*□ adtrPk ∗
    "#His_adtrPk" ∷ match auditor.Trust.get_sigpred adtr_good with None => True | Some adtrγ =>
      cryptoffi.is_sig_pk adtrPk (sigpred.P adtrγ) end ∗
    "%Heq_adtrPk" ∷ ⌜match auditor.Trust.get_full adtr_good with None => True | Some adtrγ =>
      adtrPk = adtrγ.(auditor.cfg.adtr_sig_pk) end⌝ ∗
    "%Heq_serv_pk" ∷ ⌜match auditor.Trust.get_full adtr_good with None => True | Some adtrγ =>
      γ.(cfg.sig_pk) = adtrγ.(auditor.cfg.serv_sig_pk) end⌝
  }}}
  ptr_c @! (go.PointerType client.Client) @! "Audit" #adtrAddr #sl_adtrPk
  {{{
    (startEp ep : w64) err (ptr_evid : loc),
    RET (#startEp, #ep, #(ktcore.blame_to_u64 err), #ptr_evid);
    "Hclient" ∷ Client.own γ ptr_c σ ∗
    "%Hblame" ∷ ⌜ktcore.BlameSpec err
      ({[
        ktcore.BlameServSig:=option_bool $ server.Trust.get_sigpred γ.(cfg.serv_good);
        ktcore.BlameAdtrFull:=option_bool $ auditor.Trust.get_full adtr_good
      ]})⌝ ∗
    "#Hevid" ∷ (if decide (ptr_evid = null) then True else
      ∃ evid,
      "#Hown_evid" ∷ ktcore.Evid.own ptr_evid evid (□) ∗
      "#His_evid" ∷ ktcore.wish_Evid evid γ.(cfg.sig_pk)) ∗
    "Herr" ∷ (if decide (err ≠ ∅) then True else
      "%Hlt_startEp" ∷ ⌜uint.nat startEp ≤ uint.nat ep⌝ ∗
      "%Heq_startEp" ∷ ⌜match auditor.Trust.get_sigpred adtr_good with None => True | Some adtrγ =>
        uint.nat startEp ≥ (adtrγ.(ktcore.Agree.digs_start) +
          adtrγ.(ktcore.Agree.func_start))%nat end⌝ ∗
      "%Heq_ep" ∷ ⌜uint.nat ep = σ.(state.epoch)⌝ ∗
      "#His_audit" ∷ match auditor.Trust.get_sigpred adtr_good with None => True | Some adtrγ =>
        ktcore.is_audit γ.(cfg.agreeγ) adtrγ (uint.nat ep) end)
  }}}.
Proof.
  wp_start as "@". wp_auto.
  wp_apply (auditor.wp_Dial adtr_good) as "* @".
  iNamed "Hclient". iNamed "Hown_lastEp". wp_auto.
  wp_apply auditor.wp_CallGet as "* @".
  { iFrame "#". }
  case_bool_decide as Heq_err; wp_auto;
    rewrite ktcore.rw_Blame0 in Heq_err; subst.
  2: {
    iApply "HΦ".
    iSplitL. { iFrame "∗#%". }
    iSplitL; [|by repeat case_decide].
    iPureIntro.
    eapply ktcore.blame_add_interp; [done|].
    apply map_singleton_subseteq_l.
    by simpl_map. }
  case_decide as Ht; try done. clear Ht.
  iNamed "Herr".

  iNamed "Hown_serv". wp_auto.
  wp_apply wp_checkAuditLink as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameAdtrFull.
    iApply "HΦ".
    iSplitR "Hgood Hgenie". { iFrame "∗#%". }
    iSplitL; [|by repeat case_decide].
    iApply ktcore.blame_one'; [by simpl_map|].
    iIntros (?).
    destruct (auditor.Trust.get_full _); try done.
    iNamed "Hgood".
    iApply "Hgenie".
    rewrite Heq_adtrPk Heq_serv_pk.
    iFrame "#". }
  iNamedSuffix "Hgenie" "_start".
  wp_apply wp_checkAuditLink as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameAdtrFull.
    iApply "HΦ".
    iSplitR "Hgood Hgenie". { iFrame "∗#%". }
    iSplitL; [|by repeat case_decide].
    iApply ktcore.blame_one'; [by simpl_map|].
    iIntros (?).
    destruct (auditor.Trust.get_full _); try done.
    iNamed "Hgood".
    iApply "Hgenie".
    rewrite Heq_adtrPk Heq_serv_pk.
    iFrame "#". }
  iNamedSuffix "Hgenie" "_curr".
  wp_apply wp_checkAuditVrf as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { rewrite ktcore.rw_BlameAdtrFull.
    iApply "HΦ".
    iSplitR "Hgood Hgenie". { iFrame "∗#%". }
    iSplitL; [|by repeat case_decide].
    iApply ktcore.blame_one'; [by simpl_map|].
    iIntros (?).
    destruct (auditor.Trust.get_full _); try done.
    iNamed "Hgood".
    iApply "Hgenie".
    rewrite Heq_adtrPk Heq_serv_pk.
    iFrame "#". }
  iNamed "Hgenie".
  wp_if_destruct.
  { rewrite ktcore.rw_BlameAdtrFull.
    iApply "HΦ".
    iSplitR "Hgood". { iFrame "∗#%". }
    iSplitL; [|by repeat case_decide].
    iApply ktcore.blame_one'; [by simpl_map|].
    iIntros (?).
    destruct (auditor.Trust.get_full _) eqn:Ht; try done.
    erewrite auditor.Trust.full_to_sigpred; [|done].
    clear Ht.
    iNamed "Hwish_SignedLink_curr".
    iDestruct (ktcore.get_link_sigpred with "His_adtrPk Hwish_adtr_sig") as "@".
    iNamed "Hgood".
    word. }
  iClear "Hgood".

  wp_apply cryptoffi.wp_VrfPublicKeyEncode as "* @".
  { iFrame "#". }
  iPersist "Hsl_enc".
  iNamedSuffix "Hown_vrf" "_vrf". wp_auto.
  wp_apply bytes.wp_Equal as "_".
  { iFrame "#". }
  case_bool_decide as Heq_adtr_vrf_pk; wp_auto.
  2: {
    eset (ktcore.Evid.mk'
      (Some (ktcore.EvidVrf.mk'
        γ.(cfg.agreeγ).(ktcore.Agree.vrf_pk) _
        vrf.(auditor.SignedVrf.VrfPk) _))
      None) as evid.
    iAssert (ktcore.wish_Evid evid γ.(cfg.sig_pk))%I as "#His_evid".
    { rewrite /ktcore.wish_Evid /=.
      iNamed "Hwish_SignedVrf".
      by iFrame "#". }
    wp_apply wp_alloc as "%ptr_evid_vrf Hptr_evid_vrf".
    rewrite -wp_fupd.
    wp_apply wp_alloc as "%ptr_evid Hptr_evid".
    iPersist "Hptr_evid_vrf Hptr_evid".
    iModIntro.
    rewrite ktcore.rw_BlameServSig.
    iApply "HΦ".
    iSplitL. { iFrame "∗ Hstr_serv #%". }
    iSplitL. 2: { case_decide; try done. by iFrame "His_evid #". }
    iApply ktcore.blame_one'; [by simpl_map|].
    iIntros (?).
    destruct (server.Trust.get_sigpred _); try done.
    iNamed "Halign_serv_sigpred".
    by iApply ktcore.wish_Evid_sigpred. }

  iNamedSuffix "Hown_currLink" "_link". wp_auto.
  wp_apply bytes.wp_Equal as "_".
  { iFrame "#". }
  case_bool_decide as Heq_adtr_link; wp_auto.
  2: {
    eset (ktcore.Evid.mk'
      None
      (Some (ktcore.EvidLink.mk' _
        lastEp.(epoch.link) _
        currLink.(auditor.SignedLink.Link) _))
      ) as evid.
    iAssert (ktcore.wish_Evid evid γ.(cfg.sig_pk))%I as "#His_evid".
    { rewrite /ktcore.wish_Evid /=.
      iNamed "His_lastEp".
      iNamed "Hwish_SignedLink_curr".
      by iFrame "#". }
    wp_apply wp_alloc as "%ptr_evid_link Hptr_evid_link".
    rewrite -wp_fupd.
    wp_apply wp_alloc as "%ptr_evid Hptr_evid".
    iPersist "Hptr_evid_link Hptr_evid".
    iModIntro.
    rewrite ktcore.rw_BlameServSig.
    iApply "HΦ".
    iSplitL. { iFrame "∗ Hstr_serv #%". }
    iSplitL. 2: { case_decide; try done. by iFrame "His_evid #". }
    iApply ktcore.blame_one'; [by simpl_map|].
    iIntros (?).
    destruct (server.Trust.get_sigpred _); try done.
    iNamed "Halign_serv_sigpred".
    by iApply ktcore.wish_Evid_sigpred. }

  iApply "HΦ".
  rewrite /own. iNamed "Hown_gs".
  iDestruct (mono_list_lb_own_get with "Hown_digs") as "#Hcli_digs".
  iSplitL. { iFrame "∗ Hstr_serv His_nextVer #%". }
  iSplitL. { iPureIntro. apply ktcore.blame_none. }
  iSplitL. { by case_decide. }
  case_decide as Ht; try done. clear Ht.
  repeat iSplitL.
  - word.
  - destruct (auditor.Trust.get_sigpred _); try done.
    iNamed "Hwish_SignedLink_start".
    iDestruct (ktcore.get_link_sigpred with "His_adtrPk Hwish_adtr_sig") as "@".
    word.
  - iNamed "His_lastEp". word.
  - destruct (auditor.Trust.get_sigpred _); try done.
    iFrame "#".
    iNamedSuffix "Hwish_SignedVrf" "_vrf".
    iDestruct (ktcore.get_vrf_sigpred with "His_adtrPk Hwish_adtr_sig_vrf") as "H".
    rewrite /vrfP. iNamed "H".
    iNamedSuffix "Hwish_SignedLink_curr" "_link".
    iDestruct (ktcore.get_link_sigpred with "His_adtrPk Hwish_adtr_sig_link") as "@".
    iNamed "His_lastEp".
    rewrite -Heq_adtr_link in Hinv.
    replace (_ + _)%nat with (S (uint.nat lastEp.(epoch.epoch))) in His_chain by word.
    opose proof (hashchain.inj His_chain Hinv) as [<- _].
    iFrame "#%".
    iPureIntro. split; [congruence|word].
Qed.

End proof.
End client.
