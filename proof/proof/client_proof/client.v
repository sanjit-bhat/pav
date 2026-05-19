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

Lemma wp_checkHist ptr_pk pk (uid prefixLen : w64) sl_dig dig sl_hist sl0_hist hist :
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
  @! client.checkHist #ptr_pk #uid #prefixLen #sl_dig #sl_hist
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

Lemma wp_Client_Put γ ptr_c σ sl_pk pk :
  {{{
    is_pkg_init client ∗
    "Hclient" ∷ Client.own γ ptr_c σ ∗
    "#Hsl_pk" ∷ sl_pk ↦*□ pk ∗
    "%Heq_pend" ∷
      ⌜match σ.(state.pending_pk) with
      | None => True
      | Some pk' => pk = pk'
      end⌝
  }}}
  ptr_c @! (go.PointerType client.Client) @! "Put" #sl_pk
  {{{
    RET #();
    let σ' := set state.pending_pk (λ _, Some pk) σ in
    "Hclient" ∷ Client.own γ ptr_c σ'
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hclient". iNamed "Hown_pend". iNamed "Hown_serv".
  destruct γ, σ. simpl in *.
  wp_auto. simpl.
  iPersist "c pk".
  wp_bind (If _ _ _).
  wp_apply (wp_wand _ _ _
    (λ v,
    ∃ sl_pendingPk',
    "->" ∷ ⌜v = execute_val⌝ ∗
    "Hstr_client" ∷ ptr_c ↦ {|
                          client.Client.uid' := uid;
                          client.Client.pend' := ptr_pend;
                          client.Client.last' := ptr_last;
                          client.Client.serv' := ptr_serv
                        |} ∗
    "Hstr_nextVer" ∷ ptr_pend ↦ {|
                              client.nextVer.ver' := w_ver;
                              client.nextVer.isPending' := true;
                              client.nextVer.pendingPk' := sl_pendingPk'
                            |} ∗
    "#Hsl_pendingPk'" ∷ sl_pendingPk' ↦*□ pk
    )%I
    with "[Hstr_client Hstr_nextVer]"
  ) as "* @".
  { wp_if_destruct.
    - destruct pending_pk; iNamed "HpendingPk"; try done.
      simplify_eq/=.
      wp_apply bytes.wp_Equal as "_".
      { iFrame "#". }
      wp_apply std.wp_Assert.
      { by case_bool_decide. }
      by iFrame "∗#".
    - by iFrame "∗#". }

  destruct serv_good; iNamed "Halign_pend_pend".
  2: {
    wp_apply server.wp_CallPut.
    { iFrame "#". }
    iApply "HΦ".
    by iFrame "∗ Hstr_serv #%". }
  simpl in *. destruct clis_good; iNamed "HgoodCli".
  - iMod (mono_list_auth_own_update_app [(pend.(nextVer.ver), pk)]
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
    iMod (mono_list_auth_own_update_app [(pend.(nextVer.ver), pk)]
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
        "%Heq_ep" ∷ ⌜uint.Z ep = start_epγ γ + length σ'.(state.digs) - 1⌝ ∗
        "#Hopt_pk" ∷
          match opt_pk with
          | None => "->" ∷ ⌜is_reg = false⌝
          | Some pk =>
            "->" ∷ ⌜is_reg = true⌝ ∗
            "#Hsl_pk" ∷ sl_pk ↦*□ pk
          end ∗
        "#Hptr_kt" ∷ γ.(cfg.sigγ) ↪KT[uint.nat ep, uid] opt_pk)
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
  wp_apply wp_checkHist as "* @".
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
        let σ0 := set state.digs (.++ new_digs) σ in
        let new_keys_len := (length σ0.(state.digs) - audit_offsetγ γ -
          length σ.(state.keys))%nat in
        "%Heq_ep" ∷ ⌜uint.Z ep = start_epγ γ + length σ0.(state.digs) - 1⌝ ∗
        "%Hprev_key" ∷ ⌜last σ.(state.keys) = Some prev_key⌝ ∗
        "Hchanged" ∷
          match isChanged with
          | false =>
            let σ1 := set state.keys (.++ replicate new_keys_len prev_key) σ0 in
            "Hclient" ∷ Client.own γ ptr_c σ1 ∗
            "#His_staged" ∷ ktcore.is_staged_keys γ.(cfg.sigγ) γ.(cfg.uid) σ1.(state.keys)
          | true =>
            ∃ (num_prev_keys : nat),
            let num_next_keys := (new_keys_len - num_prev_keys)%nat in
            let σ1 :=
              set state.keys
                (.++ replicate num_prev_keys prev_key ++
                  replicate num_next_keys σ.(state.pending_pk))
              (set state.pending_pk (λ _, None) σ0) in
            "Hclient" ∷ Client.own γ ptr_c σ1 ∗
            "#His_staged" ∷ ktcore.is_staged_keys γ.(cfg.sigγ) γ.(cfg.uid) σ1.(state.keys) ∗
            "%Hpend" ∷ ⌜is_Some σ.(state.pending_pk)⌝ ∗
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
  wp_apply wp_checkHist as "* @".
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
