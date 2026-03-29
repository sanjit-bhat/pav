From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi cryptoutil hashchain merkle safemarshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  key_map serde sigpred.

Module ktcore.
Import key_map.ktcore serde.ktcore sigpred.ktcore.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition wish_VrfSig sig_pk vrf_pk sig : iProp Σ :=
  let obj := VrfSig.mk' (W8 VrfSigTag) vrf_pk in
  let enc := VrfSig.pure_enc obj in
  "#His_sig" ∷ cryptoffi.is_sig sig_pk enc sig ∗
  "%Hvalid" ∷ ⌜VrfSig.valid obj⌝.

Lemma wp_SignVrf ptr_sk pk γ sl_vrfPk vrfPk :
  {{{
    is_pkg_init ktcore ∗
    "#Hown_sig_sk" ∷ cryptoffi.own_sig_sk ptr_sk pk (sigpred.P γ) ∗
    "#Hsl_vrfPk" ∷ sl_vrfPk ↦*□ vrfPk ∗
    "#Hsigpred" ∷ sigpred.vrfP γ vrfPk
  }}}
  @! ktcore.SignVrf #ptr_sk #sl_vrfPk
  {{{
    sl_vrfSig vrfSig, RET #sl_vrfSig;
    "#Hsl_vrfSig" ∷ sl_vrfSig ↦*□ vrfSig ∗
    "#Hwish_VrfSig" ∷ wish_VrfSig pk vrfPk vrfSig
  }}}.
Proof.
  simpl. wp_start as "@". wp_auto.
  wp_apply wp_slice_make3 as "* (Hsl_b&Hcap_b&_)"; [word|].
  wp_apply wp_alloc as "* Hstruct".
  iPersist "Hstruct".
  wp_apply (VrfSig.wp_enc (VrfSig.mk' _ _) with "[$Hsl_b $Hcap_b]")
    as "* (Hsl_b&Hcap_b&_&(_&%Hvalid))".
  { iFrame "#". }
  simpl in *.
  iDestruct (own_slice_len with "Hsl_vrfPk") as %[? ?].
  rewrite -wp_fupd.
  wp_apply (cryptoffi.wp_SigPrivateKey_Sign with "[$Hown_sig_sk $Hsl_b]") as "* @".
  { iFrame "#".
    iLeft.
    iSplit; [done|].
    rewrite /safemarshal.Slice1D.valid. word. }
  iPersist "Hsl_sig".
  iModIntro.
  iApply "HΦ".
  by iFrame "∗#".
Qed.

Lemma wp_VerifyVrfSig sl_pk pk sl_vrfPk vrfPk sl_sig sig :
  {{{
    is_pkg_init ktcore ∗
    "#Hsl_pk" ∷ sl_pk ↦*□ pk ∗
    "#Hsl_vrfPk" ∷ sl_vrfPk ↦*□ vrfPk ∗
    "#Hsl_sig" ∷ sl_sig ↦*□ sig
  }}}
  @! ktcore.VerifyVrfSig #sl_pk #sl_vrfPk #sl_sig
  {{{
    (err : bool), RET #err;
    "Hgenie" ∷
      match err with
      | true => ¬ wish_VrfSig pk vrfPk sig
      | false =>
        "#Hwish_VrfSig" ∷ wish_VrfSig pk vrfPk sig
      end
  }}}.
Proof.
  wp_start as "@". wp_auto.
  wp_apply wp_slice_make3 as "* (Hsl_b&Hcap_b&_)"; [word|].
  wp_apply wp_alloc as "* Hstruct".
  iPersist "Hstruct".
  replace (sint.nat _) with (0%nat) by word.
  wp_apply (VrfSig.wp_enc (VrfSig.mk' _ _) with "[$Hsl_b $Hcap_b]")
    as "* (Hsl_b&Hcap_b&_&(_&%Hvalid))".
  { iFrame "#". }
  simpl in *.
  wp_apply (cryptoffi.wp_SigPublicKey_Verify with "[$pk Hsl_b]") as "* H".
  { iFrame "∗#". }
  iNamedSuffix "H" "0".
  iApply "HΦ".
  destruct err.
  - iIntros "@". by iApply "Hgenie0".
  - by iFrame.
Qed.

Definition wish_LinkSig sig_pk ep link sig : iProp Σ :=
  let obj := LinkSig.mk' (W8 LinkSigTag) ep link in
  let enc := LinkSig.pure_enc obj in
  "#His_sig" ∷ cryptoffi.is_sig sig_pk enc sig ∗
  "%Hvalid" ∷ ⌜LinkSig.valid obj⌝.

Lemma wp_SignLink ptr_sk pk γ epoch sl_link link :
  {{{
    is_pkg_init ktcore ∗
    "#Hown_sig_sk" ∷ cryptoffi.own_sig_sk ptr_sk pk (sigpred.P γ) ∗
    "#Hsl_link" ∷ sl_link ↦*□ link ∗
    "#Hsigpred" ∷ sigpred.linkP γ epoch link
  }}}
  @! ktcore.SignLink #ptr_sk #epoch #sl_link
  {{{
    sl_linkSig linkSig, RET #sl_linkSig;
    "#Hsl_linkSig" ∷ sl_linkSig ↦*□ linkSig ∗
    "#Hwish_LinkSig" ∷ wish_LinkSig pk epoch link linkSig
  }}}.
Proof.
  simpl. wp_start as "@". wp_auto.
  wp_apply wp_slice_make3 as "* (Hsl_b&Hcap_b&_)"; [word|].
  wp_apply wp_alloc as "* Hstruct".
  iPersist "Hstruct".
  wp_apply (LinkSig.wp_enc (LinkSig.mk' _ _ _) with "[$Hsl_b $Hcap_b]")
    as "* (Hsl_b&Hcap_b&_&(_&%Hvalid))".
  { iFrame "#". }
  simpl in *.
  iDestruct (own_slice_len with "Hsl_link") as %[? ?].
  rewrite -wp_fupd.
  wp_apply (cryptoffi.wp_SigPrivateKey_Sign with "[$Hown_sig_sk $Hsl_b]") as "* @".
  { iFrame "#".
    iRight. repeat iExists _.
    iSplit; [done|].
    rewrite /safemarshal.Slice1D.valid. word. }
  iPersist "Hsl_sig".
  iModIntro.
  iApply "HΦ".
  by iFrame "∗#".
Qed.

Lemma wp_VerifyLinkSig sl_pk pk epoch sl_link link sl_sig sig :
  {{{
    is_pkg_init ktcore ∗
    "#Hsl_pk" ∷ sl_pk ↦*□ pk ∗
    "#Hsl_link" ∷ sl_link ↦*□ link ∗
    "#Hsl_sig" ∷ sl_sig ↦*□ sig
  }}}
  @! ktcore.VerifyLinkSig #sl_pk #epoch #sl_link #sl_sig
  {{{
    (err : bool), RET #err;
    "Hgenie" ∷
      match err with
      | true => ¬ wish_LinkSig pk epoch link sig
      | false =>
        "#Hwish_LinkSig" ∷ wish_LinkSig pk epoch link sig
      end
  }}}.
Proof.
  wp_start as "@". wp_auto.
  wp_apply wp_slice_make3 as "* (Hsl_b&Hcap_b&_)"; [word|].
  wp_apply wp_alloc as "* Hstruct".
  iPersist "Hstruct".
  replace (sint.nat _) with (0%nat) by word.
  wp_apply (LinkSig.wp_enc (LinkSig.mk' _ _ _) with "[$Hsl_b $Hcap_b]")
    as "* (Hsl_b&Hcap_b&_&(_&%Hvalid))".
  { iFrame "#". }
  simpl in *.
  wp_apply (cryptoffi.wp_SigPublicKey_Verify with "[$pk Hsl_b]") as "* H".
  { iFrame "∗#". }
  iNamedSuffix "H" "0".
  iApply "HΦ".
  destruct err.
  - iIntros "@". by iApply "Hgenie0".
  - by iFrame.
Qed.

Definition is_MapLabelProof vrf_pk uid ver proof : iProp Σ :=
  let enc := MapLabel.pure_enc (MapLabel.mk' uid ver) in
  cryptoffi.is_vrf_proof vrf_pk enc proof.

Lemma wp_ProveMapLabel ptr_sk pk (uid ver : w64) :
  {{{
    is_pkg_init ktcore ∗
    "#Hown_vrf_sk" ∷ cryptoffi.own_vrf_sk ptr_sk pk
  }}}
  @! ktcore.ProveMapLabel #ptr_sk #uid #ver
  {{{
    sl_label label sl_proof proof, RET (#sl_label, #sl_proof);
    "#Hsl_label" ∷ sl_label ↦*□ label ∗
    "#Hsl_proof" ∷ sl_proof ↦*□ proof ∗
    "%His_Label" ∷ ⌜map_label_fn pk uid (uint.nat ver) label⌝ ∗
    "#His_LabelProof" ∷ is_MapLabelProof pk uid ver proof
  }}}.
Proof.
  wp_start as "@". wp_auto.
  wp_apply wp_slice_make3 as "* (Hsl_b&Hcap_b&_)"; [word|].
  wp_apply wp_alloc as "* Hstruct".
  iPersist "Hstruct".
  replace (sint.nat _) with (0%nat) by word.
  wp_apply (MapLabel.wp_enc (MapLabel.mk' _ _) with "[$Hsl_b $Hcap_b]")
    as "* (Hsl_b&Hcap_b&_)".
  { iFrame "#". }
  simpl in *.
  rewrite -wp_fupd.
  wp_apply (cryptoffi.wp_VrfPrivateKey_Prove with "[$Hsl_b]") as "* @".
  { iFrame "#". }
  iPersist "Hsl_out Hsl_proof".
  iModIntro.
  iApply "HΦ".
  rewrite /map_label_fn.
  replace (W64 (uint.nat _)) with ver by word.
  by iFrame "∗#".
Qed.

Lemma wp_EvalMapLabel ptr_sk pk (uid ver : w64) :
  {{{
    is_pkg_init ktcore ∗
    "#Hown_vrf_sk" ∷ cryptoffi.own_vrf_sk ptr_sk pk
  }}}
  @! ktcore.EvalMapLabel #ptr_sk #uid #ver
  {{{
    sl_label label, RET #sl_label;
    "#Hsl_label" ∷ sl_label ↦*□ label ∗
    "%His_Label" ∷ ⌜map_label_fn pk uid (uint.nat ver) label⌝
  }}}.
Proof.
  wp_start as "@". wp_auto.
  wp_apply wp_slice_make3 as "* (Hsl_b&Hcap_b&_)"; [word|].
  wp_apply wp_alloc as "* Hstruct".
  iPersist "Hstruct".
  replace (sint.nat _) with (0%nat) by word.
  wp_apply (MapLabel.wp_enc (MapLabel.mk' _ _) with "[$Hsl_b $Hcap_b]")
    as "* (Hsl_b&Hcap_b&_)".
  { iFrame "#". }
  simpl in *.
  rewrite -wp_fupd.
  wp_apply (cryptoffi.wp_VrfPrivateKey_Evaluate with "[$Hsl_b]") as "* @".
  { iFrame "#". }
  iPersist "Hsl_out".
  iModIntro.
  iApply "HΦ".
  rewrite /map_label_fn.
  replace (W64 (uint.nat _)) with ver by word.
  by iFrame "∗#".
Qed.

Lemma wp_CheckMapLabel ptr_pk pk (uid ver : w64) sl_proof proof :
  {{{
    is_pkg_init ktcore ∗
    "#Hown_vrf_pk" ∷ cryptoffi.own_vrf_pk ptr_pk pk ∗
    "#Hsl_proof" ∷ sl_proof ↦*□ proof
  }}}
  @! ktcore.CheckMapLabel #ptr_pk #uid #ver #sl_proof
  {{{
    sl_label label (err : bool), RET (#sl_label, #err);
    "#Hsl_label" ∷ sl_label ↦*□ label ∗
    "Hgenie" ∷
      match err with
      | true => ¬ is_MapLabelProof pk uid ver proof
      | false =>
        "%His_Label" ∷ ⌜map_label_fn pk uid (uint.nat ver) label⌝ ∗
        "#His_LabelProof" ∷ is_MapLabelProof pk uid ver proof
      end
  }}}.
Proof.
  wp_start as "@". wp_auto.
  wp_apply wp_slice_make3 as "* (Hsl_b&Hcap_b&_)"; [word|].
  wp_apply wp_alloc as "* Hstruct".
  iPersist "Hstruct".
  replace (sint.nat _) with (0%nat) by word.
  wp_apply (MapLabel.wp_enc (MapLabel.mk' _ _) with "[$Hsl_b $Hcap_b]")
    as "* (Hsl_b&Hcap_b&_)".
  { iFrame "#". }
  simpl in *.
  rewrite -wp_fupd.
  wp_apply (cryptoffi.wp_VrfPublicKey_Verify with "[$Hsl_b]") as "* H".
  { iFrame "#". }
  iNamedSuffix "H" "0".
  iPersist "Hsl_out0 Hsl_proof0".
  iModIntro.
  iApply "HΦ".
  iFrame "#".
  case_match; [iFrame|].
  iNamed "Hgenie0".
  rewrite /map_label_fn.
  replace (W64 (uint.nat _)) with ver by word.
  by iFrame "#".
Qed.

Lemma wp_GetMapVal sl_pk pk sl_rand rand :
  {{{
    is_pkg_init ktcore ∗
    "#Hsl_pk" ∷ sl_pk ↦*□ pk ∗
    "#Hsl_rand" ∷ sl_rand ↦*□ rand
  }}}
  @! ktcore.GetMapVal #sl_pk #sl_rand
  {{{
    sl_mapVal mapVal, RET #sl_mapVal;
    "#Hsl_mapVal" ∷ sl_mapVal ↦*□ mapVal ∗
    "%His_MapVal" ∷ ⌜map_val_fn pk rand mapVal⌝
  }}}.
Proof.
  wp_start as "@". wp_auto.
  wp_apply wp_slice_make3 as "* (Hsl_b&Hcap_b&_)"; [word|].
  wp_apply wp_alloc as "* Hstruct".
  iPersist "Hstruct".
  replace (sint.nat _) with (0%nat) by word.
  wp_apply (CommitOpen.wp_enc (CommitOpen.mk' _ _) with "[$Hsl_b $Hcap_b]")
    as "* (Hsl_b&Hcap_b&_&%Hwish)".
  { iFrame "#". }
  simpl in *.
  rewrite -wp_fupd.
  wp_apply (cryptoutil.wp_Hash with "[$Hsl_b]") as "* @".
  iPersist "Hsl_hash".
  iModIntro.
  iApply "HΦ".
  destruct Hwish as (_&?).
  by iFrame "∗#".
Qed.

Definition is_CommitRand commit_secret label rand :=
  let enc := commit_secret ++ label in
  cryptoffi.hash_fn enc = Some rand.

Lemma is_CommitRand_det {commit_secret label rand0 rand1} :
  is_CommitRand commit_secret label rand0 →
  is_CommitRand commit_secret label rand1 →
  rand0 = rand1.
Proof. rewrite /is_CommitRand. intros. by simplify_eq/=. Qed.

Lemma wp_GetCommitRand sl_commitSecret commitSecret sl_label label :
  {{{
    is_pkg_init ktcore ∗
    "#Hsl_commitSecret" ∷ sl_commitSecret ↦*□ commitSecret ∗
    "#Hsl_label" ∷ sl_label ↦*□ label
  }}}
  @! ktcore.GetCommitRand #sl_commitSecret #sl_label
  {{{
    sl_rand rand, RET #sl_rand;
    "#Hsl_rand" ∷ sl_rand ↦*□ rand ∗
    "%His_CommitRand" ∷ ⌜is_CommitRand commitSecret label rand⌝
  }}}.
Proof.
  wp_start as "@". wp_auto.
  wp_apply cryptoffi.wp_NewHasher as "* @".
  wp_apply (cryptoffi.wp_Hasher_Write with "[$Hown_hr]") as "H".
  { iFrame "#". }
  iNamedSuffix "H" "0".
  wp_apply (cryptoffi.wp_Hasher_Write with "[$Hown_hr0]") as "H".
  { iFrame "#". }
  iNamedSuffix "H" "1".
  rewrite -wp_fupd.
  wp_apply (cryptoffi.wp_Hasher_Sum with "[$Hown_hr1]") as "* @".
  { iDestruct own_slice_nil as "$". }
  iPersist "Hsl_b_out".
  iModIntro.
  simpl.
  iApply "HΦ".
  by iFrame "∗#".
Qed.

Definition wish_Memb vrf_pk uid ver dig memb : iProp Σ :=
  ∃ label mapVal,
  let open := memb.(ktcore.Memb.PkOpen) in
  "%His_Label" ∷ ⌜map_label_fn vrf_pk uid ver label⌝ ∗
  "#His_LabelProof" ∷ is_MapLabelProof vrf_pk uid (W64 ver) memb.(ktcore.Memb.LabelProof) ∗
  "%His_MapVal" ∷ ⌜map_val_fn open.(CommitOpen.Val) open.(CommitOpen.Rand) mapVal⌝ ∗
  "#Hwish_memb" ∷ merkle.wish_Memb label mapVal memb.(ktcore.Memb.MerkleProof) dig.

Definition wish_ListMemb vrf_pk uid (prefixLen : nat) dig hist : iProp Σ :=
  ([∗ list] ver ↦ memb ∈ hist,
    wish_Memb vrf_pk uid (prefixLen + ver)%nat dig memb).

Definition wish_NonMemb vrf_pk uid ver dig nonMemb : iProp Σ :=
  ∃ label,
  "%His_Label" ∷ ⌜map_label_fn vrf_pk uid ver label⌝ ∗
  "#His_LabelProof" ∷ is_MapLabelProof vrf_pk uid (W64 ver) nonMemb.(ktcore.NonMemb.LabelProof) ∗
  "#Hwish_nonMemb" ∷ merkle.wish_NonMemb label nonMemb.(ktcore.NonMemb.MerkleProof) dig.

Definition wish_ListUpdate_aux prevDig updates digs : iProp Σ :=
  "%Hlen" ∷ ⌜length digs = S (length updates)⌝ ∗
  "%Hhead" ∷ ⌜head digs = Some prevDig⌝ ∗
  "#Hwish_upds" ∷ ([∗ list] i ↦ upd ∈ updates,
    ∃ dig0 dig1,
    "%Hlook0" ∷ ⌜digs !! i = Some dig0⌝ ∗
    "%Hlook1" ∷ ⌜digs !! (S i) = Some dig1⌝ ∗
    "#Hwish_upd" ∷ merkle.wish_Update upd.(ktcore.UpdateProof.MapLabel)
      upd.(ktcore.UpdateProof.MapVal) upd.(ktcore.UpdateProof.NonMembProof)
      dig0 dig1).

Lemma wish_ListUpdate_aux_det prevDig updates digs0 digs1 :
  wish_ListUpdate_aux prevDig updates digs0 -∗
  wish_ListUpdate_aux prevDig updates digs1 -∗
  ⌜digs0 = digs1⌝.
Proof.
  iNamedSuffix 1 "0".
  iNamedSuffix 1 "1".
  (* pointwise-equality suffices since merkle.UpdateProof's det give hashes. *)
  (* no way to apply [list_eq_same_length] directly. *)
  iAssert (⌜∀ (i : nat) x y,
    digs0 !! i = Some x → digs1 !! i = Some y → x = y⌝)%I as %?.
  2: { iPureIntro. eapply list_eq_same_length; [done..|]. naive_solver. }
  iIntros (i ?? Hlook0 Hlook1).
  apply lookup_lt_Some in Hlook0 as ?.
  destruct i.
  { iPureIntro.
    rewrite !head_lookup in Hhead0, Hhead1.
    by simplify_eq/=. }
  list_elem updates i as upd.
  iDestruct (big_sepL_lookup with "Hwish_upds0") as "H0"; [done|].
  iDestruct (big_sepL_lookup with "Hwish_upds1") as "H1"; [done|].
  iNamedSuffix "H0" "0".
  iNamedSuffix "H1" "1".
  simplify_eq/=.
  by iDestruct (merkle.wish_Update_det with "Hwish_upd0 Hwish_upd1") as %[-> ->].
Qed.

Lemma wish_ListUpdate_aux_take n prevDig updates digs :
  wish_ListUpdate_aux prevDig updates digs -∗
  wish_ListUpdate_aux prevDig (take n updates) (take (S n) digs).
Proof.
  iNamed 1.
  repeat iSplit; try iPureIntro; [len|by destruct digs|].
  iApply big_sepL_forall.
  iIntros (?? Hlook).
  apply lookup_take_Some in Hlook as [Hlook ?].
  iDestruct (big_sepL_lookup with "Hwish_upds") as "@"; [done|].
  rewrite lookup_take_lt; [|word].
  rewrite lookup_take_lt; [|word].
  iFrame "#%".
Qed.

Definition wish_ListUpdate prevDig updates nextDig : iProp Σ :=
  ∃ digs,
  "#Hwish_aux" ∷ wish_ListUpdate_aux prevDig updates digs ∗
  "%Hlast" ∷ ⌜last digs = Some nextDig⌝.

Lemma wish_ListUpdate_det prevDig updates nextDig0 nextDig1 :
  wish_ListUpdate prevDig updates nextDig0 -∗
  wish_ListUpdate prevDig updates nextDig1 -∗
  ⌜nextDig0 = nextDig1⌝.
Proof.
  iNamedSuffix 1 "0".
  iNamedSuffix 1 "1".
  iDestruct (wish_ListUpdate_aux_det with "Hwish_aux0 Hwish_aux1") as %->.
  rewrite Hlast0 in Hlast1.
  by simplify_eq/=.
Qed.

Lemma wish_ListUpdate_nil dig :
  ⊢ wish_ListUpdate dig [] dig.
Proof.
  rewrite /wish_ListUpdate /wish_ListUpdate_aux.
  iIntros. iExists [dig].
  iSplit; [|done].
  naive_solver.
Qed.

Lemma wish_ListUpdate_grow dig0 dig1 dig2 updates map_label map_val proof :
  wish_ListUpdate dig0 updates dig1 -∗
  merkle.wish_Update map_label map_val proof dig1 dig2 -∗
  wish_ListUpdate dig0 (updates ++ [UpdateProof.mk' map_label map_val proof]) dig2.
Proof.
  iIntros "@ #Hupd". iNamed "Hwish_aux".
  iExists (digs ++ [dig2]).
  repeat iSplit; try done; try iPureIntro.
  - len.
  - by rewrite head_app Hhead.
  - iApply big_sepL_forall.
    iIntros (?? Hlook).
    apply lookup_lt_Some in Hlook as ?.
    rewrite lookup_app_l; [|word].
    rewrite lookup_app_l; [|word].
    iDestruct (big_sepL_lookup with "Hwish_upds") as "@"; [done|].
    iFrame "#%".
  - iFrame "#". iPureIntro. split.
    + rewrite lookup_app_l; [|word].
      rewrite last_lookup in Hlast.
      rewrite -Hlast.
      f_equal. word.
    + rewrite lookup_app_r; [|word].
      rewrite list_lookup_singleton_Some.
      split; [word|done].
  - by rewrite last_snoc.
Qed.

End proof.
End ktcore.
