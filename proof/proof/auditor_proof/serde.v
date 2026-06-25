From New.generatedproof.github_com.sanjit_bhat.pav Require Import auditor.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import safemarshal.
From New.proof.github_com.tchajed Require Import marshal.

From New.proof.github_com.sanjit_bhat.pav.auditor_proof Require Import base.

Module auditor.

Section dfrac_valid.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

(* A non-empty byte slice owns at least one element heap-pointsto, from which
   the dfrac's validity follows. Copied from ktcore_proof/serde.v. *)
Lemma own_slice_dfrac_valid (s : slice.t) (vs : list w8) dq :
  0 < length vs →
  s ↦*{dq} vs -∗ ⌜✓ dq⌝.
Proof.
  iIntros (Hlen) "Hsl".
  destruct vs as [|v vs']; [simpl in Hlen; lia|].
  iDestruct (own_slice_elem_acc 0 with "Hsl") as "[Helem _]"; [done|done|].
  iEval (rewrite typed_pointsto_unseal_eq) in "Helem".
  iDestruct "Helem" as "[Hdef _]".
  iApply (heap_pointsto_valid with "Hdef").
Qed.
End dfrac_valid.

Module GetArg.
Record t :=
  mk' {
    Epoch: w64;
  }.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc obj.(Epoch).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /safemarshal.w64.pure_enc.
  intros -> Heq.
  apply app_inj_1 in Heq as [Hep Htail]; [|len].
  apply (inj u64_le) in Hep.
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  "Hstruct" ∷ ptr ↦{d} (auditor.GetArg.mk obj.(Epoch)).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init auditor ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! auditor.GetArgEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as "Hstruct". wp_auto.
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -?app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init auditor ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! auditor.GetArgDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj tail, ⌜wish b obj tail⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj d ∗
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof.
  wp_start as "Hsl_b". wp_auto.
  destruct b as [|b0 brest].
  - wp_apply (safemarshal.w64.wp_dec with "[$Hsl_b]").
    iIntros (ep b1 err1) "Hpost1".
    destruct err1.
    + wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      rewrite /wish /pure_enc /safemarshal.w64.pure_enc in Hwish.
      iExFalso. iPureIntro. apply (f_equal length) in Hwish.
      rewrite !length_app u64_le_length /= in Hwish. lia.
    + iDestruct "Hpost1" as (rem1) "[Hb1 %Hw64a]".
      rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc in Hw64a.
      iExFalso. iPureIntro. apply (f_equal length) in Hw64a.
      rewrite /= length_app u64_le_length in Hw64a. lia.
  - iDestruct (own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (safemarshal.w64.wp_dec with "[$Hsl_b]").
    iIntros (ep b1 err1) "Hpost1".
    destruct err1.
    + (* Epoch read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      iApply "Hpost1". iExists obj.(Epoch), _. iPureIntro.
      rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc.
      rewrite /wish /pure_enc /safemarshal.w64.pure_enc in Hwish.
      rewrite -?app_assoc in Hwish. exact Hwish.
    + iDestruct "Hpost1" as (rem1) "[Hb1 %Hw64a]".
      rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc in Hw64a.
      wp_auto.
      wp_alloc l as "Hptr".
      iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
      wp_auto.
      iApply "HΦ". iExists (GetArg.mk' ep), rem1.
      rewrite /own. iFrame "Hptr Hb1".
      iPureIntro. rewrite /wish /pure_enc /safemarshal.w64.pure_enc.
      rewrite Hw64a -?app_assoc. done.
Qed.

End proof.
End GetArg.

Module SignedLink.
Record t :=
  mk' {
    Link: list w8;
    ServSig: list w8;
    AdtrSig: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.Slice1D.pure_enc obj.(Link) ++
  safemarshal.Slice1D.pure_enc obj.(ServSig) ++
  safemarshal.Slice1D.pure_enc obj.(AdtrSig).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(Link) ∧
  safemarshal.Slice1D.valid obj.(ServSig) ∧
  safemarshal.Slice1D.valid obj.(AdtrSig).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid
    /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc
    /safemarshal.Slice1D.valid.
  intros (-> & Hv0a & Hv0b & Hv0c) (Heq & Hv1a & Hv1b & Hv1c).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Hp1 Heq]; [|len].
  apply (inj u64_le) in Hp1.
  assert (length obj0.(Link) = length obj1.(Link)) by word.
  apply app_inj_1 in Heq as [Hlink Heq]; [|done].
  apply app_inj_1 in Heq as [Hp2 Heq]; [|len].
  apply (inj u64_le) in Hp2.
  assert (length obj0.(ServSig) = length obj1.(ServSig)) by word.
  apply app_inj_1 in Heq as [Hserv Heq]; [|done].
  apply app_inj_1 in Heq as [Hp3 Heq]; [|len].
  apply (inj u64_le) in Hp3.
  assert (length obj0.(AdtrSig) = length obj1.(AdtrSig)) by word.
  apply app_inj_1 in Heq as [Hadtr Htail]; [|done].
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_Link sl_ServSig sl_AdtrSig,
  "Hstruct" ∷ ptr ↦{d} (auditor.SignedLink.mk sl_Link sl_ServSig sl_AdtrSig) ∗

  "Hsl_Link" ∷ sl_Link ↦*{d} obj.(Link) ∗
  "Hsl_ServSig" ∷ sl_ServSig ↦*{d} obj.(ServSig) ∗
  "Hsl_AdtrSig" ∷ sl_AdtrSig ↦*{d} obj.(AdtrSig).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init auditor ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! auditor.SignedLinkEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_Link sl_ServSig sl_AdtrSig) "(Hstruct & Hsl_Link & Hsl_ServSig & Hsl_AdtrSig)". wp_auto.
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_Link]") as "* (Hsl_b & Hcap_b & Hsl_Link)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_ServSig]") as "* (Hsl_b & Hcap_b & Hsl_ServSig)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_AdtrSig]") as "* (Hsl_b & Hcap_b & Hsl_AdtrSig)".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -!app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init auditor ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! auditor.SignedLinkDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj tail, ⌜wish b obj tail⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj d ∗
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof.
  wp_start as "Hsl_b". wp_auto.
  destruct b as [|b0 brest].
  - wp_apply (safemarshal.Slice1D.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc _]. iExFalso. iPureIntro.
      rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
    + iDestruct "Hpost1" as (lp0 rem1) "(Ha1 & Hb1 & %Hsl1a)".
      destruct Hsl1a as [Henc _]. iExFalso. iPureIntro.
      rewrite /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
  - iDestruct (own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (safemarshal.Slice1D.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + (* Link read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
      destruct Hvalid as [HvLink _]. iApply "Hpost1".
      iExists obj.(Link), _. iPureIntro.
      rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc
        -?app_assoc. split; [|exact HvLink].
      rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      rewrite -?app_assoc in Henc. exact Henc.
    + iDestruct "Hpost1" as (lk0 rem1) "(Ha1 & Hb1 & %Hsl1a)".
      wp_auto.
      wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb1]").
      iIntros (a2 b2 err2) "Hpost2". destruct err2.
      * (* ServSig read failed *)
        wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
        destruct Hvalid as [HvLink [HvServ _]]. iApply "Hpost2".
        iExists obj.(ServSig), (safemarshal.Slice1D.pure_enc obj.(AdtrSig) ++ tail). iPureIntro.
        assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(Link)
                  (safemarshal.Slice1D.pure_enc obj.(ServSig)
                   ++ safemarshal.Slice1D.pure_enc obj.(AdtrSig) ++ tail)) as Hw1.
        { rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
            /safemarshal.w64.pure_enc -?app_assoc. split; [|exact HvLink].
          rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
          rewrite -?app_assoc in Henc. exact Henc. }
        destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
        split; [exact Hrem1|exact HvServ].
      * iDestruct "Hpost2" as (sv0 rem2) "(Ha2 & Hb2 & %Hsl1b)".
        wp_auto.
        wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb2]").
        iIntros (a3 b3 err3) "Hpost3". destruct err3.
        -- (* AdtrSig read failed *)
           wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
           destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
           destruct Hvalid as [HvLink [HvServ HvAdtr]]. iApply "Hpost3".
           iExists obj.(AdtrSig), tail. iPureIntro.
           assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(Link)
                     (safemarshal.Slice1D.pure_enc obj.(ServSig)
                      ++ safemarshal.Slice1D.pure_enc obj.(AdtrSig) ++ tail)) as Hw1.
           { rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
               /safemarshal.w64.pure_enc -?app_assoc. split; [|exact HvLink].
             rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
             rewrite -?app_assoc in Henc. exact Henc. }
           destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
           assert (safemarshal.Slice1D.wish rem1 obj.(ServSig)
                     (safemarshal.Slice1D.pure_enc obj.(AdtrSig) ++ tail)) as Hw2.
           { split; [exact Hrem1|exact HvServ]. }
           destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1b Hw2) as [_ Hrem2].
           split; [exact Hrem2|exact HvAdtr].
        -- (* success *)
           iDestruct "Hpost3" as (av0 rem3) "(Ha3 & Hb3 & %Hsl1c)".
           destruct Hsl1a as [Hb_eq HvLink0]. destruct Hsl1b as [Hrem1_eq HvServ0].
           destruct Hsl1c as [Hrem2_eq HvAdtr0].
           wp_auto.
           wp_alloc l as "Hptr".
           iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
           wp_auto.
           iApply "HΦ". iExists (SignedLink.mk' lk0 sv0 av0), rem3.
           iFrame "Hb3". iSplitL "Hptr Ha1 Ha2 Ha3".
           { iExists a1, a2, a3. iFrame "Hptr Ha1 Ha2 Ha3". }
           iPureIntro. rewrite /wish /pure_enc /valid. split.
           ++ rewrite Hb_eq Hrem1_eq Hrem2_eq -?app_assoc. done.
           ++ split; [exact HvLink0|split; [exact HvServ0|exact HvAdtr0]].
Qed.

End proof.
End SignedLink.

Module SignedVrf.
Record t :=
  mk' {
    VrfPk: list w8;
    ServSig: list w8;
    AdtrSig: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.Slice1D.pure_enc obj.(VrfPk) ++
  safemarshal.Slice1D.pure_enc obj.(ServSig) ++
  safemarshal.Slice1D.pure_enc obj.(AdtrSig).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(VrfPk) ∧
  safemarshal.Slice1D.valid obj.(ServSig) ∧
  safemarshal.Slice1D.valid obj.(AdtrSig).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid
    /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc
    /safemarshal.Slice1D.valid.
  intros (-> & Hv0a & Hv0b & Hv0c) (Heq & Hv1a & Hv1b & Hv1c).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Hp1 Heq]; [|len].
  apply (inj u64_le) in Hp1.
  assert (length obj0.(VrfPk) = length obj1.(VrfPk)) by word.
  apply app_inj_1 in Heq as [Hvrf Heq]; [|done].
  apply app_inj_1 in Heq as [Hp2 Heq]; [|len].
  apply (inj u64_le) in Hp2.
  assert (length obj0.(ServSig) = length obj1.(ServSig)) by word.
  apply app_inj_1 in Heq as [Hserv Heq]; [|done].
  apply app_inj_1 in Heq as [Hp3 Heq]; [|len].
  apply (inj u64_le) in Hp3.
  assert (length obj0.(AdtrSig) = length obj1.(AdtrSig)) by word.
  apply app_inj_1 in Heq as [Hadtr Htail]; [|done].
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_VrfPk sl_ServSig sl_AdtrSig,
  "Hstruct" ∷ ptr ↦{d} (auditor.SignedVrf.mk sl_VrfPk sl_ServSig sl_AdtrSig) ∗

  "Hsl_VrfPk" ∷ sl_VrfPk ↦*{d} obj.(VrfPk) ∗
  "Hsl_ServSig" ∷ sl_ServSig ↦*{d} obj.(ServSig) ∗
  "Hsl_AdtrSig" ∷ sl_AdtrSig ↦*{d} obj.(AdtrSig).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init auditor ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! auditor.SignedVrfEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_VrfPk sl_ServSig sl_AdtrSig) "(Hstruct & Hsl_VrfPk & Hsl_ServSig & Hsl_AdtrSig)". wp_auto.
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_VrfPk]") as "* (Hsl_b & Hcap_b & Hsl_VrfPk)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_ServSig]") as "* (Hsl_b & Hcap_b & Hsl_ServSig)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_AdtrSig]") as "* (Hsl_b & Hcap_b & Hsl_AdtrSig)".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -!app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init auditor ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! auditor.SignedVrfDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj tail, ⌜wish b obj tail⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj d ∗
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof.
  wp_start as "Hsl_b". wp_auto.
  destruct b as [|b0 brest].
  - wp_apply (safemarshal.Slice1D.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc _]. iExFalso. iPureIntro.
      rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
    + iDestruct "Hpost1" as (lp0 rem1) "(Ha1 & Hb1 & %Hsl1a)".
      destruct Hsl1a as [Henc _]. iExFalso. iPureIntro.
      rewrite /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
  - iDestruct (own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (safemarshal.Slice1D.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + (* VrfPk read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
      destruct Hvalid as [HvVrf _]. iApply "Hpost1".
      iExists obj.(VrfPk), _. iPureIntro.
      rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc
        -?app_assoc. split; [|exact HvVrf].
      rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      rewrite -?app_assoc in Henc. exact Henc.
    + iDestruct "Hpost1" as (vp0 rem1) "(Ha1 & Hb1 & %Hsl1a)".
      wp_auto.
      wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb1]").
      iIntros (a2 b2 err2) "Hpost2". destruct err2.
      * (* ServSig read failed *)
        wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
        destruct Hvalid as [HvVrf [HvServ _]]. iApply "Hpost2".
        iExists obj.(ServSig), (safemarshal.Slice1D.pure_enc obj.(AdtrSig) ++ tail). iPureIntro.
        assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(VrfPk)
                  (safemarshal.Slice1D.pure_enc obj.(ServSig)
                   ++ safemarshal.Slice1D.pure_enc obj.(AdtrSig) ++ tail)) as Hw1.
        { rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
            /safemarshal.w64.pure_enc -?app_assoc. split; [|exact HvVrf].
          rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
          rewrite -?app_assoc in Henc. exact Henc. }
        destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
        split; [exact Hrem1|exact HvServ].
      * iDestruct "Hpost2" as (sv0 rem2) "(Ha2 & Hb2 & %Hsl1b)".
        wp_auto.
        wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb2]").
        iIntros (a3 b3 err3) "Hpost3". destruct err3.
        -- (* AdtrSig read failed *)
           wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
           destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
           destruct Hvalid as [HvVrf [HvServ HvAdtr]]. iApply "Hpost3".
           iExists obj.(AdtrSig), tail. iPureIntro.
           assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(VrfPk)
                     (safemarshal.Slice1D.pure_enc obj.(ServSig)
                      ++ safemarshal.Slice1D.pure_enc obj.(AdtrSig) ++ tail)) as Hw1.
           { rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
               /safemarshal.w64.pure_enc -?app_assoc. split; [|exact HvVrf].
             rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
             rewrite -?app_assoc in Henc. exact Henc. }
           destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
           assert (safemarshal.Slice1D.wish rem1 obj.(ServSig)
                     (safemarshal.Slice1D.pure_enc obj.(AdtrSig) ++ tail)) as Hw2.
           { split; [exact Hrem1|exact HvServ]. }
           destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1b Hw2) as [_ Hrem2].
           split; [exact Hrem2|exact HvAdtr].
        -- (* success *)
           iDestruct "Hpost3" as (av0 rem3) "(Ha3 & Hb3 & %Hsl1c)".
           destruct Hsl1a as [Hb_eq HvVrf0]. destruct Hsl1b as [Hrem1_eq HvServ0].
           destruct Hsl1c as [Hrem2_eq HvAdtr0].
           wp_auto.
           wp_alloc l as "Hptr".
           iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
           wp_auto.
           iApply "HΦ". iExists (SignedVrf.mk' vp0 sv0 av0), rem3.
           iFrame "Hb3". iSplitL "Hptr Ha1 Ha2 Ha3".
           { iExists a1, a2, a3. iFrame "Hptr Ha1 Ha2 Ha3". }
           iPureIntro. rewrite /wish /pure_enc /valid. split.
           ++ rewrite Hb_eq Hrem1_eq Hrem2_eq -?app_assoc. done.
           ++ split; [exact HvVrf0|split; [exact HvServ0|exact HvAdtr0]].
Qed.

End proof.
End SignedVrf.

Module GetReply.
Record t :=
  mk' {
    StartEp: w64;
    StartLink: SignedLink.t;
    CurrLink: SignedLink.t;
    Vrf: SignedVrf.t;
    Err: bool;
  }.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc obj.(StartEp) ++
  SignedLink.pure_enc obj.(StartLink) ++
  SignedLink.pure_enc obj.(CurrLink) ++
  SignedVrf.pure_enc obj.(Vrf) ++
  safemarshal.bool.pure_enc obj.(Err).

Definition valid obj :=
  SignedLink.valid obj.(StartLink) ∧
  SignedLink.valid obj.(CurrLink) ∧
  SignedVrf.valid obj.(Vrf).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  intros [Henc0 Hvld0] [Henc1 Hvld1].
  rewrite /valid in Hvld0 Hvld1.
  destruct Hvld0 as [Hv0a [Hv0b Hv0c]]. destruct Hvld1 as [Hv1a [Hv1b Hv1c]].
  assert (safemarshal.w64.wish b obj0.(StartEp)
            (SignedLink.pure_enc obj0.(StartLink) ++ SignedLink.pure_enc obj0.(CurrLink)
             ++ SignedVrf.pure_enc obj0.(Vrf) ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)) as Hw0.
  { rewrite /safemarshal.w64.wish Henc0 /pure_enc -!app_assoc //. }
  assert (safemarshal.w64.wish b obj1.(StartEp)
            (SignedLink.pure_enc obj1.(StartLink) ++ SignedLink.pure_enc obj1.(CurrLink)
             ++ SignedVrf.pure_enc obj1.(Vrf) ++ safemarshal.bool.pure_enc obj1.(Err) ++ tail1)) as Hw1.
  { rewrite /safemarshal.w64.wish Henc1 /pure_enc -!app_assoc //. }
  destruct (safemarshal.w64.wish_det _ _ _ _ Hw0 Hw1) as [HSE Hr1].
  assert (SignedLink.wish
            (SignedLink.pure_enc obj0.(StartLink) ++ SignedLink.pure_enc obj0.(CurrLink)
             ++ SignedVrf.pure_enc obj0.(Vrf) ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)
            obj0.(StartLink)
            (SignedLink.pure_enc obj0.(CurrLink) ++ SignedVrf.pure_enc obj0.(Vrf)
             ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)) as Hs0.
  { split; [done|exact Hv0a]. }
  assert (SignedLink.wish
            (SignedLink.pure_enc obj0.(StartLink) ++ SignedLink.pure_enc obj0.(CurrLink)
             ++ SignedVrf.pure_enc obj0.(Vrf) ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)
            obj1.(StartLink)
            (SignedLink.pure_enc obj1.(CurrLink) ++ SignedVrf.pure_enc obj1.(Vrf)
             ++ safemarshal.bool.pure_enc obj1.(Err) ++ tail1)) as Hs1.
  { split; [rewrite Hr1 //|exact Hv1a]. }
  destruct (SignedLink.wish_det _ _ _ _ Hs0 Hs1) as [HSL Hr2].
  assert (SignedLink.wish
            (SignedLink.pure_enc obj0.(CurrLink) ++ SignedVrf.pure_enc obj0.(Vrf)
             ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)
            obj0.(CurrLink)
            (SignedVrf.pure_enc obj0.(Vrf) ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)) as Hc0.
  { split; [done|exact Hv0b]. }
  assert (SignedLink.wish
            (SignedLink.pure_enc obj0.(CurrLink) ++ SignedVrf.pure_enc obj0.(Vrf)
             ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)
            obj1.(CurrLink)
            (SignedVrf.pure_enc obj1.(Vrf) ++ safemarshal.bool.pure_enc obj1.(Err) ++ tail1)) as Hc1.
  { split; [rewrite Hr2 //|exact Hv1b]. }
  destruct (SignedLink.wish_det _ _ _ _ Hc0 Hc1) as [HCL Hr3].
  assert (SignedVrf.wish
            (SignedVrf.pure_enc obj0.(Vrf) ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)
            obj0.(Vrf) (safemarshal.bool.pure_enc obj0.(Err) ++ tail0)) as Hvf0.
  { split; [done|exact Hv0c]. }
  assert (SignedVrf.wish
            (SignedVrf.pure_enc obj0.(Vrf) ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)
            obj1.(Vrf) (safemarshal.bool.pure_enc obj1.(Err) ++ tail1)) as Hvf1.
  { split; [rewrite Hr3 //|exact Hv1c]. }
  destruct (SignedVrf.wish_det _ _ _ _ Hvf0 Hvf1) as [HV Hr4].
  assert (safemarshal.bool.wish
            (safemarshal.bool.pure_enc obj0.(Err) ++ tail0) obj0.(Err) tail0) as Hb0.
  { rewrite /safemarshal.bool.wish //. }
  assert (safemarshal.bool.wish
            (safemarshal.bool.pure_enc obj0.(Err) ++ tail0) obj1.(Err) tail1) as Hb1.
  { rewrite /safemarshal.bool.wish Hr4 //. }
  destruct (safemarshal.bool.wish_det _ _ _ _ Hb0 Hb1) as [HErr Htail].
  split; [|exact Htail].
  destruct obj0, obj1. simpl in *. by subst.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ ptr_StartLink ptr_CurrLink ptr_Vrf,
  "Hstruct" ∷ ptr ↦{d} (auditor.GetReply.mk obj.(StartEp) ptr_StartLink ptr_CurrLink ptr_Vrf obj.(Err)) ∗

  "Hown_StartLink" ∷ SignedLink.own ptr_StartLink obj.(StartLink) d ∗
  "Hown_CurrLink" ∷ SignedLink.own ptr_CurrLink obj.(CurrLink) d ∗
  "Hown_Vrf" ∷ SignedVrf.own ptr_Vrf obj.(Vrf) d.

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init auditor ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! auditor.GetReplyEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (ptr_StartLink ptr_CurrLink ptr_Vrf) "(Hstruct & Hown_StartLink & Hown_CurrLink & Hown_Vrf)". wp_auto.
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (SignedLink.wp_enc with "[$Hsl_b $Hcap_b $Hown_StartLink]") as "* (Hsl_b & Hcap_b & Hown_StartLink)".
  wp_apply (SignedLink.wp_enc with "[$Hsl_b $Hcap_b $Hown_CurrLink]") as "* (Hsl_b & Hcap_b & Hown_CurrLink)".
  wp_apply (SignedVrf.wp_enc with "[$Hsl_b $Hcap_b $Hown_Vrf]") as "* (Hsl_b & Hcap_b & Hown_Vrf)".
  wp_apply (safemarshal.bool.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -?app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init auditor ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! auditor.GetReplyDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj tail, ⌜wish b obj tail⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj d ∗
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
(* BLOCKED: GetReply's last field [Err : bool] is decoded via [safemarshal.ReadBool]
   (= marshal.ReadBool), whose spec returns [bool_decide (uint.Z bit ≠ 0)] for ANY
   first byte [bit]. The success case must produce [wish b obj tail], i.e.
   [b = ... ++ bool.pure_enc obj.(Err) ++ tail] with [bool.pure_enc Err = [if Err then W8 1 else W8 0]].
   But a non-canonical byte (e.g. 2) decodes to Err=true while pure_enc true = [1], so the
   round-trip wish is FALSE — the wish-based spec is unprovable, exactly like the (now respec'd)
   standalone [safemarshal.bool.wp_dec]. Needs a respec (state the actual decoder guarantee,
   like bool.wp_dec) rather than [wish]. wp_enc / wish_det are fine and proven. *)
Proof. Admitted.

End proof.
End GetReply.

End auditor.
