From New.generatedproof.github_com.sanjit_bhat.pav Require Import server.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import
  ktcore safemarshal.
From New.proof.github_com.tchajed Require Import marshal.

From New.proof.github_com.sanjit_bhat.pav.server_proof Require Import base.

Module server.

Module StartChain.
Record t :=
  mk' {
    PrevEpochLen: w64;
    PrevLink: list w8;
    ChainProof: list w8;
    LinkSig: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc obj.(PrevEpochLen) ++
  safemarshal.Slice1D.pure_enc obj.(PrevLink) ++
  safemarshal.Slice1D.pure_enc obj.(ChainProof) ++
  safemarshal.Slice1D.pure_enc obj.(LinkSig).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(PrevLink) ∧
  safemarshal.Slice1D.valid obj.(ChainProof) ∧
  safemarshal.Slice1D.valid obj.(LinkSig).

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
  apply app_inj_1 in Heq as [Hpe Heq]; [|len].
  apply (inj u64_le) in Hpe.
  apply app_inj_1 in Heq as [Hp1 Heq]; [|len].
  apply (inj u64_le) in Hp1.
  assert (length obj0.(PrevLink) = length obj1.(PrevLink)) by word.
  apply app_inj_1 in Heq as [Hpl Heq]; [|done].
  apply app_inj_1 in Heq as [Hp2 Heq]; [|len].
  apply (inj u64_le) in Hp2.
  assert (length obj0.(ChainProof) = length obj1.(ChainProof)) by word.
  apply app_inj_1 in Heq as [Hcp Heq]; [|done].
  apply app_inj_1 in Heq as [Hp3 Heq]; [|len].
  apply (inj u64_le) in Hp3.
  assert (length obj0.(LinkSig) = length obj1.(LinkSig)) by word.
  apply app_inj_1 in Heq as [Hls Htail]; [|done].
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_PrevLink sl_ChainProof sl_LinkSig,
  "Hstruct" ∷ ptr ↦{d} (server.StartChain.mk obj.(PrevEpochLen) sl_PrevLink sl_ChainProof sl_LinkSig) ∗

  "Hsl_PrevLink" ∷ sl_PrevLink ↦*{d} obj.(PrevLink) ∗
  "Hsl_ChainProof" ∷ sl_ChainProof ↦*{d} obj.(ChainProof) ∗
  "Hsl_LinkSig" ∷ sl_LinkSig ↦*{d} obj.(LinkSig).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! server.StartChainEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_PrevLink sl_ChainProof sl_LinkSig) "(Hstruct & Hsl_PrevLink & Hsl_ChainProof & Hsl_LinkSig)". wp_auto.
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_PrevLink]") as "* (Hsl_b & Hcap_b & Hsl_PrevLink)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_ChainProof]") as "* (Hsl_b & Hcap_b & Hsl_ChainProof)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_LinkSig]") as "* (Hsl_b & Hcap_b & Hsl_LinkSig)".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -?app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! server.StartChainDecode #sl_b
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
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc _]. iExFalso. iPureIntro.
      rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
    + iDestruct "Hpost1" as (rem1) "(Hb1 & %Hsl1a)".
      rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc in Hsl1a.
      apply (f_equal length) in Hsl1a. rewrite length_app u64_le_length /= in Hsl1a. lia.
  - iDestruct (ktcore.own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (safemarshal.w64.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + (* PrevEpochLen read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc _]. iApply "Hpost1".
      iExists obj.(PrevEpochLen), _. iPureIntro.
      rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc.
      rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      rewrite -?app_assoc in Henc. exact Henc.
    + iDestruct "Hpost1" as (rem1) "(Hb1 & %Hsl1a)".
      wp_auto.
      wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb1]").
      iIntros (a2 b2 err2) "Hpost2". destruct err2.
      * (* PrevLink read failed *)
        wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
        destruct Hvalid as [HvPL _]. iApply "Hpost2".
        iExists obj.(PrevLink),
          (safemarshal.Slice1D.pure_enc obj.(ChainProof)
           ++ safemarshal.Slice1D.pure_enc obj.(LinkSig) ++ tail). iPureIntro.
        assert (safemarshal.w64.wish (b0 :: brest) obj.(PrevEpochLen)
                  (safemarshal.Slice1D.pure_enc obj.(PrevLink)
                   ++ safemarshal.Slice1D.pure_enc obj.(ChainProof)
                   ++ safemarshal.Slice1D.pure_enc obj.(LinkSig) ++ tail)) as Hw1.
        { rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc /safemarshal.Slice1D.pure_enc -?app_assoc.
          rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
          rewrite -?app_assoc in Henc. exact Henc. }
        destruct (safemarshal.w64.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
        rewrite /safemarshal.Slice1D.wish. split; [rewrite Hrem1 -?app_assoc //|exact HvPL].
      * iDestruct "Hpost2" as (pl0 rem2) "(Ha2 & Hb2 & %Hsl1b)".
        wp_auto.
        wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb2]").
        iIntros (a3 b3 err3) "Hpost3". destruct err3.
        -- (* ChainProof read failed *)
           wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
           destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
           destruct Hvalid as [HvPL [HvCP _]]. iApply "Hpost3".
           iExists obj.(ChainProof),
             (safemarshal.Slice1D.pure_enc obj.(LinkSig) ++ tail). iPureIntro.
           assert (safemarshal.w64.wish (b0 :: brest) obj.(PrevEpochLen)
                     (safemarshal.Slice1D.pure_enc obj.(PrevLink)
                      ++ safemarshal.Slice1D.pure_enc obj.(ChainProof)
                      ++ safemarshal.Slice1D.pure_enc obj.(LinkSig) ++ tail)) as Hw1.
           { rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc /safemarshal.Slice1D.pure_enc -?app_assoc.
             rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
             rewrite -?app_assoc in Henc. exact Henc. }
           destruct (safemarshal.w64.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
           assert (safemarshal.Slice1D.wish rem1 obj.(PrevLink)
                     (safemarshal.Slice1D.pure_enc obj.(ChainProof)
                      ++ safemarshal.Slice1D.pure_enc obj.(LinkSig) ++ tail)) as Hw2.
           { rewrite /safemarshal.Slice1D.wish. split; [rewrite Hrem1 -?app_assoc //|exact HvPL]. }
           destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1b Hw2) as [_ Hrem2].
           rewrite /safemarshal.Slice1D.wish. split; [rewrite Hrem2 -?app_assoc //|exact HvCP].
        -- iDestruct "Hpost3" as (cp0 rem3) "(Ha3 & Hb3 & %Hsl1c)".
           wp_auto.
           wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb3]").
           iIntros (a4 b4 err4) "Hpost4". destruct err4.
           ++ (* LinkSig read failed *)
              wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
              destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
              destruct Hvalid as [HvPL [HvCP HvLS]]. iApply "Hpost4".
              iExists obj.(LinkSig), tail. iPureIntro.
              assert (safemarshal.w64.wish (b0 :: brest) obj.(PrevEpochLen)
                        (safemarshal.Slice1D.pure_enc obj.(PrevLink)
                         ++ safemarshal.Slice1D.pure_enc obj.(ChainProof)
                         ++ safemarshal.Slice1D.pure_enc obj.(LinkSig) ++ tail)) as Hw1.
              { rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc /safemarshal.Slice1D.pure_enc -?app_assoc.
                rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
                rewrite -?app_assoc in Henc. exact Henc. }
              destruct (safemarshal.w64.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
              assert (safemarshal.Slice1D.wish rem1 obj.(PrevLink)
                        (safemarshal.Slice1D.pure_enc obj.(ChainProof)
                         ++ safemarshal.Slice1D.pure_enc obj.(LinkSig) ++ tail)) as Hw2.
              { rewrite /safemarshal.Slice1D.wish. split; [rewrite Hrem1 -?app_assoc //|exact HvPL]. }
              destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1b Hw2) as [_ Hrem2].
              assert (safemarshal.Slice1D.wish rem2 obj.(ChainProof)
                        (safemarshal.Slice1D.pure_enc obj.(LinkSig) ++ tail)) as Hw3.
              { rewrite /safemarshal.Slice1D.wish. split; [rewrite Hrem2 -?app_assoc //|exact HvCP]. }
              destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1c Hw3) as [_ Hrem3].
              rewrite /safemarshal.Slice1D.wish. split; [rewrite Hrem3 //|exact HvLS].
           ++ (* success *)
              iDestruct "Hpost4" as (ls0 rem4) "(Ha4 & Hb4 & %Hsl1d)".
              rewrite /safemarshal.w64.wish in Hsl1a.
              destruct Hsl1b as [Hrem1_eq HvPL0]. destruct Hsl1c as [Hrem2_eq HvCP0].
              destruct Hsl1d as [Hrem3_eq HvLS0].
              wp_auto.
              wp_alloc l as "Hptr".
              iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
              wp_auto.
              iApply "HΦ". iExists (StartChain.mk' a1 pl0 cp0 ls0), rem4.
              iFrame "Hb4". iSplitL "Hptr Ha2 Ha3 Ha4".
              { iExists a2, a3, a4. iFrame "Hptr Ha2 Ha3 Ha4". }
              iPureIntro. rewrite /wish /pure_enc /valid. split.
              ** rewrite Hsl1a Hrem1_eq Hrem2_eq Hrem3_eq -?app_assoc. done.
              ** split; [exact HvPL0|split; [exact HvCP0|exact HvLS0]].
Qed.

End proof.
End StartChain.

Module StartVrf.
Record t :=
  mk' {
    VrfPk: list w8;
    VrfSig: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.Slice1D.pure_enc obj.(VrfPk) ++
  safemarshal.Slice1D.pure_enc obj.(VrfSig).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(VrfPk) ∧
  safemarshal.Slice1D.valid obj.(VrfSig).

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
  intros (-> & Hv0a & Hv0b) (Heq & Hv1a & Hv1b).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Hp1 Heq]; [|len].
  apply (inj u64_le) in Hp1.
  assert (length obj0.(VrfPk) = length obj1.(VrfPk)) by word.
  apply app_inj_1 in Heq as [Hvk Heq]; [|done].
  apply app_inj_1 in Heq as [Hp2 Heq]; [|len].
  apply (inj u64_le) in Hp2.
  assert (length obj0.(VrfSig) = length obj1.(VrfSig)) by word.
  apply app_inj_1 in Heq as [Hvs Htail]; [|done].
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_VrfPk sl_VrfSig,
  "Hstruct" ∷ ptr ↦{d} (server.StartVrf.mk sl_VrfPk sl_VrfSig) ∗

  "Hsl_VrfPk" ∷ sl_VrfPk ↦*{d} obj.(VrfPk) ∗
  "Hsl_VrfSig" ∷ sl_VrfSig ↦*{d} obj.(VrfSig).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! server.StartVrfEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_VrfPk sl_VrfSig) "(Hstruct & Hsl_VrfPk & Hsl_VrfSig)". wp_auto.
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_VrfPk]") as "* (Hsl_b & Hcap_b & Hsl_VrfPk)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_VrfSig]") as "* (Hsl_b & Hcap_b & Hsl_VrfSig)".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -?app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! server.StartVrfDecode #sl_b
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
  - iDestruct (ktcore.own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
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
      * (* VrfSig read failed *)
        wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
        destruct Hvalid as [HvVrf HvSig]. iApply "Hpost2".
        iExists obj.(VrfSig), tail. iPureIntro.
        assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(VrfPk)
                  (safemarshal.Slice1D.pure_enc obj.(VrfSig) ++ tail)) as Hw1.
        { rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
            /safemarshal.w64.pure_enc -?app_assoc. split; [|exact HvVrf].
          rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
          rewrite -?app_assoc in Henc. exact Henc. }
        destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
        split; [exact Hrem1|exact HvSig].
      * (* success *)
        iDestruct "Hpost2" as (vs0 rem2) "(Ha2 & Hb2 & %Hsl1b)".
        destruct Hsl1a as [Hb_eq HvVrf0]. destruct Hsl1b as [Hrem1_eq HvSig0].
        wp_auto.
        wp_alloc l as "Hptr".
        iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
        wp_auto.
        iApply "HΦ". iExists (StartVrf.mk' vp0 vs0), rem2.
        iFrame "Hb2". iSplitL "Hptr Ha1 Ha2".
        { iExists a1, a2. iFrame "Hptr Ha1 Ha2". }
        iPureIntro. rewrite /wish /pure_enc /valid. split.
        ++ rewrite Hb_eq Hrem1_eq -?app_assoc. done.
        ++ split; [exact HvVrf0|exact HvSig0].
Qed.

End proof.
End StartVrf.

Module StartReply.
Record t :=
  mk' {
    Chain: StartChain.t;
    Vrf: StartVrf.t;
  }.

Definition pure_enc obj :=
  StartChain.pure_enc obj.(Chain) ++
  StartVrf.pure_enc obj.(Vrf).

Definition valid obj :=
  StartChain.valid obj.(Chain) ∧
  StartVrf.valid obj.(Vrf).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid
    /StartChain.pure_enc /StartChain.valid /StartVrf.pure_enc /StartVrf.valid
    /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc /safemarshal.Slice1D.valid.
  intros (-> & (Hv0a & Hv0b & Hv0c) & (Hv0d & Hv0e))
         (Heq & (Hv1a & Hv1b & Hv1c) & (Hv1d & Hv1e)).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Hpe Heq]; [|len]. apply (inj u64_le) in Hpe.
  apply app_inj_1 in Heq as [Hp1 Heq]; [|len]. apply (inj u64_le) in Hp1.
  assert (length obj0.(Chain).(StartChain.PrevLink) = length obj1.(Chain).(StartChain.PrevLink)) by word.
  apply app_inj_1 in Heq as [Hpl Heq]; [|done].
  apply app_inj_1 in Heq as [Hp2 Heq]; [|len]. apply (inj u64_le) in Hp2.
  assert (length obj0.(Chain).(StartChain.ChainProof) = length obj1.(Chain).(StartChain.ChainProof)) by word.
  apply app_inj_1 in Heq as [Hcp Heq]; [|done].
  apply app_inj_1 in Heq as [Hp3 Heq]; [|len]. apply (inj u64_le) in Hp3.
  assert (length obj0.(Chain).(StartChain.LinkSig) = length obj1.(Chain).(StartChain.LinkSig)) by word.
  apply app_inj_1 in Heq as [Hls Heq]; [|done].
  apply app_inj_1 in Heq as [Hp4 Heq]; [|len]. apply (inj u64_le) in Hp4.
  assert (length obj0.(Vrf).(StartVrf.VrfPk) = length obj1.(Vrf).(StartVrf.VrfPk)) by word.
  apply app_inj_1 in Heq as [Hvp Heq]; [|done].
  apply app_inj_1 in Heq as [Hp5 Heq]; [|len]. apply (inj u64_le) in Hp5.
  assert (length obj0.(Vrf).(StartVrf.VrfSig) = length obj1.(Vrf).(StartVrf.VrfSig)) by word.
  apply app_inj_1 in Heq as [Hvs Htail]; [|done].
  destruct obj0 as [[PEL0 PL0 CP0 LS0] [VP0 VS0]], obj1 as [[PEL1 PL1 CP1 LS1] [VP1 VS1]].
  by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ ptr_Chain ptr_Vrf,
  "Hstruct" ∷ ptr ↦{d} (server.StartReply.mk ptr_Chain ptr_Vrf) ∗

  "Hown_Chain" ∷ StartChain.own ptr_Chain obj.(Chain) d ∗
  "Hown_Vrf" ∷ StartVrf.own ptr_Vrf obj.(Vrf) d.

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! server.StartReplyEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (ptr_Chain ptr_Vrf) "(Hstruct & Hown_Chain & Hown_Vrf)". wp_auto.
  wp_apply (StartChain.wp_enc with "[$Hsl_b $Hcap_b $Hown_Chain]") as "* (Hsl_b & Hcap_b & Hown_Chain)".
  wp_apply (StartVrf.wp_enc with "[$Hsl_b $Hcap_b $Hown_Vrf]") as "* (Hsl_b & Hcap_b & Hown_Vrf)".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -?app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! server.StartReplyDecode #sl_b
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
  - wp_apply (StartChain.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc _]. iExFalso. iPureIntro.
      rewrite /pure_enc /StartChain.pure_enc /safemarshal.Slice1D.pure_enc
        /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
    + iDestruct "Hpost1" as (ch0 rem1) "(Hown_ch & Hb1 & %Hsl1a)".
      destruct Hsl1a as [Henc _]. iExFalso. iPureIntro.
      rewrite /StartChain.pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
  - iDestruct (ktcore.own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (StartChain.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + (* Chain read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
      destruct Hvalid as [HvCh _]. iApply "Hpost1".
      iExists obj.(Chain), (StartVrf.pure_enc obj.(Vrf) ++ tail). iPureIntro.
      rewrite /StartChain.wish. split; [|exact HvCh].
      rewrite Henc /pure_enc -app_assoc //.
    + iDestruct "Hpost1" as (ch0 rem1) "(Hown_ch & Hb1 & %Hsl1a)".
      wp_auto.
      wp_apply (StartVrf.wp_dec with "[$Hb1]").
      iIntros (a2 b2 err2) "Hpost2". destruct err2.
      * (* Vrf read failed *)
        wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
        destruct Hvalid as [HvCh HvVrf]. iApply "Hpost2".
        iExists obj.(Vrf), tail. iPureIntro.
        assert (StartChain.wish (b0 :: brest) obj.(Chain)
                  (StartVrf.pure_enc obj.(Vrf) ++ tail)) as Hw1.
        { rewrite /StartChain.wish. split; [|exact HvCh].
          rewrite Henc /pure_enc -app_assoc //. }
        destruct (StartChain.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
        rewrite /StartVrf.wish. split; [rewrite Hrem1 //|exact HvVrf].
      * (* success *)
        iDestruct "Hpost2" as (vrf0 rem2) "(Hown_vrf & Hb2 & %Hsl1b)".
        destruct Hsl1a as [Hb_eq HvCh0]. destruct Hsl1b as [Hrem1_eq HvVrf0].
        wp_auto.
        wp_alloc l as "Hptr".
        iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
        wp_auto.
        iApply "HΦ". iExists (StartReply.mk' ch0 vrf0), rem2.
        iFrame "Hb2". iSplitL "Hptr Hown_ch Hown_vrf".
        { iExists a1, a2. iFrame "Hptr Hown_ch Hown_vrf". }
        iPureIntro. rewrite /wish /pure_enc /valid. split.
        ++ rewrite Hb_eq Hrem1_eq -?app_assoc. done.
        ++ split; [exact HvCh0|exact HvVrf0].
Qed.

End proof.
End StartReply.

Module PutArg.
Record t :=
  mk' {
    Uid: w64;
    Pk: list w8;
    Ver: w64;
  }.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc obj.(Uid) ++
  safemarshal.Slice1D.pure_enc obj.(Pk) ++
  safemarshal.w64.pure_enc obj.(Ver).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(Pk).

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
  intros (-> & Hv0) (Heq & Hv1).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Huid Heq]; [|len].
  apply (inj u64_le) in Huid.
  apply app_inj_1 in Heq as [Hp Heq]; [|len].
  apply (inj u64_le) in Hp.
  assert (length obj0.(Pk) = length obj1.(Pk)) by word.
  apply app_inj_1 in Heq as [Hpk Heq]; [|done].
  apply app_inj_1 in Heq as [Hver Htail]; [|len].
  apply (inj u64_le) in Hver.
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_Pk,
  "Hstruct" ∷ ptr ↦{d} (server.PutArg.mk obj.(Uid) sl_Pk obj.(Ver)) ∗

  "Hsl_Pk" ∷ sl_Pk ↦*{d} obj.(Pk).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! server.PutArgEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_Pk) "(Hstruct & Hsl_Pk)". wp_auto.
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_Pk]") as "* (Hsl_b & Hcap_b & Hsl_Pk)".
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -?app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! server.PutArgDecode #sl_b
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
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc _]. iExFalso. iPureIntro.
      rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
    + iDestruct "Hpost1" as (rem1) "(Hb1 & %Hsl1a)".
      rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc in Hsl1a.
      apply (f_equal length) in Hsl1a. rewrite length_app u64_le_length /= in Hsl1a. lia.
  - iDestruct (ktcore.own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (safemarshal.w64.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + (* Uid read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc _]. iApply "Hpost1".
      iExists obj.(Uid), _. iPureIntro.
      rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc.
      rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      rewrite -?app_assoc in Henc. exact Henc.
    + iDestruct "Hpost1" as (rem1) "(Hb1 & %Hsl1a)".
      wp_auto.
      wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb1]").
      iIntros (a2 b2 err2) "Hpost2". destruct err2.
      * (* Pk read failed *)
        wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
        iApply "Hpost2".
        iExists obj.(Pk), (safemarshal.w64.pure_enc obj.(Ver) ++ tail). iPureIntro.
        assert (safemarshal.w64.wish (b0 :: brest) obj.(Uid)
                  (safemarshal.Slice1D.pure_enc obj.(Pk)
                   ++ safemarshal.w64.pure_enc obj.(Ver) ++ tail)) as Hw1.
        { rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc /safemarshal.Slice1D.pure_enc -?app_assoc.
          rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
          rewrite -?app_assoc in Henc. exact Henc. }
        destruct (safemarshal.w64.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
        rewrite /safemarshal.Slice1D.wish. split; [rewrite Hrem1 -?app_assoc //|exact Hvalid].
      * iDestruct "Hpost2" as (pk0 rem2) "(Ha2 & Hb2 & %Hsl1b)".
        wp_auto.
        wp_apply (safemarshal.w64.wp_dec with "[$Hb2]").
        iIntros (a3 b3 err3) "Hpost3". destruct err3.
        -- (* Ver read failed *)
           wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
           destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
           iApply "Hpost3".
           iExists obj.(Ver), tail. iPureIntro.
           assert (safemarshal.w64.wish (b0 :: brest) obj.(Uid)
                     (safemarshal.Slice1D.pure_enc obj.(Pk)
                      ++ safemarshal.w64.pure_enc obj.(Ver) ++ tail)) as Hw1.
           { rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc /safemarshal.Slice1D.pure_enc -?app_assoc.
             rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
             rewrite -?app_assoc in Henc. exact Henc. }
           destruct (safemarshal.w64.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
           assert (safemarshal.Slice1D.wish rem1 obj.(Pk)
                     (safemarshal.w64.pure_enc obj.(Ver) ++ tail)) as Hw2.
           { rewrite /safemarshal.Slice1D.wish. split; [rewrite Hrem1 -?app_assoc //|exact Hvalid]. }
           destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1b Hw2) as [_ Hrem2].
           rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc.
           rewrite Hrem2 //.
        -- (* success *)
           iDestruct "Hpost3" as (rem3) "(Hb3 & %Hsl1c)".
           rewrite /safemarshal.w64.wish in Hsl1a.
           destruct Hsl1b as [Hrem1_eq HvPk0].
           rewrite /safemarshal.w64.wish in Hsl1c.
           wp_auto.
           wp_alloc l as "Hptr".
           iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
           wp_auto.
           iApply "HΦ". iExists (PutArg.mk' a1 pk0 a3), rem3.
           iFrame "Hb3". iSplitL "Hptr Ha2".
           { iExists a2. iFrame "Hptr Ha2". }
           iPureIntro. rewrite /wish /pure_enc /valid. split.
           ++ rewrite Hsl1a Hrem1_eq Hsl1c -?app_assoc. done.
           ++ exact HvPk0.
Qed.

End proof.
End PutArg.

Module HistoryArg.
Record t :=
  mk' {
    Uid: w64;
    PrevEpoch: w64;
    PrevVerLen: w64;
  }.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc obj.(Uid) ++
  safemarshal.w64.pure_enc obj.(PrevEpoch) ++
  safemarshal.w64.pure_enc obj.(PrevVerLen).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /safemarshal.w64.pure_enc.
  intros -> Heq.
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Huid Heq]; [|len].
  apply (inj u64_le) in Huid.
  apply app_inj_1 in Heq as [Hpe Heq]; [|len].
  apply (inj u64_le) in Hpe.
  apply app_inj_1 in Heq as [Hpv Htail]; [|len].
  apply (inj u64_le) in Hpv.
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  "Hstruct" ∷ ptr ↦{d} (server.HistoryArg.mk obj.(Uid) obj.(PrevEpoch) obj.(PrevVerLen)).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! server.HistoryArgEncode #sl_b #ptr_obj
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
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -?app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! server.HistoryArgDecode #sl_b
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
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      rewrite /wish /pure_enc /safemarshal.w64.pure_enc in Hwish.
      iExFalso. iPureIntro. apply (f_equal length) in Hwish.
      rewrite !length_app u64_le_length /= in Hwish. lia.
    + iDestruct "Hpost1" as (rem1) "(Hb1 & %Hsl1a)".
      rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc in Hsl1a.
      apply (f_equal length) in Hsl1a. rewrite length_app u64_le_length /= in Hsl1a. lia.
  - iDestruct (ktcore.own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (safemarshal.w64.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + (* Uid read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      iApply "Hpost1". iExists obj.(Uid), _. iPureIntro.
      rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc.
      rewrite /wish /pure_enc /safemarshal.w64.pure_enc in Hwish.
      rewrite -?app_assoc in Hwish. exact Hwish.
    + iDestruct "Hpost1" as (rem1) "(Hb1 & %Hsl1a)".
      wp_auto.
      wp_apply (safemarshal.w64.wp_dec with "[$Hb1]").
      iIntros (a2 b2 err2) "Hpost2". destruct err2.
      * (* PrevEpoch read failed *)
        wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        iApply "Hpost2". iExists obj.(PrevEpoch),
          (safemarshal.w64.pure_enc obj.(PrevVerLen) ++ tail). iPureIntro.
        assert (safemarshal.w64.wish (b0 :: brest) obj.(Uid)
                  (safemarshal.w64.pure_enc obj.(PrevEpoch)
                   ++ safemarshal.w64.pure_enc obj.(PrevVerLen) ++ tail)) as Hw1.
        { rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc.
          rewrite /wish /pure_enc /safemarshal.w64.pure_enc in Hwish.
          rewrite -?app_assoc in Hwish. exact Hwish. }
        destruct (safemarshal.w64.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
        rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc. rewrite Hrem1 //.
      * iDestruct "Hpost2" as (rem2) "(Hb2 & %Hsl1b)".
        wp_auto.
        wp_apply (safemarshal.w64.wp_dec with "[$Hb2]").
        iIntros (a3 b3 err3) "Hpost3". destruct err3.
        -- (* PrevVerLen read failed *)
           wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
           iApply "Hpost3". iExists obj.(PrevVerLen), tail. iPureIntro.
           assert (safemarshal.w64.wish (b0 :: brest) obj.(Uid)
                     (safemarshal.w64.pure_enc obj.(PrevEpoch)
                      ++ safemarshal.w64.pure_enc obj.(PrevVerLen) ++ tail)) as Hw1.
           { rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc.
             rewrite /wish /pure_enc /safemarshal.w64.pure_enc in Hwish.
             rewrite -?app_assoc in Hwish. exact Hwish. }
           destruct (safemarshal.w64.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
           assert (safemarshal.w64.wish rem1 obj.(PrevEpoch)
                     (safemarshal.w64.pure_enc obj.(PrevVerLen) ++ tail)) as Hw2.
           { rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc. rewrite Hrem1 //. }
           destruct (safemarshal.w64.wish_det _ _ _ _ Hsl1b Hw2) as [_ Hrem2].
           rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc. rewrite Hrem2 //.
        -- (* success *)
           iDestruct "Hpost3" as (rem3) "(Hb3 & %Hsl1c)".
           rewrite /safemarshal.w64.wish in Hsl1a Hsl1b Hsl1c.
           wp_auto.
           wp_alloc l as "Hptr".
           iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
           wp_auto.
           iApply "HΦ". iExists (HistoryArg.mk' a1 a2 a3), rem3.
           iFrame "Hb3". iSplitL "Hptr".
           { iFrame "Hptr". }
           iPureIntro. rewrite /wish /pure_enc.
           rewrite Hsl1a Hsl1b Hsl1c -?app_assoc. done.
Qed.

End proof.
End HistoryArg.

Module HistoryReply.
Record t :=
  mk' {
    ChainProof: list w8;
    LinkSig: list w8;
    Hist: list ktcore.Memb.t;
    Bound: ktcore.NonMemb.t;
    Err: bool;
  }.

Definition pure_enc obj :=
  safemarshal.Slice1D.pure_enc obj.(ChainProof) ++
  safemarshal.Slice1D.pure_enc obj.(LinkSig) ++
  ktcore.MembSlice1D.pure_enc obj.(Hist) ++
  ktcore.NonMemb.pure_enc obj.(Bound) ++
  safemarshal.bool.pure_enc obj.(Err).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(ChainProof) ∧
  safemarshal.Slice1D.valid obj.(LinkSig) ∧
  ktcore.MembSlice1D.valid obj.(Hist) ∧
  ktcore.NonMemb.valid obj.(Bound).

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
  destruct Hvld0 as [Hv0a [Hv0b [Hv0c Hv0d]]].
  destruct Hvld1 as [Hv1a [Hv1b [Hv1c Hv1d]]].
  (* ChainProof : Slice1D *)
  assert (safemarshal.Slice1D.wish b obj0.(ChainProof)
            (safemarshal.Slice1D.pure_enc obj0.(LinkSig)
             ++ ktcore.MembSlice1D.pure_enc obj0.(Hist)
             ++ ktcore.NonMemb.pure_enc obj0.(Bound)
             ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)) as Hcp0.
  { split; [|exact Hv0a]. rewrite Henc0 /pure_enc -!app_assoc //. }
  assert (safemarshal.Slice1D.wish b obj1.(ChainProof)
            (safemarshal.Slice1D.pure_enc obj1.(LinkSig)
             ++ ktcore.MembSlice1D.pure_enc obj1.(Hist)
             ++ ktcore.NonMemb.pure_enc obj1.(Bound)
             ++ safemarshal.bool.pure_enc obj1.(Err) ++ tail1)) as Hcp1.
  { split; [|exact Hv1a]. rewrite Henc1 /pure_enc -!app_assoc //. }
  destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hcp0 Hcp1) as [HCP Hr1].
  (* LinkSig : Slice1D *)
  assert (safemarshal.Slice1D.wish
            (safemarshal.Slice1D.pure_enc obj0.(LinkSig)
             ++ ktcore.MembSlice1D.pure_enc obj0.(Hist)
             ++ ktcore.NonMemb.pure_enc obj0.(Bound)
             ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)
            obj0.(LinkSig)
            (ktcore.MembSlice1D.pure_enc obj0.(Hist)
             ++ ktcore.NonMemb.pure_enc obj0.(Bound)
             ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)) as Hls0.
  { split; [done|exact Hv0b]. }
  assert (safemarshal.Slice1D.wish
            (safemarshal.Slice1D.pure_enc obj0.(LinkSig)
             ++ ktcore.MembSlice1D.pure_enc obj0.(Hist)
             ++ ktcore.NonMemb.pure_enc obj0.(Bound)
             ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)
            obj1.(LinkSig)
            (ktcore.MembSlice1D.pure_enc obj1.(Hist)
             ++ ktcore.NonMemb.pure_enc obj1.(Bound)
             ++ safemarshal.bool.pure_enc obj1.(Err) ++ tail1)) as Hls1.
  { split; [rewrite Hr1 //|exact Hv1b]. }
  destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hls0 Hls1) as [HLS Hr2].
  (* Hist : MembSlice1D *)
  assert (ktcore.MembSlice1D.wish
            (ktcore.MembSlice1D.pure_enc obj0.(Hist)
             ++ ktcore.NonMemb.pure_enc obj0.(Bound)
             ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)
            obj0.(Hist)
            (ktcore.NonMemb.pure_enc obj0.(Bound)
             ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)) as Hh0.
  { split; [done|exact Hv0c]. }
  assert (ktcore.MembSlice1D.wish
            (ktcore.MembSlice1D.pure_enc obj0.(Hist)
             ++ ktcore.NonMemb.pure_enc obj0.(Bound)
             ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)
            obj1.(Hist)
            (ktcore.NonMemb.pure_enc obj1.(Bound)
             ++ safemarshal.bool.pure_enc obj1.(Err) ++ tail1)) as Hh1.
  { split; [rewrite Hr2 //|exact Hv1c]. }
  destruct (ktcore.MembSlice1D.wish_det _ _ _ _ Hh0 Hh1) as [HH Hr3].
  (* Bound : NonMemb *)
  assert (ktcore.NonMemb.wish
            (ktcore.NonMemb.pure_enc obj0.(Bound)
             ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)
            obj0.(Bound)
            (safemarshal.bool.pure_enc obj0.(Err) ++ tail0)) as Hbd0.
  { split; [done|exact Hv0d]. }
  assert (ktcore.NonMemb.wish
            (ktcore.NonMemb.pure_enc obj0.(Bound)
             ++ safemarshal.bool.pure_enc obj0.(Err) ++ tail0)
            obj1.(Bound)
            (safemarshal.bool.pure_enc obj1.(Err) ++ tail1)) as Hbd1.
  { split; [rewrite Hr3 //|exact Hv1d]. }
  destruct (ktcore.NonMemb.wish_det _ _ _ _ Hbd0 Hbd1) as [HBD Hr4].
  (* Err : bool *)
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
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_ChainProof sl_LinkSig ptr_Hist ptr_Bound,
  "Hstruct" ∷ ptr ↦{d} (server.HistoryReply.mk sl_ChainProof sl_LinkSig ptr_Hist ptr_Bound obj.(Err)) ∗

  "Hsl_ChainProof" ∷ sl_ChainProof ↦*{d} obj.(ChainProof) ∗
  "Hsl_LinkSig" ∷ sl_LinkSig ↦*{d} obj.(LinkSig) ∗
  "Hown_Hist" ∷ ktcore.MembSlice1D.own ptr_Hist obj.(Hist) d ∗
  "Hown_Bound" ∷ ktcore.NonMemb.own ptr_Bound obj.(Bound) d.

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! server.HistoryReplyEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_ChainProof sl_LinkSig ptr_Hist ptr_Bound)
    "(Hstruct & Hsl_ChainProof & Hsl_LinkSig & Hown_Hist & Hown_Bound)". wp_auto.
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_ChainProof]") as "* (Hsl_b & Hcap_b & Hsl_ChainProof)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_LinkSig]") as "* (Hsl_b & Hcap_b & Hsl_LinkSig)".
  wp_apply (ktcore.MembSlice1D.wp_enc with "[$Hsl_b $Hcap_b $Hown_Hist]") as "* (Hsl_b & Hcap_b & Hown_Hist)".
  wp_apply (ktcore.NonMemb.wp_enc with "[$Hsl_b $Hcap_b $Hown_Bound]") as "* (Hsl_b & Hcap_b & Hown_Bound)".
  wp_apply (safemarshal.bool.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -?app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! server.HistoryReplyDecode #sl_b
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
  - (* empty input *)
    wp_apply (safemarshal.Slice1D.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc _]. iExFalso. iPureIntro.
      rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app !u64_le_length /= in Henc. lia.
    + iDestruct "Hpost1" as (cp0 rem1) "(Ha1 & Hb1 & %Hsl1)".
      destruct Hsl1 as [Henc _]. iExFalso. iPureIntro.
      rewrite /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
  - iDestruct (ktcore.own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (safemarshal.Slice1D.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + (* ChainProof read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
      destruct Hvalid as [HvCP [HvLS [HvHist HvBound]]]. iApply "Hpost1".
      iExists obj.(ChainProof), _. iPureIntro.
      rewrite /safemarshal.Slice1D.wish. split; [|exact HvCP].
      rewrite /pure_enc in Henc. rewrite -?app_assoc in Henc. rewrite -?app_assoc. exact Henc.
    + iDestruct "Hpost1" as (cp0 rem1) "(Ha1 & Hb1 & %Hsl1)".
      wp_auto.
      wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb1]").
      iIntros (a2 b2 err2) "Hpost2". destruct err2.
      * (* LinkSig read failed *)
        wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
        destruct Hvalid as [HvCP [HvLS [HvHist HvBound]]]. iApply "Hpost2".
        assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(ChainProof)
                  (safemarshal.Slice1D.pure_enc obj.(LinkSig)
                   ++ ktcore.MembSlice1D.pure_enc obj.(Hist)
                   ++ ktcore.NonMemb.pure_enc obj.(Bound)
                   ++ safemarshal.bool.pure_enc obj.(Err) ++ tail)) as Hcp.
        { rewrite /safemarshal.Slice1D.wish. split; [|exact HvCP].
          rewrite /pure_enc in Henc. rewrite -?app_assoc in Henc. rewrite -?app_assoc. exact Henc. }
        destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1 Hcp) as [_ Hrem1].
        iExists obj.(LinkSig),
          (ktcore.MembSlice1D.pure_enc obj.(Hist) ++ ktcore.NonMemb.pure_enc obj.(Bound)
           ++ safemarshal.bool.pure_enc obj.(Err) ++ tail).
        iPureIntro. rewrite /safemarshal.Slice1D.wish. split; [|exact HvLS].
        rewrite Hrem1 -?app_assoc //.
      * iDestruct "Hpost2" as (ls0 rem2) "(Ha2 & Hb2 & %Hsl2)".
        wp_auto.
        wp_apply (ktcore.MembSlice1D.wp_dec with "[$Hb2]").
        iIntros (a3 b3 err3) "Hpost3". destruct err3.
        -- (* Hist read failed *)
           wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
           destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
           destruct Hvalid as [HvCP [HvLS [HvHist HvBound]]]. iApply "Hpost3".
           assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(ChainProof)
                     (safemarshal.Slice1D.pure_enc obj.(LinkSig)
                      ++ ktcore.MembSlice1D.pure_enc obj.(Hist)
                      ++ ktcore.NonMemb.pure_enc obj.(Bound)
                      ++ safemarshal.bool.pure_enc obj.(Err) ++ tail)) as Hcp.
           { rewrite /safemarshal.Slice1D.wish. split; [|exact HvCP].
             rewrite /pure_enc in Henc. rewrite -?app_assoc in Henc. rewrite -?app_assoc. exact Henc. }
           destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1 Hcp) as [_ Hrem1].
           assert (safemarshal.Slice1D.wish rem1 obj.(LinkSig)
                     (ktcore.MembSlice1D.pure_enc obj.(Hist) ++ ktcore.NonMemb.pure_enc obj.(Bound)
                      ++ safemarshal.bool.pure_enc obj.(Err) ++ tail)) as Hls.
           { rewrite /safemarshal.Slice1D.wish. split; [|exact HvLS]. rewrite Hrem1 -?app_assoc //. }
           destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl2 Hls) as [_ Hrem2].
           iExists obj.(Hist),
             (ktcore.NonMemb.pure_enc obj.(Bound) ++ safemarshal.bool.pure_enc obj.(Err) ++ tail).
           iPureIntro. rewrite /ktcore.MembSlice1D.wish. split; [|exact HvHist].
           rewrite Hrem2 -?app_assoc //.
        -- iDestruct "Hpost3" as (h0 rem3) "(Ha3 & Hb3 & %Hsl3)".
           wp_auto.
           wp_apply (ktcore.NonMemb.wp_dec with "[$Hb3]").
           iIntros (a4 b4 err4) "Hpost4". destruct err4.
           ++ (* Bound read failed *)
              wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
              destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
              destruct Hvalid as [HvCP [HvLS [HvHist HvBound]]]. iApply "Hpost4".
              assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(ChainProof)
                        (safemarshal.Slice1D.pure_enc obj.(LinkSig)
                         ++ ktcore.MembSlice1D.pure_enc obj.(Hist)
                         ++ ktcore.NonMemb.pure_enc obj.(Bound)
                         ++ safemarshal.bool.pure_enc obj.(Err) ++ tail)) as Hcp.
              { rewrite /safemarshal.Slice1D.wish. split; [|exact HvCP].
                rewrite /pure_enc in Henc. rewrite -?app_assoc in Henc. rewrite -?app_assoc. exact Henc. }
              destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1 Hcp) as [_ Hrem1].
              assert (safemarshal.Slice1D.wish rem1 obj.(LinkSig)
                        (ktcore.MembSlice1D.pure_enc obj.(Hist) ++ ktcore.NonMemb.pure_enc obj.(Bound)
                         ++ safemarshal.bool.pure_enc obj.(Err) ++ tail)) as Hls.
              { rewrite /safemarshal.Slice1D.wish. split; [|exact HvLS]. rewrite Hrem1 -?app_assoc //. }
              destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl2 Hls) as [_ Hrem2].
              assert (ktcore.MembSlice1D.wish rem2 obj.(Hist)
                        (ktcore.NonMemb.pure_enc obj.(Bound) ++ safemarshal.bool.pure_enc obj.(Err) ++ tail)) as Hh.
              { rewrite /ktcore.MembSlice1D.wish. split; [|exact HvHist]. rewrite Hrem2 -?app_assoc //. }
              destruct (ktcore.MembSlice1D.wish_det _ _ _ _ Hsl3 Hh) as [_ Hrem3].
              iExists obj.(Bound), (safemarshal.bool.pure_enc obj.(Err) ++ tail).
              iPureIntro. rewrite /ktcore.NonMemb.wish. split; [|exact HvBound].
              rewrite Hrem3 -?app_assoc //.
           ++ iDestruct "Hpost4" as (bd0 rem4) "(Ha4 & Hb4 & %Hsl4)".
              wp_auto.
              wp_apply (safemarshal.bool.wp_dec with "[$Hb4]").
              iIntros (a5 b5 err5) "Hpost5". destruct err5.
              ** (* Err read failed *)
                 wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
                 destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
                 destruct Hvalid as [HvCP [HvLS [HvHist HvBound]]]. iApply "Hpost5".
                 assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(ChainProof)
                           (safemarshal.Slice1D.pure_enc obj.(LinkSig)
                            ++ ktcore.MembSlice1D.pure_enc obj.(Hist)
                            ++ ktcore.NonMemb.pure_enc obj.(Bound)
                            ++ safemarshal.bool.pure_enc obj.(Err) ++ tail)) as Hcp.
                 { rewrite /safemarshal.Slice1D.wish. split; [|exact HvCP].
                   rewrite /pure_enc in Henc. rewrite -?app_assoc in Henc. rewrite -?app_assoc. exact Henc. }
                 destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1 Hcp) as [_ Hrem1].
                 assert (safemarshal.Slice1D.wish rem1 obj.(LinkSig)
                           (ktcore.MembSlice1D.pure_enc obj.(Hist) ++ ktcore.NonMemb.pure_enc obj.(Bound)
                            ++ safemarshal.bool.pure_enc obj.(Err) ++ tail)) as Hls.
                 { rewrite /safemarshal.Slice1D.wish. split; [|exact HvLS]. rewrite Hrem1 -?app_assoc //. }
                 destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl2 Hls) as [_ Hrem2].
                 assert (ktcore.MembSlice1D.wish rem2 obj.(Hist)
                           (ktcore.NonMemb.pure_enc obj.(Bound) ++ safemarshal.bool.pure_enc obj.(Err) ++ tail)) as Hh.
                 { rewrite /ktcore.MembSlice1D.wish. split; [|exact HvHist]. rewrite Hrem2 -?app_assoc //. }
                 destruct (ktcore.MembSlice1D.wish_det _ _ _ _ Hsl3 Hh) as [_ Hrem3].
                 assert (ktcore.NonMemb.wish rem3 obj.(Bound)
                           (safemarshal.bool.pure_enc obj.(Err) ++ tail)) as Hbd.
                 { rewrite /ktcore.NonMemb.wish. split; [|exact HvBound]. rewrite Hrem3 -?app_assoc //. }
                 destruct (ktcore.NonMemb.wish_det _ _ _ _ Hsl4 Hbd) as [_ Hrem4].
                 iExists obj.(Err), tail.
                 iPureIntro. rewrite /safemarshal.bool.wish. rewrite Hrem4 -?app_assoc //.
              ** (* success *)
                 iDestruct "Hpost5" as (rem5) "(Hb5 & %Hb5w)".
                 destruct Hsl1 as [Hsl1eq HvCP0]. destruct Hsl2 as [Hsl2eq HvLS0].
                 destruct Hsl3 as [Hsl3eq HvHist0]. destruct Hsl4 as [Hsl4eq HvBound0].
                 rewrite /safemarshal.bool.wish in Hb5w.
                 wp_auto.
                 wp_alloc l as "Hptr".
                 iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
                 wp_auto.
                 iApply "HΦ". iExists (HistoryReply.mk' cp0 ls0 h0 bd0 a5), rem5.
                 iFrame "Hb5". iSplitL "Hptr Ha1 Ha2 Ha3 Ha4".
                 { iExists a1, a2, a3, a4. iFrame "Hptr Ha1 Ha2 Ha3 Ha4". }
                 iPureIntro. rewrite /wish /pure_enc /valid. split.
                 --- rewrite Hsl1eq Hsl2eq Hsl3eq Hsl4eq Hb5w -?app_assoc //.
                 --- split; [exact HvCP0|split; [exact HvLS0|split; [exact HvHist0|exact HvBound0]]].
Qed.

End proof.
End HistoryReply.

Module AuditArg.
Record t :=
  mk' {
    PrevEpoch: w64;
  }.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc obj.(PrevEpoch).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /safemarshal.w64.pure_enc.
  intros -> Heq.
  apply app_inj_1 in Heq as [Hpe Htail]; [|len].
  apply (inj u64_le) in Hpe.
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  "Hstruct" ∷ ptr ↦{d} (server.AuditArg.mk obj.(PrevEpoch)).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! server.AuditArgEncode #sl_b #ptr_obj
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
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! server.AuditArgDecode #sl_b
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
  - iDestruct (ktcore.own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (safemarshal.w64.wp_dec with "[$Hsl_b]").
    iIntros (ep b1 err1) "Hpost1".
    destruct err1.
    + (* PrevEpoch read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      iApply "Hpost1". iExists obj.(PrevEpoch), _. iPureIntro.
      rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc.
      rewrite /wish /pure_enc /safemarshal.w64.pure_enc in Hwish.
      rewrite -?app_assoc in Hwish. exact Hwish.
    + iDestruct "Hpost1" as (rem1) "[Hb1 %Hw64a]".
      rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc in Hw64a.
      wp_auto.
      wp_alloc l as "Hptr".
      iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
      wp_auto.
      iApply "HΦ". iExists (AuditArg.mk' ep), rem1.
      rewrite /own. iFrame "Hptr Hb1".
      iPureIntro. rewrite /wish /pure_enc /safemarshal.w64.pure_enc.
      rewrite Hw64a -?app_assoc. done.
Qed.

End proof.
End AuditArg.

Module AuditReply.
Record t :=
  mk' {
    P: list ktcore.AuditProof.t;
    Err: bool;
  }.

Definition pure_enc obj :=
  ktcore.AuditProofSlice1D.pure_enc obj.(P) ++
  safemarshal.bool.pure_enc obj.(Err).

Definition valid obj :=
  ktcore.AuditProofSlice1D.valid obj.(P).

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
  assert (ktcore.AuditProofSlice1D.wish b obj0.(P)
            (safemarshal.bool.pure_enc obj0.(Err) ++ tail0)) as Hw0.
  { split; [|exact Hvld0]. rewrite Henc0 /pure_enc -app_assoc //. }
  assert (ktcore.AuditProofSlice1D.wish b obj1.(P)
            (safemarshal.bool.pure_enc obj1.(Err) ++ tail1)) as Hw1.
  { split; [|exact Hvld1]. rewrite Henc1 /pure_enc -app_assoc //. }
  destruct (ktcore.AuditProofSlice1D.wish_det _ _ _ _ Hw0 Hw1) as [HP Hrest].
  assert (safemarshal.bool.wish
            (safemarshal.bool.pure_enc obj0.(Err) ++ tail0) obj0.(Err) tail0) as Hb0.
  { rewrite /safemarshal.bool.wish //. }
  assert (safemarshal.bool.wish
            (safemarshal.bool.pure_enc obj0.(Err) ++ tail0) obj1.(Err) tail1) as Hb1.
  { rewrite /safemarshal.bool.wish Hrest //. }
  destruct (safemarshal.bool.wish_det _ _ _ _ Hb0 Hb1) as [HErr Htail].
  split; [|exact Htail].
  destruct obj0, obj1. simpl in *. by subst.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ ptr_P,
  "Hstruct" ∷ ptr ↦{d} (server.AuditReply.mk ptr_P obj.(Err)) ∗

  "Hown_P" ∷ ktcore.AuditProofSlice1D.own ptr_P obj.(P) d.

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! server.AuditReplyEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (ptr_P) "(Hstruct & Hown_P)". wp_auto.
  wp_apply (ktcore.AuditProofSlice1D.wp_enc with "[$Hsl_b $Hcap_b $Hown_P]") as "* (Hsl_b & Hcap_b & Hown_P)".
  wp_apply (safemarshal.bool.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -?app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! server.AuditReplyDecode #sl_b
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
  - (* empty input *)
    wp_apply (ktcore.AuditProofSlice1D.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc _]. iExFalso. iPureIntro.
      rewrite /pure_enc /ktcore.AuditProofSlice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
    + iDestruct "Hpost1" as (p0 rem1) "(Ha1 & Hb1 & %Hsl1)".
      destruct Hsl1 as [Henc _]. iExFalso. iPureIntro.
      rewrite /ktcore.AuditProofSlice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
  - iDestruct (ktcore.own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (ktcore.AuditProofSlice1D.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + (* P read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid. iApply "Hpost1".
      iExists obj.(P), _. iPureIntro.
      rewrite /ktcore.AuditProofSlice1D.wish. split; [|exact Hvalid].
      rewrite /pure_enc in Henc. rewrite -?app_assoc in Henc. rewrite -?app_assoc. exact Henc.
    + iDestruct "Hpost1" as (p0 rem1) "(Ha1 & Hb1 & %Hsl1)".
      wp_auto.
      wp_apply (safemarshal.bool.wp_dec with "[$Hb1]").
      iIntros (a2 b2 err2) "Hpost2". destruct err2.
      * (* Err read failed *)
        wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid. iApply "Hpost2".
        assert (ktcore.AuditProofSlice1D.wish (b0 :: brest) obj.(P)
                  (safemarshal.bool.pure_enc obj.(Err) ++ tail)) as Hp.
        { rewrite /ktcore.AuditProofSlice1D.wish. split; [|exact Hvalid].
          rewrite /pure_enc in Henc. rewrite -?app_assoc in Henc. rewrite -?app_assoc. exact Henc. }
        destruct (ktcore.AuditProofSlice1D.wish_det _ _ _ _ Hsl1 Hp) as [_ Hrem1].
        iExists obj.(Err), tail.
        iPureIntro. rewrite /safemarshal.bool.wish. rewrite Hrem1 -?app_assoc //.
      * (* success *)
        iDestruct "Hpost2" as (rem2) "(Hb2 & %Hb2w)".
        destruct Hsl1 as [Hsl1eq Hvld0].
        rewrite /safemarshal.bool.wish in Hb2w.
        wp_auto.
        wp_alloc l as "Hptr".
        iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
        wp_auto.
        iApply "HΦ". iExists (AuditReply.mk' p0 a2), rem2.
        iFrame "Hb2". iSplitL "Hptr Ha1".
        { iExists a1. iFrame "Hptr Ha1". }
        iPureIntro. rewrite /wish /pure_enc /valid.
        split; [rewrite Hsl1eq Hb2w -?app_assoc // | exact Hvld0].
Qed.

End proof.
End AuditReply.

End server.
