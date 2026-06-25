From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import safemarshal.
From New.proof.github_com.tchajed Require Import marshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import base.

(** core serde spec requirements:
- deterministic encoding of object.
- optional correctness: encoded object decodes to same object.
- security: specs usable even for weak caller.
- "composable". e.g., predicates on struct re-use field predicates.

impl:
- [pure_enc] gives deterministic encoding.
- [wish] transports correctness from encoder to decoder.
it's just [pure_enc] plus a [valid] predicate.
[valid] says that variable-length objects (e.g., lists)
have lengths that fit within the s64 slice length.
- [pure_enc] and [valid] of bigger objects is the
[pure_enc] and [valid] of their components. *)

(* generic injectivity for list encodings of the form
   [mjoin (enc <$> l)], reducing to element-level injectivity. *)
Lemma mjoin_enc_inj {A} (enc : A → list w8) (valid : A → Prop) l0 l1 t0 t1 :
  (∀ a0 a1 s0 s1, valid a0 → valid a1 →
     enc a0 ++ s0 = enc a1 ++ s1 → a0 = a1 ∧ s0 = s1) →
  length l0 = length l1 →
  Forall valid l0 → Forall valid l1 →
  mjoin (enc <$> l0) ++ t0 = mjoin (enc <$> l1) ++ t1 →
  l0 = l1 ∧ t0 = t1.
Proof.
  intros Hinj. revert l1 t0 t1.
  induction l0 as [|a0 l0 IH]; intros [|a1 l1] t0 t1 Hlen Hv0 Hv1 Heq;
    simpl in *; [by simplify_eq/=|done|done|].
  injection Hlen as Hlen.
  apply Forall_cons in Hv0 as [Hv0a Hv0].
  apply Forall_cons in Hv1 as [Hv1a Hv1].
  rewrite -!app_assoc in Heq.
  apply Hinj in Heq as [-> Heq]; [|done..].
  apply IH in Heq as [-> ->]; [|done..].
  done.
Qed.

Module ktcore.

Notation VrfSigTag := 0 (only parsing).
Notation LinkSigTag := 1 (only parsing).

Section dfrac_valid.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

(* A non-empty byte slice owns at least one element heap-pointsto, from which
   the dfrac's validity follows. (Empty slices own nothing, so this fails for
   them — the root of the zero-sized-alloc issue, e.g. hashchain.v.) This is the
   missing piece for decoders: the freshly-[GoAlloc]ed result struct is owned at
   [DfracOwn 1] but [own _ d] needs it at the input dfrac [d]; downgrading via
   [dfractional_update_to_dfrac] needs [✓ d]. *)
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

Module VrfSig.
Record t :=
  mk' {
    SigTag: w8;
    VrfPk: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.w8.pure_enc obj.(SigTag) ++
  safemarshal.Slice1D.pure_enc obj.(VrfPk).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(VrfPk).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid
    /safemarshal.w8.pure_enc /safemarshal.Slice1D.pure_enc
    /safemarshal.w64.pure_enc /safemarshal.Slice1D.valid.
  intros (-> & Hv0) (Heq & Hv1).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Htag Heq]; [|done].
  apply app_inj_1 in Heq as [Hlen Heq]; [|len].
  apply (inj u64_le) in Hlen.
  assert (length obj0.(VrfPk) = length obj1.(VrfPk)) by word.
  apply app_inj_1 in Heq as [Hpk Htail]; [|done].
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_VrfPk,
  "Hstr_VrfSig" ∷ ptr ↦{d} (ktcore.VrfSig.mk obj.(SigTag) sl_VrfPk) ∗

  "Hsl_VrfPk" ∷ sl_VrfPk ↦*{d} obj.(VrfPk).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.VrfSigEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_VrfPk) "[Hstr_VrfSig Hsl_VrfPk]". wp_auto.
  wp_apply (safemarshal.w8.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_VrfPk]") as "* (Hsl_b & Hcap_b & Hsl_VrfPk)".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -!app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.VrfSigDecode #sl_b
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
  - (* empty input: a valid encoding needs ≥ 9 bytes, so none exists *)
    wp_apply (safemarshal.w8.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1".
    destruct err1.
    + wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc _]. iExFalso. iPureIntro.
      rewrite /pure_enc /safemarshal.w8.pure_enc /safemarshal.Slice1D.pure_enc
        /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
    + iDestruct "Hpost1" as (rem1) "[Hb1 %Hw8]".
      rewrite /safemarshal.w8.wish /safemarshal.w8.pure_enc in Hw8.
      iExFalso. iPureIntro. apply (f_equal length) in Hw8. rewrite /= in Hw8. lia.
  - (* non-empty input: extract validity of [d] from the input slice. *)
    iDestruct (own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (safemarshal.w8.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1".
    destruct err1.
    + (* SigTag read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc _]. iApply "Hpost1".
      iExists obj.(SigTag), (safemarshal.Slice1D.pure_enc obj.(VrfPk) ++ tail).
      iPureIntro. rewrite /safemarshal.w8.wish /safemarshal.w8.pure_enc.
      rewrite /pure_enc /safemarshal.w8.pure_enc in Henc.
      rewrite app_assoc. exact Henc.
    + iDestruct "Hpost1" as (rem1) "[Hb1 %Hw8]".
      rewrite /safemarshal.w8.wish /safemarshal.w8.pure_enc in Hw8.
      wp_auto.
      wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb1]").
      iIntros (a2 b2 err2) "Hpost2".
      destruct err2.
      * (* VrfPk read failed *)
        wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        destruct Hwish as [Henc Hvalid]. iApply "Hpost2".
        iExists obj.(VrfPk), tail. iPureIntro.
        rewrite /pure_enc /safemarshal.w8.pure_enc in Henc.
        rewrite Hw8 in Henc. rewrite -app_assoc in Henc.
        apply app_inj_1 in Henc as [_ Hrem1]; [|done].
        rewrite /safemarshal.Slice1D.wish. split; [exact Hrem1|exact Hvalid].
      * (* success *)
        iDestruct "Hpost2" as (vrfpk rem2) "(Ha2 & Hb2 & %Hsl1)".
        destruct Hsl1 as [Hrem1 Hvvalid].
        wp_auto.
        wp_alloc l as "Hptr".
        iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
        wp_auto.
        iApply "HΦ". iExists (VrfSig.mk' a1 vrfpk), rem2.
        iFrame "Hb2". iSplitL "Hptr Ha2".
        { iExists a2. iFrame "Hptr Ha2". }
        iPureIntro. rewrite /wish /pure_enc /valid /safemarshal.w8.pure_enc. split.
        -- rewrite Hw8 Hrem1 -app_assoc. done.
        -- exact Hvvalid.
Qed.

End proof.
End VrfSig.

Module LinkSig.
Record t :=
  mk' {
    SigTag: w8;
    Epoch: w64;
    Link: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.w8.pure_enc obj.(SigTag) ++
  safemarshal.w64.pure_enc obj.(Epoch) ++
  safemarshal.Slice1D.pure_enc obj.(Link).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(Link).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid
    /safemarshal.w8.pure_enc /safemarshal.w64.pure_enc
    /safemarshal.Slice1D.pure_enc /safemarshal.Slice1D.valid.
  intros (-> & Hv0) (Heq & Hv1).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Htag Heq]; [|done].
  apply app_inj_1 in Heq as [Hep Heq]; [|len].
  apply (inj u64_le) in Hep.
  apply app_inj_1 in Heq as [Hlen Heq]; [|len].
  apply (inj u64_le) in Hlen.
  assert (length obj0.(Link) = length obj1.(Link)) by word.
  apply app_inj_1 in Heq as [Hlink Htail]; [|done].
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_Link,
  "Hstr_LinkSig" ∷ ptr ↦{d} (ktcore.LinkSig.mk obj.(SigTag) obj.(Epoch) sl_Link) ∗

  "Hsl_Link" ∷ sl_Link ↦*{d} obj.(Link).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.LinkSigEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_Link) "[Hstr_LinkSig Hsl_Link]". wp_auto.
  wp_apply (safemarshal.w8.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_Link]") as "* (Hsl_b & Hcap_b & Hsl_Link)".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -!app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.LinkSigDecode #sl_b
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
  - wp_apply (safemarshal.w8.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1".
    destruct err1.
    + wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc _]. iExFalso. iPureIntro.
      rewrite /pure_enc /safemarshal.w8.pure_enc /safemarshal.w64.pure_enc
        /safemarshal.Slice1D.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
    + iDestruct "Hpost1" as (rem1) "[Hb1 %Hw8]".
      rewrite /safemarshal.w8.wish /safemarshal.w8.pure_enc in Hw8.
      iExFalso. iPureIntro. apply (f_equal length) in Hw8. rewrite /= in Hw8. lia.
  - iDestruct (own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (safemarshal.w8.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1".
    destruct err1.
    + (* SigTag read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc _]. iApply "Hpost1".
      iExists obj.(SigTag), _.
      iPureIntro. rewrite /safemarshal.w8.wish.
      rewrite /pure_enc in Henc. rewrite -!app_assoc in Henc. exact Henc.
    + iDestruct "Hpost1" as (rem1) "[Hb1 %Hw8]".
      rewrite /safemarshal.w8.wish /safemarshal.w8.pure_enc in Hw8.
      wp_auto.
      wp_apply (safemarshal.w64.wp_dec with "[$Hb1]").
      iIntros (ep b2 err2) "Hpost2".
      destruct err2.
      * (* Epoch read failed *)
        wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        destruct Hwish as [Henc _]. iApply "Hpost2".
        iExists obj.(Epoch), _.
        iPureIntro. rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc.
        rewrite /pure_enc /safemarshal.w8.pure_enc /safemarshal.w64.pure_enc in Henc.
        rewrite Hw8 in Henc. rewrite -!app_assoc in Henc.
        apply app_inj_1 in Henc as [_ Hrem1]; [|done]. exact Hrem1.
      * iDestruct "Hpost2" as (rem2) "[Hb2 %Hw64]".
        rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc in Hw64.
        wp_auto.
        wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb2]").
        iIntros (a3 b3 err3) "Hpost3".
        destruct err3.
        -- (* Link read failed *)
           wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
           destruct Hwish as [Henc Hvalid]. iApply "Hpost3".
           iExists obj.(Link), tail. iPureIntro.
           rewrite /pure_enc /safemarshal.w8.pure_enc /safemarshal.w64.pure_enc in Henc.
           rewrite Hw8 in Henc. rewrite -!app_assoc in Henc.
           apply app_inj_1 in Henc as [_ Hrem1]; [|done].
           rewrite Hw64 in Hrem1. rewrite -?app_assoc in Hrem1.
           apply app_inj_1 in Hrem1 as [_ Hrem2]; [|len].
           rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc -?app_assoc.
            split; [exact Hrem2|exact Hvalid].
        -- (* success *)
           iDestruct "Hpost3" as (link rem3) "(Ha3 & Hb3 & %Hsl1)".
           destruct Hsl1 as [Hrem2 Hvvalid].
           wp_auto.
           wp_alloc l as "Hptr".
           iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
           wp_auto.
           iApply "HΦ". iExists (LinkSig.mk' a1 ep link), rem3.
           iFrame "Hb3". iSplitL "Hptr Ha3".
           { iExists a3. iFrame "Hptr Ha3". }
           iPureIntro. rewrite /wish /pure_enc /valid
             /safemarshal.w8.pure_enc /safemarshal.w64.pure_enc
             /safemarshal.Slice1D.pure_enc. split.
           ++ rewrite /safemarshal.Slice1D.pure_enc in Hrem2.
              rewrite Hw8 Hw64 Hrem2 -!app_assoc. done.
           ++ exact Hvvalid.
Qed.

End proof.
End LinkSig.

Module MapLabel.
Record t :=
  mk' {
    Uid: w64;
    Ver: w64;
  }.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc obj.(Uid) ++
  safemarshal.w64.pure_enc obj.(Ver).

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
  apply app_inj_1 in Heq as [Hver Htail]; [|len].
  apply (inj u64_le) in Hver.
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  "Hstruct" ∷ ptr ↦{d} (ktcore.MapLabel.mk obj.(Uid) obj.(Ver)).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.MapLabelEncode #sl_b #ptr_obj
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
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -!app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.MapLabelDecode #sl_b
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
    iIntros (uid b1 err1) "Hpost1".
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
    iIntros (uid b1 err1) "Hpost1".
    destruct err1.
    + (* Uid read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      iApply "Hpost1". iExists obj.(Uid), _. iPureIntro.
      rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc.
      rewrite /wish /pure_enc /safemarshal.w64.pure_enc in Hwish.
      rewrite -?app_assoc in Hwish. exact Hwish.
    + iDestruct "Hpost1" as (rem1) "[Hb1 %Hw64a]".
      rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc in Hw64a.
      wp_auto.
      wp_apply (safemarshal.w64.wp_dec with "[$Hb1]").
      iIntros (ver b2 err2) "Hpost2".
      destruct err2.
      * (* Ver read failed *)
        wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        iApply "Hpost2". iExists obj.(Ver), _. iPureIntro.
        rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc.
        rewrite /wish /pure_enc /safemarshal.w64.pure_enc in Hwish.
        rewrite Hw64a in Hwish. rewrite -?app_assoc in Hwish.
        apply app_inj_1 in Hwish as [_ Hrem1]; [|len]. exact Hrem1.
      * iDestruct "Hpost2" as (rem2) "[Hb2 %Hw64b]".
        rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc in Hw64b.
        wp_auto.
        wp_alloc l as "Hptr".
        iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
        wp_auto.
        iApply "HΦ". iExists (MapLabel.mk' uid ver), rem2.
        rewrite /own. iFrame "Hptr Hb2".
        iPureIntro. rewrite /wish /pure_enc /safemarshal.w64.pure_enc.
        rewrite Hw64a Hw64b -?app_assoc. done.
Qed.

End proof.
End MapLabel.

Module CommitOpen.
Record t :=
  mk' {
    Val: list w8;
    Rand: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.Slice1D.pure_enc obj.(Val) ++
  safemarshal.Slice1D.pure_enc obj.(Rand).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(Val) ∧
  safemarshal.Slice1D.valid obj.(Rand).

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
  apply app_inj_1 in Heq as [Hl1 Heq]; [|len].
  apply (inj u64_le) in Hl1.
  assert (length obj0.(Val) = length obj1.(Val)) by word.
  apply app_inj_1 in Heq as [Hval Heq]; [|done].
  apply app_inj_1 in Heq as [Hl2 Heq]; [|len].
  apply (inj u64_le) in Hl2.
  assert (length obj0.(Rand) = length obj1.(Rand)) by word.
  apply app_inj_1 in Heq as [Hrand Htail]; [|done].
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_Val sl_Rand,
  "Hstr_CommitOpen" ∷ ptr ↦{d} (ktcore.CommitOpen.mk sl_Val sl_Rand) ∗

  "Hsl_Val" ∷ sl_Val ↦*{d} obj.(Val) ∗
  "Hsl_Rand" ∷ sl_Rand ↦*{d} obj.(Rand).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.CommitOpenEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_Val sl_Rand) "(Hstr_CommitOpen & Hsl_Val & Hsl_Rand)". wp_auto.
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_Val]") as "* (Hsl_b & Hcap_b & Hsl_Val)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_Rand]") as "* (Hsl_b & Hcap_b & Hsl_Rand)".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -!app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.CommitOpenDecode #sl_b
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
    iIntros (a1 b1 err1) "Hpost1".
    destruct err1.
    + wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc _]. iExFalso. iPureIntro.
      rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
    + iDestruct "Hpost1" as (val0 rem1) "(Ha1 & Hb1 & %Hsl1a)".
      destruct Hsl1a as [Henc _]. iExFalso. iPureIntro.
      rewrite /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
  - iDestruct (own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (safemarshal.Slice1D.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1".
    destruct err1.
    + (* Val read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
      destruct Hvalid as [HvVal _]. iApply "Hpost1".
      iExists obj.(CommitOpen.Val), _. iPureIntro.
      rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc
        -?app_assoc.
      split; [|exact HvVal].
      rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      rewrite -?app_assoc in Henc. exact Henc.
    + iDestruct "Hpost1" as (val0 rem1) "(Ha1 & Hb1 & %Hsl1a)".
      wp_auto.
      wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb1]").
      iIntros (a2 b2 err2) "Hpost2".
      destruct err2.
      * (* Rand read failed *)
        wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
        destruct Hvalid as [HvVal HvRand]. iApply "Hpost2".
        iExists obj.(CommitOpen.Rand), tail. iPureIntro.
        assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(CommitOpen.Val)
                  (safemarshal.Slice1D.pure_enc obj.(CommitOpen.Rand) ++ tail)) as Hw'.
        { rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
            /safemarshal.w64.pure_enc -?app_assoc. split; [|exact HvVal].
          rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
          rewrite -?app_assoc in Henc. exact Henc. }
        destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1a Hw') as [_ Hrem1].
        rewrite /safemarshal.Slice1D.wish. split; [exact Hrem1|exact HvRand].
      * (* success *)
        iDestruct "Hpost2" as (rand0 rem2) "(Ha2 & Hb2 & %Hsl1b)".
        destruct Hsl1a as [Hb_eq HvVal0]. destruct Hsl1b as [Hrem1_eq HvRand0].
        wp_auto.
        wp_alloc l as "Hptr".
        iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
        wp_auto.
        iApply "HΦ". iExists (CommitOpen.mk' val0 rand0), rem2.
        iFrame "Hb2". iSplitL "Hptr Ha1 Ha2".
        { iExists a1, a2. iFrame "Hptr Ha1 Ha2". }
        iPureIntro. rewrite /wish /pure_enc /valid. split.
        -- rewrite Hb_eq Hrem1_eq -?app_assoc. done.
        -- split; [exact HvVal0|exact HvRand0].
Qed.

End proof.
End CommitOpen.

Module Memb.
Record t :=
  mk' {
    LabelProof: list w8;
    PkOpen: CommitOpen.t;
    MerkleProof: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.Slice1D.pure_enc obj.(LabelProof) ++
  CommitOpen.pure_enc obj.(PkOpen) ++
  safemarshal.Slice1D.pure_enc obj.(MerkleProof).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(LabelProof) ∧
  CommitOpen.valid obj.(PkOpen) ∧
  safemarshal.Slice1D.valid obj.(MerkleProof).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid
    /CommitOpen.pure_enc /CommitOpen.valid
    /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc
    /safemarshal.Slice1D.valid.
  intros (-> & Hv0a & (Hv0b & Hv0c) & Hv0d) (Heq & Hv1a & (Hv1b & Hv1c) & Hv1d).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Hpre1 Heq]; [|len].
  apply (inj u64_le) in Hpre1.
  assert (length obj0.(LabelProof) = length obj1.(LabelProof)) by word.
  apply app_inj_1 in Heq as [Hlp Heq]; [|done].
  apply app_inj_1 in Heq as [Hpre2 Heq]; [|len].
  apply (inj u64_le) in Hpre2.
  assert (length obj0.(PkOpen).(CommitOpen.Val) = length obj1.(PkOpen).(CommitOpen.Val)) by word.
  apply app_inj_1 in Heq as [Hval Heq]; [|done].
  apply app_inj_1 in Heq as [Hpre3 Heq]; [|len].
  apply (inj u64_le) in Hpre3.
  assert (length obj0.(PkOpen).(CommitOpen.Rand) = length obj1.(PkOpen).(CommitOpen.Rand)) by word.
  apply app_inj_1 in Heq as [Hrand Heq]; [|done].
  apply app_inj_1 in Heq as [Hpre4 Heq]; [|len].
  apply (inj u64_le) in Hpre4.
  assert (length obj0.(MerkleProof) = length obj1.(MerkleProof)) by word.
  apply app_inj_1 in Heq as [Hmp Htail]; [|done].
  destruct obj0 as [LP0 [Val0 Rand0] MP0], obj1 as [LP1 [Val1 Rand1] MP1].
  by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_LabelProof ptr_PkOpen sl_MerkleProof,
  "Hstr_Memb" ∷ ptr ↦{d} (ktcore.Memb.mk sl_LabelProof ptr_PkOpen sl_MerkleProof) ∗

  "Hsl_LabelProof" ∷ sl_LabelProof ↦*{d} obj.(LabelProof) ∗
  "Hown_PkOpen" ∷ CommitOpen.own ptr_PkOpen obj.(PkOpen) d ∗
  "Hsl_MerkleProof" ∷ sl_MerkleProof ↦*{d} obj.(MerkleProof).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.MembEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_LabelProof ptr_PkOpen sl_MerkleProof) "(Hstr_Memb & Hsl_LabelProof & Hown_PkOpen & Hsl_MerkleProof)". wp_auto.
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_LabelProof]") as "* (Hsl_b & Hcap_b & Hsl_LabelProof)".
  wp_apply (CommitOpen.wp_enc with "[$Hsl_b $Hcap_b $Hown_PkOpen]") as "* (Hsl_b & Hcap_b & Hown_PkOpen)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_MerkleProof]") as "* (Hsl_b & Hcap_b & Hsl_MerkleProof)".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -?app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.MembDecode #sl_b
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
      rewrite /pure_enc /CommitOpen.pure_enc /safemarshal.Slice1D.pure_enc
        /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
    + iDestruct "Hpost1" as (lp0 rem1) "(Ha1 & Hb1 & %Hsl1a)".
      destruct Hsl1a as [Henc _]. iExFalso. iPureIntro.
      rewrite /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
  - iDestruct (own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (safemarshal.Slice1D.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + (* LabelProof read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
      destruct Hvalid as [HvLP _]. iApply "Hpost1".
      iExists obj.(LabelProof), _. iPureIntro.
      rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc
        -?app_assoc. split; [|exact HvLP].
      rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      rewrite -?app_assoc in Henc. exact Henc.
    + iDestruct "Hpost1" as (lp0 rem1) "(Ha1 & Hb1 & %Hsl1a)".
      wp_auto.
      wp_apply (CommitOpen.wp_dec with "[$Hb1]").   (* nested PkOpen *)
      iIntros (a2 b2 err2) "Hpost2". destruct err2.
      * (* PkOpen read failed *)
        wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
        destruct Hvalid as [HvLP [HvPk _]]. iApply "Hpost2".
        iExists obj.(PkOpen), (safemarshal.Slice1D.pure_enc obj.(MerkleProof) ++ tail). iPureIntro.
        assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(LabelProof)
                  (CommitOpen.pure_enc obj.(PkOpen)
                   ++ safemarshal.Slice1D.pure_enc obj.(MerkleProof) ++ tail)) as Hw1.
        { rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
            /safemarshal.w64.pure_enc -?app_assoc. split; [|exact HvLP].
          rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
          rewrite -?app_assoc in Henc. exact Henc. }
        destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
        rewrite /CommitOpen.wish. split; [exact Hrem1|exact HvPk].
      * iDestruct "Hpost2" as (pko0 rem2) "(Hown_pko & Hb2 & %Hsl1b)".
        wp_auto.
        wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb2]").
        iIntros (a3 b3 err3) "Hpost3". destruct err3.
        -- (* MerkleProof read failed *)
           wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
           destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
           destruct Hvalid as [HvLP [HvPk HvMP]]. iApply "Hpost3".
           iExists obj.(MerkleProof), tail. iPureIntro.
           assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(LabelProof)
                     (CommitOpen.pure_enc obj.(PkOpen)
                      ++ safemarshal.Slice1D.pure_enc obj.(MerkleProof) ++ tail)) as Hw1.
           { rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
               /safemarshal.w64.pure_enc -?app_assoc. split; [|exact HvLP].
             rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
             rewrite -?app_assoc in Henc. exact Henc. }
           destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
           assert (CommitOpen.wish rem1 obj.(PkOpen)
                     (safemarshal.Slice1D.pure_enc obj.(MerkleProof) ++ tail)) as Hw2.
           { rewrite /CommitOpen.wish. split; [exact Hrem1|exact HvPk]. }
           destruct (CommitOpen.wish_det _ _ _ _ Hsl1b Hw2) as [_ Hrem2].
           rewrite /safemarshal.Slice1D.wish. split; [exact Hrem2|exact HvMP].
        -- (* success *)
           iDestruct "Hpost3" as (mp0 rem3) "(Ha3 & Hb3 & %Hsl1c)".
           destruct Hsl1a as [Hb_eq HvLP0]. destruct Hsl1b as [Hrem1_eq HvPk0].
           destruct Hsl1c as [Hrem2_eq HvMP0].
           wp_auto.
           wp_alloc l as "Hptr".
           iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
           wp_auto.
           iApply "HΦ". iExists (Memb.mk' lp0 pko0 mp0), rem3.
           iFrame "Hb3". iSplitL "Hptr Ha1 Hown_pko Ha3".
           { iExists a1, a2, a3. iFrame "Hptr Ha1 Hown_pko Ha3". }
           iPureIntro. rewrite /wish /pure_enc /valid. split.
           ++ rewrite Hb_eq Hrem1_eq Hrem2_eq -?app_assoc. done.
           ++ split; [exact HvLP0|split; [exact HvPk0|exact HvMP0]].
Qed.

End proof.
End Memb.

Module MembSlice1D.
Definition t := list Memb.t.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc (W64 $ length obj) ++ mjoin (Memb.pure_enc <$> obj).

Definition valid (obj : t) :=
  sint.Z (W64 (length obj)) = length obj ∧
  Forall (λ x, Memb.valid x) obj.

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid /safemarshal.w64.pure_enc.
  intros (-> & Hlen0 & Hvf0) (Heq & Hlen1 & Hvf1).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Hl Heq]; [|len].
  apply (inj u64_le) in Hl.
  assert (length obj0 = length obj1) by word.
  assert (Hinj : ∀ a0 a1 s0 s1, Memb.valid a0 → Memb.valid a1 →
    Memb.pure_enc a0 ++ s0 = Memb.pure_enc a1 ++ s1 → a0 = a1 ∧ s0 = s1).
  { intros a0 a1 s0 s1 Hva0 Hva1 Henc.
    apply (Memb.wish_det s0 s1 a0 a1 (b := Memb.pure_enc a0 ++ s0));
      rewrite /Memb.wish; by split. }
  apply (mjoin_enc_inj _ _ _ _ _ _ Hinj) in Heq as [-> ->]; done.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ ptr0,
  ptr ↦*{d} ptr0 ∗
  ([∗ list] ptr;obj ∈ ptr0;obj,
    Memb.own ptr obj d).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.MembSlice1DEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (ptr0) "[Hsl_obj Hbig]".
  iDestruct (own_slice_len with "Hsl_obj") as %[Hlen0 ?].
  iDestruct (big_sepL2_length with "Hbig") as %Hlen_eq.
  wp_auto.
  wp_apply (marshal.wp_WriteInt with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iAssert (∃ (j : w64) (sl_cur : slice.t) (ev : loc),
    "i" ∷ i_ptr ↦ j ∗
    "%Hj" ∷ ⌜0 ≤ sint.Z j ≤ length obj⌝ ∗
    "e" ∷ e_ptr ↦ ev ∗
    "b" ∷ b_ptr ↦ sl_cur ∗
    "Hsl_b" ∷ sl_cur ↦* (b ++ u64_le ptr_obj.(slice.len)
                          ++ mjoin (Memb.pure_enc <$> take (sint.nat j) obj)) ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_cur 1 ∗
    "Hsl_obj" ∷ ptr_obj ↦*{d} ptr0 ∗
    "Hbig" ∷ ([∗ list] ptr;o ∈ ptr0;obj, Memb.own ptr o d))%I
    with "[-HΦ]" as "IH".
  { iExists (W64 0), s', null. rewrite take_0 /= app_nil_r. iFrame "∗". iPureIntro. word. }
  wp_for "IH".
  case_bool_decide.
  2: { wp_auto.
       iApply "HΦ".
       iFrame "Hcap_b".
       iSplitL "Hsl_b".
       { iExactEq "Hsl_b".
         replace (sint.nat j) with (length obj) by word.
         rewrite take_ge; [|lia].
         rewrite /pure_enc /safemarshal.w64.pure_enc.
         replace (W64 (length obj)) with ptr_obj.(slice.len) by word.
         done. }
       iExists ptr0. iFrame "Hsl_obj Hbig". }
  (* body *)
  list_elem ptr0 (sint.Z j) as pj.
  list_elem obj (sint.Z j) as oj.
  wp_auto.
  rewrite decide_True; last word.
  wp_apply (wp_load_slice_index with "[$Hsl_obj]") as "Hsl_obj".
  { word. }
  { eauto. }
  iDestruct (big_sepL2_lookup_acc with "Hbig") as "[Hown_j Hbig_close]";
    [exact Hpj_lookup | exact Hoj_lookup |].
  wp_apply (Memb.wp_enc with "[$Hsl_b $Hcap_b $Hown_j]") as "* (Hsl_b & Hcap_b & Hown_j)".
  iDestruct ("Hbig_close" with "Hown_j") as "Hbig".
  wp_for_post.
  iFrame.
  iSplitR; [iPureIntro; word|].
  iExactEq "Hsl_b".
  replace (sint.nat (word.add j (W64 1))) with (S (sint.nat j)) by word.
  rewrite (take_S_r _ _ oj); [|exact Hoj_lookup].
  rewrite fmap_app join_app /= app_nil_r -!app_assoc.
  done.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.MembSlice1DDecode #sl_b
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
  - (* empty input: ReadInt cannot read a length prefix *)
    wp_apply (safemarshal.w64.wp_dec with "[$Hsl_b]").
    iIntros (length0 b1 err1) "Hpost1". destruct err1.
    + wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc _]. iExFalso. iPureIntro.
      rewrite /pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
    + iDestruct "Hpost1" as (tail1) "(Hb1 & %Hwish1)".
      rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc in Hwish1.
      iExFalso. iPureIntro.
      apply (f_equal length) in Hwish1. rewrite length_app u64_le_length /= in Hwish1. lia.
  - iDestruct (own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (safemarshal.w64.wp_dec with "[$Hsl_b]").
    iIntros (length0 b1 err1) "Hpost1". destruct err1.
    + (* ReadInt failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc _]. iApply "Hpost1".
      iExists (W64 (length obj)), (mjoin (Memb.pure_enc <$> obj) ++ tail). iPureIntro.
      rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc Henc /pure_enc
        /safemarshal.w64.pure_enc -app_assoc //.
    + iDestruct "Hpost1" as (tail1) "(Hb1 & %Hwish1)".
      wp_auto.
      wp_if_destruct.
      * (* length0 < 0 : invalid length, error *)
        rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc in Hwish1.
        iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid. destruct Hvalid as [Hvlen _].
        exfalso.
        rewrite /pure_enc /safemarshal.w64.pure_enc -app_assoc in Henc.
        rewrite Hwish1 in Henc.
        apply app_inj_1 in Henc as [Hpre _]; [|len].
        apply (inj u64_le) in Hpre.
        word.
      * (* length0 >= 0 : decode loop *)
        wp_apply wp_slice_make3; first word.
        iIntros (lo_sl) "(Hlo & Hcap & %Hlocap)".
        wp_auto.
      iAssert (∃ (j : w64) (decoded : list Memb.t) (ptrs : list loc)
                 (cur_lo cur_lb : slice.t) (rest : list w8),
        "i" ∷ i_ptr ↦ j ∗
        "%Hj" ∷ ⌜uint.Z j ≤ uint.Z length0⌝ ∗
        "%Hdeclen" ∷ ⌜Z.of_nat (length decoded) = uint.Z j⌝ ∗
        "loopO" ∷ loopO_ptr ↦ cur_lo ∗
        "Hlo" ∷ cur_lo ↦* ptrs ∗
        "Hcap" ∷ own_slice_cap loc cur_lo (DfracOwn 1) ∗
        "Hbig" ∷ ([∗ list] p;o ∈ ptrs;decoded, Memb.own p o d) ∗
        "loopErr" ∷ loopErr_ptr ↦ false ∗
        "loopB" ∷ loopB_ptr ↦ cur_lb ∗
        "Hlb" ∷ cur_lb ↦*{d} rest ∗
        "%Hcons" ∷ ⌜tail1 = mjoin (Memb.pure_enc <$> decoded) ++ rest⌝ ∗
        "%Hvf" ∷ ⌜Forall Memb.valid decoded⌝)%I
        with "[i loopO Hlo Hcap loopErr loopB Hb1]" as "IH".
      { assert (Hrep : replicate (sint.nat (W64 0)) (zero_val loc) = (@nil loc)).
        { replace (sint.nat (W64 0)) with 0%nat by word. done. }
        iEval (rewrite Hrep) in "Hlo".
        iExists (W64 0), [], [], lo_sl, b1, tail1.
        iFrame "i loopO Hlo Hcap loopErr loopB Hb1".
        repeat (iSplit; [solve [iPureIntro; word | by iApply big_sepL2_nil'
                                | iPureIntro; by constructor | iPureIntro; done]|]).
        solve [iPureIntro; word | by iApply big_sepL2_nil'
              | iPureIntro; by constructor | iPureIntro; done]. }
      wp_for "IH".
      case_bool_decide as Hcond.
      2: { (* exit: j = length0, decoded all elements; loopErr=false → success *)
        iMod (dfractional_update_to_dfrac _ d with "Hlo") as "Hlo".
        { apply (own_slice_dfractional cur_lo ptrs). }
        { exact Hvd. }
        wp_auto.
        rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc in Hwish1.
        assert (Hlen : W64 (length decoded) = length0) by word.
        iApply "HΦ".
        iExists decoded, rest.
        iSplitL "Hlo Hbig".
        { iExists ptrs. iFrame "Hlo Hbig". }
        iFrame "Hlb".
        iPureIntro. rewrite /wish /pure_enc /valid /safemarshal.w64.pure_enc.
        split.
        - rewrite Hlen Hwish1 Hcons -app_assoc //.
        - split; [word | exact Hvf]. }
      (* body: uint.Z j < uint.Z length0 *)
      wp_auto.
      wp_apply (Memb.wp_dec with "[$Hlb]").
      iIntros (a2 lb1 err2) "Hpost2".
      wp_auto.
      destruct err2.
      -- (* Memb decode failed → set loopErr, break, return error *)
         iDestruct "Hpost2" as "Hno".
         wp_auto.
         wp_for_post.
         iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
         destruct Hwish as [Henc Hvalid].
         rewrite /safemarshal.w64.wish /safemarshal.w64.pure_enc in Hwish1.
         rewrite /pure_enc /safemarshal.w64.pure_enc -app_assoc in Henc.
         rewrite Hwish1 in Henc.
         apply app_inj_1 in Henc as [Hlen_eq Hrest_eq]; [|len].
         apply (inj u64_le) in Hlen_eq.
         destruct Hvalid as [Hvlen Hvforall].
         assert (Hjlt : (uint.nat j < length obj)%nat) by word.
         destruct (lookup_lt_is_Some_2 obj (uint.nat j) Hjlt) as [oj Hoj].
         pose proof (take_drop_middle obj (uint.nat j) oj Hoj) as Hsplit.
         assert (Hinj : ∀ a0 a1 s0 s1, Memb.valid a0 → Memb.valid a1 →
           Memb.pure_enc a0 ++ s0 = Memb.pure_enc a1 ++ s1 → a0 = a1 ∧ s0 = s1).
         { intros a0 a1 s0 s1 Hva0 Hva1 He.
           apply (Memb.wish_det s0 s1 a0 a1 (b := Memb.pure_enc a0 ++ s0));
             rewrite /Memb.wish; by split. }
         rewrite Hcons in Hrest_eq.
         assert (Hmjobj : mjoin (Memb.pure_enc <$> obj)
                          = mjoin (Memb.pure_enc <$> take (uint.nat j) obj)
                            ++ Memb.pure_enc oj
                            ++ mjoin (Memb.pure_enc <$> drop (S (uint.nat j)) obj)).
         { rewrite -{1}Hsplit fmap_app fmap_cons join_app join_cons -app_assoc //. }
         rewrite Hmjobj -!app_assoc in Hrest_eq.
         assert (Hleneq : length decoded = length (take (uint.nat j) obj)).
         { rewrite length_take Nat.min_l; [word | lia]. }
         assert (Hforalltake : Forall Memb.valid (take (uint.nat j) obj))
           by (apply Forall_take; exact Hvforall).
         destruct (mjoin_enc_inj _ _ _ _ _ _ Hinj Hleneq Hvf Hforalltake Hrest_eq)
           as [_ Hrest_split].
         iApply "Hno".
         iExists oj, (mjoin (Memb.pure_enc <$> drop (S (uint.nat j)) obj) ++ tail).
         iPureIntro. rewrite /Memb.wish. split.
         { rewrite Hrest_split /Memb.pure_enc /CommitOpen.pure_enc
             /safemarshal.Slice1D.pure_enc -!app_assoc //. }
         rewrite Forall_forall in Hvforall.
         apply Hvforall. by eapply list_elem_of_lookup_2.
      -- (* success: append the decoded element and continue *)
         iDestruct "Hpost2" as (m t) "(Hown_m & Hlb1 & %Hwm)".
         destruct Hwm as [Hrest_eq Hvm].
         wp_auto.
         wp_apply wp_slice_literal. iSplitR; first done. iIntros "* [Hlit _]". wp_auto.
         wp_apply (wp_slice_append with "[$Hlo $Hcap $Hlit]").
         iIntros (lo2) "(Hlo & Hcap & _)".
         wp_auto.
         iAssert ([∗ list] p;o ∈ (ptrs ++ [a2]);(decoded ++ [m]), Memb.own p o d)%I
           with "[Hbig Hown_m]" as "Hbig2".
         { iApply big_sepL2_snoc. iFrame. }
         assert (Hcons' : tail1 = mjoin (Memb.pure_enc <$> (decoded ++ [m])) ++ t).
         { rewrite fmap_app join_app /= app_nil_r Hcons Hrest_eq -app_assoc //. }
         assert (Hvf' : Forall Memb.valid (decoded ++ [m])).
         { apply Forall_app; split; [exact Hvf|by apply Forall_singleton]. }
         assert (Hj' : uint.Z (word.add j (W64 1)) ≤ uint.Z length0) by word.
         assert (Hdeclen' : Z.of_nat (length (decoded ++ [m])) = uint.Z (word.add j (W64 1))).
         { rewrite length_app /=. word. }
         wp_for_post.
         iFrame "HΦ length".
         iExists (word.add j (W64 1)), (decoded ++ [m]), (ptrs ++ [a2]), lo2, lb1, t.
         iFrame "i loopO Hlo Hcap Hbig2 loopErr loopB Hlb1 %".
Qed.

End proof.
End MembSlice1D.

Module NonMemb.
Record t :=
  mk' {
    LabelProof: list w8;
    MerkleProof: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.Slice1D.pure_enc obj.(LabelProof) ++
  safemarshal.Slice1D.pure_enc obj.(MerkleProof).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(LabelProof) ∧
  safemarshal.Slice1D.valid obj.(MerkleProof).

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
  apply app_inj_1 in Heq as [Hl1 Heq]; [|len].
  apply (inj u64_le) in Hl1.
  assert (length obj0.(LabelProof) = length obj1.(LabelProof)) by word.
  apply app_inj_1 in Heq as [Hlp Heq]; [|done].
  apply app_inj_1 in Heq as [Hl2 Heq]; [|len].
  apply (inj u64_le) in Hl2.
  assert (length obj0.(MerkleProof) = length obj1.(MerkleProof)) by word.
  apply app_inj_1 in Heq as [Hmp Htail]; [|done].
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_LabelProof sl_MerkleProof,
  "Hstr_NonMemb" ∷ ptr ↦{d} (ktcore.NonMemb.mk sl_LabelProof sl_MerkleProof) ∗

  "Hsl_LabelProof" ∷ sl_LabelProof ↦*{d} obj.(LabelProof) ∗
  "Hsl_MerkleProof" ∷ sl_MerkleProof ↦*{d} obj.(MerkleProof).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.NonMembEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_LabelProof sl_MerkleProof) "(Hstr_NonMemb & Hsl_LabelProof & Hsl_MerkleProof)". wp_auto.
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_LabelProof]") as "* (Hsl_b & Hcap_b & Hsl_LabelProof)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_MerkleProof]") as "* (Hsl_b & Hcap_b & Hsl_MerkleProof)".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -!app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.NonMembDecode #sl_b
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
    iIntros (a1 b1 err1) "Hpost1".
    destruct err1.
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
    iIntros (a1 b1 err1) "Hpost1".
    destruct err1.
    + (* LabelProof read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
      destruct Hvalid as [HvLP _]. iApply "Hpost1".
      iExists obj.(LabelProof), _. iPureIntro.
      rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc
        -?app_assoc.
      split; [|exact HvLP].
      rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      rewrite -?app_assoc in Henc. exact Henc.
    + iDestruct "Hpost1" as (lp0 rem1) "(Ha1 & Hb1 & %Hsl1a)".
      wp_auto.
      wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb1]").
      iIntros (a2 b2 err2) "Hpost2".
      destruct err2.
      * (* MerkleProof read failed *)
        wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
        destruct Hvalid as [HvLP HvMP]. iApply "Hpost2".
        iExists obj.(MerkleProof), tail. iPureIntro.
        assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(LabelProof)
                  (safemarshal.Slice1D.pure_enc obj.(MerkleProof) ++ tail)) as Hw'.
        { rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
            /safemarshal.w64.pure_enc -?app_assoc. split; [|exact HvLP].
          rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
          rewrite -?app_assoc in Henc. exact Henc. }
        destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1a Hw') as [_ Hrem1].
        rewrite /safemarshal.Slice1D.wish. split; [exact Hrem1|exact HvMP].
      * (* success *)
        iDestruct "Hpost2" as (mp0 rem2) "(Ha2 & Hb2 & %Hsl1b)".
        destruct Hsl1a as [Hb_eq HvLP0]. destruct Hsl1b as [Hrem1_eq HvMP0].
        wp_auto.
        wp_alloc l as "Hptr".
        iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
        wp_auto.
        iApply "HΦ". iExists (NonMemb.mk' lp0 mp0), rem2.
        iFrame "Hb2". iSplitL "Hptr Ha1 Ha2".
        { iExists a1, a2. iFrame "Hptr Ha1 Ha2". }
        iPureIntro. rewrite /wish /pure_enc /valid. split.
        -- rewrite Hb_eq Hrem1_eq -?app_assoc. done.
        -- split; [exact HvLP0|exact HvMP0].
Qed.

End proof.
End NonMemb.

Module UpdateProof.
Record t :=
  mk' {
    MapLabel: list w8;
    MapVal: list w8;
    NonMembProof: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.Slice1D.pure_enc obj.(MapLabel) ++
  safemarshal.Slice1D.pure_enc obj.(MapVal) ++
  safemarshal.Slice1D.pure_enc obj.(NonMembProof).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(MapLabel) ∧
  safemarshal.Slice1D.valid obj.(MapVal) ∧
  safemarshal.Slice1D.valid obj.(NonMembProof).

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
  apply app_inj_1 in Heq as [Hl1 Heq]; [|len].
  apply (inj u64_le) in Hl1.
  assert (length obj0.(MapLabel) = length obj1.(MapLabel)) by word.
  apply app_inj_1 in Heq as [Hml Heq]; [|done].
  apply app_inj_1 in Heq as [Hl2 Heq]; [|len].
  apply (inj u64_le) in Hl2.
  assert (length obj0.(MapVal) = length obj1.(MapVal)) by word.
  apply app_inj_1 in Heq as [Hmv Heq]; [|done].
  apply app_inj_1 in Heq as [Hl3 Heq]; [|len].
  apply (inj u64_le) in Hl3.
  assert (length obj0.(NonMembProof) = length obj1.(NonMembProof)) by word.
  apply app_inj_1 in Heq as [Hnmp Htail]; [|done].
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_MapLabel sl_MapVal sl_NonMembProof,
  "Hstr_UpdateProof" ∷ ptr ↦{d} (ktcore.UpdateProof.mk sl_MapLabel sl_MapVal sl_NonMembProof) ∗

  "Hsl_MapLabel" ∷ sl_MapLabel ↦*{d} obj.(MapLabel) ∗
  "Hsl_MapVal" ∷ sl_MapVal ↦*{d} obj.(MapVal) ∗
  "Hsl_NonMembProof" ∷ sl_NonMembProof ↦*{d} obj.(NonMembProof).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.UpdateProofEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_MapLabel sl_MapVal sl_NonMembProof) "(Hstr_UpdateProof & Hsl_MapLabel & Hsl_MapVal & Hsl_NonMembProof)". wp_auto.
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_MapLabel]") as "* (Hsl_b & Hcap_b & Hsl_MapLabel)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_MapVal]") as "* (Hsl_b & Hcap_b & Hsl_MapVal)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_NonMembProof]") as "* (Hsl_b & Hcap_b & Hsl_NonMembProof)".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -!app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.UpdateProofDecode #sl_b
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
    + iDestruct "Hpost1" as (ml0 rem1) "(Ha1 & Hb1 & %Hsl1a)".
      destruct Hsl1a as [Henc _]. iExFalso. iPureIntro.
      rewrite /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
  - iDestruct (own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (safemarshal.Slice1D.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + (* MapLabel read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
      destruct Hvalid as [HvML _]. iApply "Hpost1".
      iExists obj.(UpdateProof.MapLabel), _. iPureIntro.
      rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc
        -?app_assoc. split; [|exact HvML].
      rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      rewrite -?app_assoc in Henc. exact Henc.
    + iDestruct "Hpost1" as (ml0 rem1) "(Ha1 & Hb1 & %Hsl1a)".
      wp_auto.
      wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb1]").
      iIntros (a2 b2 err2) "Hpost2". destruct err2.
      * (* MapVal read failed *)
        wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
        destruct Hvalid as [HvML [HvMV _]]. iApply "Hpost2".
        iExists obj.(UpdateProof.MapVal), _. iPureIntro.
        assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(UpdateProof.MapLabel)
                  (safemarshal.Slice1D.pure_enc obj.(UpdateProof.MapVal)
                   ++ safemarshal.Slice1D.pure_enc obj.(UpdateProof.NonMembProof) ++ tail)) as Hw1.
        { rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
            /safemarshal.w64.pure_enc -?app_assoc. split; [|exact HvML].
          rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
          rewrite -?app_assoc in Henc. exact Henc. }
        destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
        rewrite /safemarshal.Slice1D.wish. split; [exact Hrem1|exact HvMV].
      * iDestruct "Hpost2" as (mv0 rem2) "(Ha2 & Hb2 & %Hsl1b)".
        wp_auto.
        wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb2]").
        iIntros (a3 b3 err3) "Hpost3". destruct err3.
        -- (* NonMembProof read failed *)
           wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
           destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
           destruct Hvalid as [HvML [HvMV HvNMP]]. iApply "Hpost3".
           iExists obj.(UpdateProof.NonMembProof), tail. iPureIntro.
           assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(UpdateProof.MapLabel)
                     (safemarshal.Slice1D.pure_enc obj.(UpdateProof.MapVal)
                      ++ safemarshal.Slice1D.pure_enc obj.(UpdateProof.NonMembProof) ++ tail)) as Hw1.
           { rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
               /safemarshal.w64.pure_enc -?app_assoc. split; [|exact HvML].
             rewrite /pure_enc /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
             rewrite -?app_assoc in Henc. exact Henc. }
           destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
           assert (safemarshal.Slice1D.wish rem1 obj.(UpdateProof.MapVal)
                     (safemarshal.Slice1D.pure_enc obj.(UpdateProof.NonMembProof) ++ tail)) as Hw2.
           { rewrite /safemarshal.Slice1D.wish. split; [exact Hrem1|exact HvMV]. }
           destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1b Hw2) as [_ Hrem2].
           rewrite /safemarshal.Slice1D.wish. split; [exact Hrem2|exact HvNMP].
        -- (* success *)
           iDestruct "Hpost3" as (nmp0 rem3) "(Ha3 & Hb3 & %Hsl1c)".
           destruct Hsl1a as [Hb_eq HvML0]. destruct Hsl1b as [Hrem1_eq HvMV0].
           destruct Hsl1c as [Hrem2_eq HvNMP0].
           wp_auto.
           wp_alloc l as "Hptr".
           iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
           wp_auto.
           iApply "HΦ". iExists (UpdateProof.mk' ml0 mv0 nmp0), rem3.
           iFrame "Hb3". iSplitL "Hptr Ha1 Ha2 Ha3".
           { iExists a1, a2, a3. iFrame "Hptr Ha1 Ha2 Ha3". }
           iPureIntro. rewrite /wish /pure_enc /valid. split.
           ++ rewrite Hb_eq Hrem1_eq Hrem2_eq -?app_assoc. done.
           ++ split; [exact HvML0|split; [exact HvMV0|exact HvNMP0]].
Qed.

End proof.
End UpdateProof.

Module UpdateProofSlice1D.
Definition t := list UpdateProof.t.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc (W64 $ length obj) ++ mjoin (UpdateProof.pure_enc <$> obj).

Definition valid (obj : t) :=
  sint.Z (W64 (length obj)) = length obj ∧
  Forall (λ x, UpdateProof.valid x) obj.

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid /safemarshal.w64.pure_enc.
  intros (-> & Hlen0 & Hvf0) (Heq & Hlen1 & Hvf1).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Hl Heq]; [|len].
  apply (inj u64_le) in Hl.
  assert (length obj0 = length obj1) by word.
  assert (Hinj : ∀ a0 a1 s0 s1, UpdateProof.valid a0 → UpdateProof.valid a1 →
    UpdateProof.pure_enc a0 ++ s0 = UpdateProof.pure_enc a1 ++ s1 → a0 = a1 ∧ s0 = s1).
  { intros a0 a1 s0 s1 Hva0 Hva1 Henc.
    apply (UpdateProof.wish_det s0 s1 a0 a1 (b := UpdateProof.pure_enc a0 ++ s0));
      rewrite /UpdateProof.wish; by split. }
  apply (mjoin_enc_inj _ _ _ _ _ _ Hinj) in Heq as [-> ->]; done.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ ptr0,
  ptr ↦*{d} ptr0 ∗
  ([∗ list] ptr;obj ∈ ptr0;obj,
    UpdateProof.own ptr obj d).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.UpdateProofSlice1DEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (ptr0) "[Hsl_obj Hbig]".
  iDestruct (own_slice_len with "Hsl_obj") as %[Hlen0 ?].
  iDestruct (big_sepL2_length with "Hbig") as %Hlen_eq.
  wp_auto.
  wp_apply (marshal.wp_WriteInt with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iAssert (∃ (j : w64) (sl_cur : slice.t) (ev : loc),
    "i" ∷ i_ptr ↦ j ∗
    "%Hj" ∷ ⌜0 ≤ sint.Z j ≤ length obj⌝ ∗
    "e" ∷ e_ptr ↦ ev ∗
    "b" ∷ b_ptr ↦ sl_cur ∗
    "Hsl_b" ∷ sl_cur ↦* (b ++ u64_le ptr_obj.(slice.len)
                          ++ mjoin (UpdateProof.pure_enc <$> take (sint.nat j) obj)) ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_cur 1 ∗
    "Hsl_obj" ∷ ptr_obj ↦*{d} ptr0 ∗
    "Hbig" ∷ ([∗ list] ptr;o ∈ ptr0;obj, UpdateProof.own ptr o d))%I
    with "[-HΦ]" as "IH".
  { iExists (W64 0), s', null. rewrite take_0 /= app_nil_r. iFrame "∗". iPureIntro. word. }
  wp_for "IH".
  case_bool_decide.
  2: { wp_auto.
       iApply "HΦ".
       iFrame "Hcap_b".
       iSplitL "Hsl_b".
       { iExactEq "Hsl_b".
         replace (sint.nat j) with (length obj) by word.
         rewrite take_ge; [|lia].
         rewrite /pure_enc /safemarshal.w64.pure_enc.
         replace (W64 (length obj)) with ptr_obj.(slice.len) by word.
         done. }
       iExists ptr0. iFrame "Hsl_obj Hbig". }
  (* body *)
  list_elem ptr0 (sint.Z j) as pj.
  list_elem obj (sint.Z j) as oj.
  wp_auto.
  rewrite decide_True; last word.
  wp_apply (wp_load_slice_index with "[$Hsl_obj]") as "Hsl_obj".
  { word. }
  { eauto. }
  iDestruct (big_sepL2_lookup_acc with "Hbig") as "[Hown_j Hbig_close]";
    [exact Hpj_lookup | exact Hoj_lookup |].
  wp_apply (UpdateProof.wp_enc with "[$Hsl_b $Hcap_b $Hown_j]") as "* (Hsl_b & Hcap_b & Hown_j)".
  iDestruct ("Hbig_close" with "Hown_j") as "Hbig".
  wp_for_post.
  iFrame.
  iSplitR; [iPureIntro; word|].
  iExactEq "Hsl_b".
  replace (sint.nat (word.add j (W64 1))) with (S (sint.nat j)) by word.
  rewrite (take_S_r _ _ oj); [|exact Hoj_lookup].
  rewrite fmap_app join_app /= app_nil_r -!app_assoc.
  done.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.UpdateProofSlice1DDecode #sl_b
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
Proof. Admitted.

End proof.
End UpdateProofSlice1D.

Module AuditProof.
Record t :=
  mk' {
    Updates: list UpdateProof.t;
    LinkSig: list w8;
  }.

Definition pure_enc obj :=
  UpdateProofSlice1D.pure_enc obj.(Updates) ++
  safemarshal.Slice1D.pure_enc obj.(LinkSig).

Definition valid obj :=
  UpdateProofSlice1D.valid obj.(Updates) ∧
  safemarshal.Slice1D.valid obj.(LinkSig).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
(* Compose the sub-encoders' [wish_det] (keeping them FOLDED in the wish
   statements so the lemmas apply) instead of peeling the raw bytes. Each step
   needs only a single OUTER [app_assoc] to expose [enc field ++ rest]. *)
Proof.
  intros [Henc0 Hvld0] [Henc1 Hvld1].
  rewrite /valid in Hvld0 Hvld1.
  destruct Hvld0 as [Hv0a Hv0b]. destruct Hvld1 as [Hv1a Hv1b].
  assert (UpdateProofSlice1D.wish b obj0.(Updates)
            (safemarshal.Slice1D.pure_enc obj0.(LinkSig) ++ tail0)) as Hw0.
  { split; [|exact Hv0a]. rewrite Henc0 /pure_enc -app_assoc //. }
  assert (UpdateProofSlice1D.wish b obj1.(Updates)
            (safemarshal.Slice1D.pure_enc obj1.(LinkSig) ++ tail1)) as Hw1.
  { split; [|exact Hv1a]. rewrite Henc1 /pure_enc -app_assoc //. }
  destruct (UpdateProofSlice1D.wish_det _ _ _ _ Hw0 Hw1) as [HUp Hrest].
  assert (safemarshal.Slice1D.wish
            (safemarshal.Slice1D.pure_enc obj0.(LinkSig) ++ tail0)
            obj0.(LinkSig) tail0) as Hs0.
  { split; [done|exact Hv0b]. }
  assert (safemarshal.Slice1D.wish
            (safemarshal.Slice1D.pure_enc obj0.(LinkSig) ++ tail0)
            obj1.(LinkSig) tail1) as Hs1.
  { split; [rewrite Hrest //|exact Hv1b]. }
  destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hs0 Hs1) as [HLS Htail].
  split; [|exact Htail].
  destruct obj0, obj1. simpl in *. by subst.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ ptr_Updates sl_LinkSig,
  "Hstr_AuditProof" ∷ ptr ↦{d} (ktcore.AuditProof.mk ptr_Updates sl_LinkSig) ∗

  "Hsl_Updates" ∷ UpdateProofSlice1D.own ptr_Updates obj.(Updates) d ∗
  "Hsl_LinkSig" ∷ sl_LinkSig ↦*{d} obj.(LinkSig).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.AuditProofEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (ptr_Updates sl_LinkSig) "(Hstr_AuditProof & Hsl_Updates & Hsl_LinkSig)". wp_auto.
  wp_apply (UpdateProofSlice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_Updates]") as "* (Hsl_b & Hcap_b & Hsl_Updates)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_LinkSig]") as "* (Hsl_b & Hcap_b & Hsl_LinkSig)".
  iApply "HΦ".
  iSplitL "Hsl_b".
  { iExactEq "Hsl_b". rewrite /pure_enc -?app_assoc. done. }
  iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.AuditProofDecode #sl_b
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
  - wp_apply (UpdateProofSlice1D.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc _]. iExFalso. iPureIntro.
      rewrite /pure_enc /UpdateProofSlice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
    + iDestruct "Hpost1" as (up0 rem1) "(Hown_up & Hb1 & %Hsl1a)".
      destruct Hsl1a as [Henc _]. iExFalso. iPureIntro.
      rewrite /UpdateProofSlice1D.pure_enc /safemarshal.w64.pure_enc in Henc.
      apply (f_equal length) in Henc. rewrite !length_app u64_le_length /= in Henc. lia.
  - iDestruct (own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (UpdateProofSlice1D.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + (* Updates read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
      destruct Hvalid as [HvUp _]. iApply "Hpost1".
      iExists obj.(Updates), (safemarshal.Slice1D.pure_enc obj.(AuditProof.LinkSig) ++ tail).
      iPureIntro. split; [|exact HvUp]. rewrite Henc /pure_enc -app_assoc //.
    + iDestruct "Hpost1" as (up0 rem1) "(Hown_up & Hb1 & %Hsl1a)".
      wp_auto.
      wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb1]").
      iIntros (a2 b2 err2) "Hpost2". destruct err2.
      * (* LinkSig read failed *)
        wp_auto. iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
        destruct Hwish as [Henc Hvalid]. rewrite /valid in Hvalid.
        destruct Hvalid as [HvUp HvLS]. iApply "Hpost2".
        iExists obj.(AuditProof.LinkSig), tail. iPureIntro.
        assert (UpdateProofSlice1D.wish (b0 :: brest) obj.(Updates)
                  (safemarshal.Slice1D.pure_enc obj.(AuditProof.LinkSig) ++ tail)) as Hw1.
        { split; [|exact HvUp]. rewrite Henc /pure_enc -app_assoc //. }
        destruct (UpdateProofSlice1D.wish_det _ _ _ _ Hsl1a Hw1) as [_ Hrem1].
        split; [exact Hrem1|exact HvLS].
      * (* success *)
        iDestruct "Hpost2" as (ls0 rem2) "(Ha2 & Hb2 & %Hsl1b)".
        destruct Hsl1a as [Hb_eq HvUp0]. destruct Hsl1b as [Hrem1_eq HvLS0].
        wp_auto.
        wp_alloc l as "Hptr".
        iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
        wp_auto.
        iApply "HΦ". iExists (AuditProof.mk' up0 ls0), rem2.
        iFrame "Hb2". iSplitL "Hptr Hown_up Ha2".
        { iExists a1, a2. iFrame "Hptr Hown_up Ha2". }
        iPureIntro. rewrite /wish /pure_enc /valid. split.
        ++ rewrite Hb_eq Hrem1_eq -?app_assoc. done.
        ++ split; [exact HvUp0|exact HvLS0].
Qed.

End proof.
End AuditProof.

Module AuditProofSlice1D.
Definition t := list AuditProof.t.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc (W64 $ length obj) ++ mjoin (AuditProof.pure_enc <$> obj).

Definition valid (obj : t) :=
  sint.Z (W64 (length obj)) = length obj ∧
  Forall (λ x, AuditProof.valid x) obj.

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid /safemarshal.w64.pure_enc.
  intros (-> & Hlen0 & Hvf0) (Heq & Hlen1 & Hvf1).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Hl Heq]; [|len].
  apply (inj u64_le) in Hl.
  assert (length obj0 = length obj1) by word.
  assert (Hinj : ∀ a0 a1 s0 s1, AuditProof.valid a0 → AuditProof.valid a1 →
    AuditProof.pure_enc a0 ++ s0 = AuditProof.pure_enc a1 ++ s1 → a0 = a1 ∧ s0 = s1).
  { intros a0 a1 s0 s1 Hva0 Hva1 Henc.
    apply (AuditProof.wish_det s0 s1 a0 a1 (b := AuditProof.pure_enc a0 ++ s0));
      rewrite /AuditProof.wish; by split. }
  apply (mjoin_enc_inj _ _ _ _ _ _ Hinj) in Heq as [-> ->]; done.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ ptr0,
  ptr ↦*{d} ptr0 ∗
  ([∗ list] ptr;obj ∈ ptr0;obj,
    ktcore.AuditProof.own ptr obj d).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.AuditProofSlice1DEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (ptr0) "[Hsl_obj Hbig]".
  iDestruct (own_slice_len with "Hsl_obj") as %[Hlen0 ?].
  iDestruct (big_sepL2_length with "Hbig") as %Hlen_eq.
  wp_auto.
  wp_apply (marshal.wp_WriteInt with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iAssert (∃ (j : w64) (sl_cur : slice.t) (ev : loc),
    "i" ∷ i_ptr ↦ j ∗
    "%Hj" ∷ ⌜0 ≤ sint.Z j ≤ length obj⌝ ∗
    "e" ∷ e_ptr ↦ ev ∗
    "b" ∷ b_ptr ↦ sl_cur ∗
    "Hsl_b" ∷ sl_cur ↦* (b ++ u64_le ptr_obj.(slice.len)
                          ++ mjoin (AuditProof.pure_enc <$> take (sint.nat j) obj)) ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_cur 1 ∗
    "Hsl_obj" ∷ ptr_obj ↦*{d} ptr0 ∗
    "Hbig" ∷ ([∗ list] ptr;o ∈ ptr0;obj, ktcore.AuditProof.own ptr o d))%I
    with "[-HΦ]" as "IH".
  { iExists (W64 0), s', null. rewrite take_0 /= app_nil_r. iFrame "∗". iPureIntro. word. }
  wp_for "IH".
  case_bool_decide.
  2: { wp_auto.
       iApply "HΦ".
       iFrame "Hcap_b".
       iSplitL "Hsl_b".
       { iExactEq "Hsl_b".
         replace (sint.nat j) with (length obj) by word.
         rewrite take_ge; [|lia].
         rewrite /pure_enc /safemarshal.w64.pure_enc.
         replace (W64 (length obj)) with ptr_obj.(slice.len) by word.
         done. }
       iExists ptr0. iFrame "Hsl_obj Hbig". }
  (* body *)
  list_elem ptr0 (sint.Z j) as pj.
  list_elem obj (sint.Z j) as oj.
  wp_auto.
  rewrite decide_True; last word.
  wp_apply (wp_load_slice_index with "[$Hsl_obj]") as "Hsl_obj".
  { word. }
  { eauto. }
  iDestruct (big_sepL2_lookup_acc with "Hbig") as "[Hown_j Hbig_close]";
    [exact Hpj_lookup | exact Hoj_lookup |].
  wp_apply (AuditProof.wp_enc with "[$Hsl_b $Hcap_b $Hown_j]") as "* (Hsl_b & Hcap_b & Hown_j)".
  iDestruct ("Hbig_close" with "Hown_j") as "Hbig".
  wp_for_post.
  iFrame.
  iSplitR; [iPureIntro; word|].
  iExactEq "Hsl_b".
  replace (sint.nat (word.add j (W64 1))) with (S (sint.nat j)) by word.
  rewrite (take_S_r _ _ oj); [|exact Hoj_lookup].
  rewrite fmap_app join_app /= app_nil_r -!app_assoc.
  done.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.AuditProofSlice1DDecode #sl_b
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
Proof. Admitted.

End proof.
End AuditProofSlice1D.

End ktcore.
