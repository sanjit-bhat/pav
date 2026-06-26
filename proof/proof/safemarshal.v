From New.generatedproof.github_com.sanjit_bhat.pav Require Import safemarshal.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.tchajed Require Import marshal.

Module safemarshal.
Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : safemarshal.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

#[global] Instance : IsPkgInit (iProp Σ) safemarshal := define_is_pkg_init True%I.
#[global] Instance : GetIsPkgInitWf (iProp Σ) safemarshal := build_get_is_pkg_init_wf.

Lemma wp_initialize' get_is_pkg_init :
  get_is_pkg_init_prop safemarshal get_is_pkg_init →
  {{{ own_initializing get_is_pkg_init }}}
    safemarshal.initialize' #()
  {{{ RET #(); own_initializing get_is_pkg_init ∗ is_pkg_init safemarshal }}}.
Proof.
  intros Hinit. wp_start as "Hown".
  wp_apply (wp_package_init with "[$Hown] HΦ") as "Hown".
  { destruct Hinit as (-> & ?); done. }

  wp_apply (marshal.wp_initialize' with "[$Hown]").
  { naive_solver. }
  iIntros "(Hown & #?)". wp_auto.
  iFrame. iEval (rewrite is_pkg_init_unfold).
  simpl. iFrame "#". done.
Qed.

End proof.

Module w8.

Definition pure_enc (obj : w8) :=
  [obj].

Definition wish b obj tail :=
  b = pure_enc obj ++ tail.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc. intros -> Heq.
  by simplify_eq/=.
Qed.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : safemarshal.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b :
  {{{
    is_pkg_init safemarshal ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1
  }}}
  @! safemarshal.WriteByte #sl_b #obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1
  }}}.
Proof.
  wp_start as "[Hsl_b Hcap_b]". wp_auto.
  wp_apply wp_slice_literal. iSplitR; first done. iIntros "* [Hdata _]". wp_auto.
  wp_apply (marshal.wp_WriteBytes with "[$Hsl_b $Hcap_b $Hdata]").
  iIntros (sl_b') "(Hsl' & Hcap' & _)". wp_auto.
  iApply "HΦ". rewrite /pure_enc. iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init safemarshal ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! safemarshal.ReadByte #sl_b
  {{{
    obj sl_tail err, RET (#obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj' tail', ⌜wish b obj' tail'⌝
    | false =>
      ∃ tail,
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof.
  wp_start as "Hsl_b". wp_auto.
  iDestruct (own_slice_len with "Hsl_b") as %[Hlen ?].
  wp_if_destruct.
  - iApply "HΦ". iPureIntro.
    intros (obj' & tail' & Heq). rewrite /wish /pure_enc in Heq.
    apply (f_equal length) in Heq. rewrite length_app /= in Heq. word.
  - assert (Hb : b = take 1 b ++ drop 1 b) by (by rewrite take_drop).
    assert (Hlen1 : length (take 1 b) = uint.nat (W64 1)) by (rewrite length_take; word).
    assert (∃ x, take 1 b = [x]) as [x Htk].
    { destruct (take 1 b) as [|x rest] eqn:E; [ simpl in Hlen1; word |].
      destruct rest; [ by exists x | simpl in Hlen1; word ]. }
    iEval (rewrite {1}Hb) in "Hsl_b".
    wp_apply (marshal.wp_ReadBytes with "[$Hsl_b]"); first done.
    iIntros (data0 s') "[Hdata0 Hs']".
    iEval (rewrite Htk) in "Hdata0".
    iDestruct (own_slice_len with "Hdata0") as %[Hdlen Hdpos].
    simpl in Hdlen.
    wp_auto.
    assert (0 ≤ sint.Z (W64 0) < sint.Z data0.(slice.len)) as Hbound by word.
    rewrite (decide_True _ _ Hbound).
    wp_apply (wp_load_slice_index with "[$Hdata0]") as "Hdata0"; [word|done|].
    wp_auto.
    iApply "HΦ". iFrame "Hs'". iPureIntro.
    rewrite /wish /pure_enc -Htk take_drop. done.
Qed.

End proof.
End w8.

Module bool.

Definition pure_enc (obj : bool) :=
  [if obj then W8 1 else W8 0].

Definition wish b obj tail :=
  b = pure_enc obj ++ tail.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc. intros -> Heq.
  destruct obj0, obj1; simplify_eq/=; try done; word.
Qed.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : safemarshal.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b :
  {{{
    is_pkg_init marshal ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1
  }}}
  @! marshal.WriteBool #sl_b #obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1
  }}}.
Proof.
  iIntros (Φ) "(Hinit & Hsl_b & Hcap_b) HΦ".
  wp_apply (marshal.wp_WriteBool with "[$Hinit $Hsl_b $Hcap_b]").
  iIntros (sl_b') "[Hsl' Hcap']".
  iApply "HΦ". rewrite /pure_enc. iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init safemarshal ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! safemarshal.ReadBool #sl_b
  {{{
    obj sl_tail err, RET (#obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj' tail', ⌜wish b obj' tail'⌝
    | false =>
      ∃ tail,
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof.
  wp_start as "Hsl_b". wp_auto.
  wp_apply (w8.wp_dec with "[$Hsl_b]").
  iIntros (x b1 err1) "Hpost". destruct err1.
  - wp_auto. iDestruct "Hpost" as %Hpost.
    iApply "HΦ". iPureIntro. intros (obj' & tail' & Hwish).
    apply Hpost. exists (if obj' then W8 1 else W8 0), tail'.
    rewrite /wish /pure_enc in Hwish. rewrite /w8.wish /w8.pure_enc. exact Hwish.
  - iDestruct "Hpost" as (tail) "(Hb1 & %Hw8)".
    wp_auto.
    wp_if_destruct.
    + rewrite /w8.wish /w8.pure_enc in Hw8.
      iApply "HΦ". iPureIntro. intros (obj' & tail' & Hwish).
      rewrite /wish /pure_enc Hw8 in Hwish.
      destruct obj'; simplify_eq/=; word.
    + rewrite /w8.wish /w8.pure_enc in Hw8.
      iApply "HΦ". iExists tail. iFrame "Hb1". iPureIntro.
      rewrite /wish /pure_enc Hw8.
      case_bool_decide as Hx.
      * subst x. done.
      * assert (x = W8 0) as -> by word. done.
Qed.

End proof.
End bool.

Module w64.

Definition pure_enc obj :=
  u64_le obj.

Definition wish b obj tail :=
  b = pure_enc obj ++ tail.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc. intros -> Heq.
  apply app_inj_1 in Heq as [Hlen Htail]; [|len].
  apply (inj u64_le) in Hlen. by simplify_eq.
Qed.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : safemarshal.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b :
  {{{
    is_pkg_init marshal ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1
  }}}
  @! marshal.WriteInt #sl_b #obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1
  }}}.
Proof.
  iIntros (Φ) "(Hinit & Hsl_b & Hcap_b) HΦ".
  wp_apply (marshal.wp_WriteInt with "[$Hinit $Hsl_b $Hcap_b]").
  iIntros (sl_b') "[Hsl' Hcap']".
  iApply "HΦ". rewrite /pure_enc. iFrame.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init safemarshal ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! safemarshal.ReadInt #sl_b
  {{{
    obj sl_tail err, RET (#obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj' tail', ⌜wish b obj' tail'⌝
    | false =>
      ∃ tail,
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof.
  wp_start as "Hsl_b". wp_auto.
  iDestruct (own_slice_len with "Hsl_b") as %[Hlen ?].
  wp_if_destruct.
  - iApply "HΦ". iPureIntro.
    intros (obj' & tail' & Heq). rewrite /wish /pure_enc in Heq.
    apply (f_equal length) in Heq. rewrite length_app u64_le_length in Heq. word.
  - assert (Hb : b = u64_le (le_to_u64 (take 8 b)) ++ drop 8 b).
    { rewrite le_to_u64_le; [by rewrite take_drop|]. rewrite length_take. word. }
    iEval (rewrite {1}Hb) in "Hsl_b".
    wp_apply (marshal.wp_ReadInt with "[$Hsl_b]").
    iIntros (s') "Hs'". wp_auto.
    iApply "HΦ". iFrame "Hs'". iPureIntro. rewrite /wish /pure_enc. done.
Qed.

End proof.
End w64.

Module Slice1D.
Definition t := list w8.

Definition pure_enc obj :=
  w64.pure_enc (W64 $ length obj) ++ obj.

Definition valid (obj : t) :=
  sint.Z (W64 (length obj)) = length obj.

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /w64.pure_enc /valid.
  intros (-> & Hvalid0) (Heq & Hvalid1).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Hlen Heq]; [|len].
  apply (inj u64_le) in Hlen.
  assert (length obj0 = length obj1) by word.
  apply app_inj_1 in Heq as [-> ->]; [|done].
  done.
Qed.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : safemarshal.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init safemarshal ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hsl_obj" ∷ ptr_obj ↦*{d} obj
  }}}
  @! safemarshal.WriteSlice1D #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    ptr_obj ↦*{d} obj
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hsl_obj)". wp_auto.
  iDestruct (own_slice_len with "Hsl_obj") as %[Hlen ?].
  wp_apply (marshal.wp_WriteInt with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (marshal.wp_WriteBytes with "[$Hsl_b $Hsl_obj $Hcap_b]") as "* (Hsl_b & Hcap_b & Hsl_obj)".
  iApply "HΦ". iFrame "Hcap_b Hsl_obj".
  rewrite /pure_enc /w64.pure_enc -!app_assoc.
  iExactEq "Hsl_b". repeat (f_equal; try word).
Qed.

(* Spec for the helper [safemarshal.ReadBytes], which reads [len] bytes off the
   front. No [wish]/[valid] here — it just splits [b] into the first [len] bytes
   and the rest. *)
Lemma wp_ReadBytes sl_b d b (len : w64) :
  {{{
    is_pkg_init safemarshal ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! safemarshal.ReadBytes #sl_b #len
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ⌜length b < uint.Z len⌝
    | false =>
      ∃ (obj tail : list w8),
      ptr_obj ↦*{d} obj ∗
      sl_tail ↦*{d} tail ∗
      ⌜b = obj ++ tail ∧ length obj = uint.nat len⌝
    end
  }}}.
Proof.
  wp_start as "Hsl_b". wp_auto.
  iDestruct (own_slice_len with "Hsl_b") as %[Hlen Hpos].
  wp_if_destruct.
  - iApply "HΦ". iPureIntro. word.
  - assert (Hb : b = take (uint.nat len) b ++ drop (uint.nat len) b) by (by rewrite take_drop).
    assert (Hlen2 : length (take (uint.nat len) b) = uint.nat len) by (rewrite length_take; word).
    iEval (rewrite {1}Hb) in "Hsl_b".
    wp_apply (marshal.wp_ReadBytes with "[$Hsl_b]"); first done.
    iIntros (data0 s') "[Hdata0 Hs']". wp_auto.
    iApply "HΦ". iFrame "Hdata0 Hs'". iPureIntro. split; [by rewrite take_drop|done].
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init safemarshal ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! safemarshal.ReadSlice1D #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj tail, ⌜wish b obj tail⌝
    | false =>
      ∃ obj tail,
      ptr_obj ↦*{d} obj ∗
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof.
  wp_start as "Hsl_b". wp_auto.
  wp_apply (w64.wp_dec with "[$Hsl_b]").
  iIntros (length0 sl_rem err0) "Hpost".
  destruct err0.
  - (* ReadInt failed: no valid encoding (it would give a w64 prefix). *)
    wp_auto.
    iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
    iApply "Hpost". iExists (W64 (length obj)), (obj ++ tail). iPureIntro.
    destruct Hwish as [Henc _].
    rewrite /Slice1D.pure_enc in Henc.
    rewrite /w64.wish app_assoc. exact Henc.
  - (* ReadInt succeeded, reading length0 and leaving rem. *)
    iDestruct "Hpost" as (rem) "[Hrem %Hw64]".
    rewrite /w64.wish /w64.pure_enc in Hw64.
    wp_auto.
    wp_apply (wp_ReadBytes with "[$Hrem]").
    iIntros (ptr_obj sl_tail err1) "Hpost2".
    destruct err1.
    + (* ReadBytes failed: rem too short for length0 — contradicts any wish. *)
      iDestruct "Hpost2" as "%Hlt".
      wp_auto.
      iApply "HΦ". iIntros "Hex". iDestruct "Hex" as (obj tail) "%Hwish".
      destruct Hwish as [Henc Hvalid].
      rewrite /Slice1D.pure_enc /w64.pure_enc in Henc.
      (* both decompositions share the 8-byte prefix, so length0 = W64 (length obj) *)
      rewrite -app_assoc Hw64 in Henc.
      apply app_inj_1 in Henc as [Hpre Hrest]; [|len].
      apply (inj u64_le) in Hpre. subst length0.
      rewrite /Slice1D.valid in Hvalid.
      apply (f_equal length) in Hrest. rewrite length_app in Hrest.
      exfalso. word.
    + (* ReadBytes succeeded. *)
      iDestruct "Hpost2" as (obj tail) "(Hobj & Htail & %Hbytes)".
      destruct Hbytes as [Hrem_eq Hobjlen].
      iDestruct (own_slice_len with "Hobj") as %[Hlen2 _].
      wp_auto.
      iApply "HΦ". iFrame "Hobj Htail". iPureIntro.
      assert (Hww : W64 (length obj) = length0) by word.
      rewrite /wish /Slice1D.pure_enc /w64.pure_enc.
      split.
      * rewrite -app_assoc -Hrem_eq Hww. exact Hw64.
      * rewrite /Slice1D.valid. word.
Qed.

End proof.
End Slice1D.

End safemarshal.
