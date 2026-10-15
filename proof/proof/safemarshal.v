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

(** serde spec form, shared by all serde modules:

  own obj ⊢ ⌜valid obj⌝

  { own obj }
  Encode(b, obj) (b')
  { b' = b ++ enc_fn obj ∗ ⌜valid obj⌝ }

  { True }
  Decode(b) (obj, tail, err)
  { err → ¬ ∃ obj tail, b = enc_fn obj ++ tail ∧ valid obj
    ¬err → own obj ∗ b = enc_fn obj ++ tail }

  enc_inj :
    enc_fn obj ++ tail = enc_fn obj' ++ tail' →
    valid obj → valid obj' →
    obj = obj' ∧ tail = tail'.

primitives (this file) are transparent and have no [valid], except [Slice1D].
byte slices are owned by a plain [sl ↦*{d} obj].
struct and list [enc_fn] and [valid] are sealed; only their module unseals them.
struct and list [own] are persistent. *)

Module w8.

Definition enc_fn (obj : w8) := [obj].

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  obj = obj' ∧ tail = tail'.
Proof. by intros [=]. Qed.

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
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1
  }}}.
Proof.
  wp_start as "[Hsl_b Hcap_b]". wp_auto.
  wp_apply wp_slice_literal. iSplitR; first done. iIntros "* [Hdata _]". wp_auto.
  wp_apply (marshal.wp_WriteBytes with "[$Hsl_b $Hcap_b $Hdata]").
  iIntros (sl_b') "(Hsl' & Hcap' & _)". wp_auto.
  iApply "HΦ". iFrame.
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
    | true => ⌜¬ ∃ obj tail, b = enc_fn obj ++ tail⌝
    | false =>
      ∃ tail,
      sl_tail ↦*{d} tail ∗
      ⌜b = enc_fn obj ++ tail⌝
    end
  }}}.
Proof.
  wp_start as "Hsl_b". wp_auto.
  iDestruct (own_slice_len with "Hsl_b") as %[Hlen ?].
  wp_if_destruct.
  - iApply "HΦ". iPureIntro.
    intros (obj' & tail' & Heq).
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
    rewrite /enc_fn -Htk take_drop. done.
Qed.

End proof.
End w8.

Module bool.

Definition enc_fn (obj : bool) := [if obj then W8 1 else W8 0].

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite /enc_fn. intros Heq.
  destruct obj, obj'; simplify_eq/=; try done; word.
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
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1
  }}}.
Proof.
  iIntros (Φ) "(Hinit & Hsl_b & Hcap_b) HΦ".
  wp_apply (marshal.wp_WriteBool with "[$Hinit $Hsl_b $Hcap_b]").
  iIntros (sl_b') "[Hsl' Hcap']".
  iApply "HΦ". iFrame.
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
    | true => ⌜¬ ∃ obj tail, b = enc_fn obj ++ tail⌝
    | false =>
      ∃ tail,
      sl_tail ↦*{d} tail ∗
      ⌜b = enc_fn obj ++ tail⌝
    end
  }}}.
Proof.
  rewrite /enc_fn.
  wp_start as "Hsl_b". wp_auto.
  wp_apply (w8.wp_dec with "[$Hsl_b]").
  iIntros (x b1 err1) "Hpost". destruct err1.
  - iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj' & tail' & Heq).
    apply Hfail. by eexists _, _.
  - iDestruct "Hpost" as (tail) "(Hb1 & %Hw8)".
    rewrite /w8.enc_fn in Hw8. subst b.
    wp_auto.
    wp_if_destruct.
    + iApply "HΦ". iPureIntro. intros (obj' & tail' & Heq).
      destruct obj'; simplify_eq/=; word.
    + iApply "HΦ". iFrame "Hb1". iPureIntro.
      case_bool_decide as Hx.
      * by subst x.
      * by assert (x = W8 0) as -> by word.
Qed.

End proof.
End bool.

Module w64.

Definition enc_fn (obj : w64) := u64_le obj.

Definition dec_fn (b : list w8) : option (w64 * list w8) :=
  guard (8 ≤ length b)%nat;;
  Some (le_to_u64 (take 8 b), drop 8 b).

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite /enc_fn. intros Heq.
  apply app_inj_1 in Heq as [Heq ->]; [|len].
  by apply (inj u64_le) in Heq.
Qed.

Lemma dec_fn_iff b obj tail :
  dec_fn b = Some (obj, tail) ↔ b = enc_fn obj ++ tail.
Proof.
  rewrite /dec_fn /enc_fn. split.
  - intros ?. simplify_option_eq.
    rewrite le_to_u64_le ?take_drop //. rewrite length_take. lia.
  - intros ->. pose proof (u64_le_length obj).
    rewrite option_guard_True; [|len]. simpl.
    rewrite take_app_length' // drop_app_length' // u64_le_to_word //.
Qed.

Lemma dec_fn_enc obj tail :
  dec_fn (enc_fn obj ++ tail) = Some (obj, tail).
Proof. by apply dec_fn_iff. Qed.

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
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1
  }}}.
Proof.
  iIntros (Φ) "(Hinit & Hsl_b & Hcap_b) HΦ".
  wp_apply (marshal.wp_WriteInt with "[$Hinit $Hsl_b $Hcap_b]").
  iIntros (sl_b') "[Hsl' Hcap']".
  iApply "HΦ". iFrame.
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
    | true => ⌜¬ ∃ obj tail, b = enc_fn obj ++ tail⌝
    | false =>
      ∃ tail,
      sl_tail ↦*{d} tail ∗
      ⌜b = enc_fn obj ++ tail⌝
    end
  }}}.
Proof.
  rewrite /enc_fn.
  wp_start as "Hsl_b". wp_auto.
  iDestruct (own_slice_len with "Hsl_b") as %[Hlen ?].
  wp_if_destruct.
  - iApply "HΦ". iPureIntro.
    intros (obj' & tail' & Heq).
    apply (f_equal length) in Heq. rewrite length_app u64_le_length in Heq. word.
  - assert (Hb : b = u64_le (le_to_u64 (take 8 b)) ++ drop 8 b).
    { rewrite le_to_u64_le; [by rewrite take_drop|]. rewrite length_take. word. }
    iEval (rewrite {1}Hb) in "Hsl_b".
    wp_apply (marshal.wp_ReadInt with "[$Hsl_b]").
    iIntros (s') "Hs'". wp_auto.
    iApply "HΦ". by iFrame "Hs'".
Qed.

End proof.
End w64.

Module Slice1D.
Definition t := list w8.

Definition enc_fn (obj : t) :=
  w64.enc_fn (W64 $ length obj) ++ obj.

Definition valid (obj : t) :=
  sint.Z (W64 (length obj)) = length obj.

Definition dec_fn (b : list w8) : option (t * list w8) :=
  '(len, rem) ← w64.dec_fn b;
  guard (0 ≤ sint.Z len);;
  guard (uint.nat len ≤ length rem)%nat;;
  Some (take (uint.nat len) rem, drop (uint.nat len) rem).

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite /enc_fn /valid -!app_assoc.
  intros Heq ??.
  apply w64.enc_inj in Heq as [? Heq].
  apply app_inj_1 in Heq; [done|word].
Qed.

Lemma dec_fn_iff b obj tail :
  dec_fn b = Some (obj, tail) ↔ b = enc_fn obj ++ tail ∧ valid obj.
Proof.
  rewrite /dec_fn /enc_fn /valid -app_assoc. split.
  - destruct (w64.dec_fn b) as [[len rem]|] eqn:Hw; [|done]. simpl.
    apply w64.dec_fn_iff in Hw as ->.
    intros ?. simplify_option_eq.
    rewrite length_take Nat.min_l; [|lia].
    rewrite take_drop. split; [repeat f_equal; word|word].
  - intros [-> Hv].
    rewrite (proj2 (w64.dec_fn_iff _ _ _) eq_refl) /=.
    rewrite option_guard_True; [|word]. simpl.
    rewrite option_guard_True; [|rewrite length_app; word]. simpl.
    replace (uint.nat (W64 (length obj))) with (length obj) by word.
    by rewrite take_app_length' // drop_app_length'.
Qed.

Lemma dec_fn_enc obj tail :
  valid obj →
  dec_fn (enc_fn obj ++ tail) = Some (obj, tail).
Proof. intros. by apply dec_fn_iff. Qed.

Section defs.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics}.

Lemma own_valid sl obj d :
  sl ↦*{d} obj ⊢ ⌜valid obj⌝.
Proof using All.
  iIntros "Hsl". iDestruct (own_slice_len with "Hsl") as %[??].
  iPureIntro. rewrite /valid. word.
Qed.
End defs.

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
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ptr_obj ↦*{d} obj ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hsl_obj)". wp_auto.
  iDestruct (own_valid with "Hsl_obj") as %?.
  iDestruct (own_slice_len with "Hsl_obj") as %[Hlen ?].
  wp_apply (w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (marshal.wp_WriteBytes with "[$Hsl_b $Hsl_obj $Hcap_b]") as "* (Hsl_b & Hcap_b & Hsl_obj)".
  iApply "HΦ". iFrame "Hcap_b Hsl_obj %".
  rewrite /enc_fn.
  iExactEq "Hsl_b". rewrite -!app_assoc. repeat (f_equal; try word).
Qed.

(* reads [len] bytes off the front. *)
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
    | true => ⌜¬ ∃ obj tail, b = enc_fn obj ++ tail ∧ valid obj⌝
    | false =>
      ∃ obj tail,
      ptr_obj ↦*{d} obj ∗
      sl_tail ↦*{d} tail ∗
      ⌜b = enc_fn obj ++ tail⌝
    end
  }}}.
Proof.
  rewrite /enc_fn /valid.
  wp_start as "Hsl_b". wp_auto.
  wp_apply (w64.wp_dec with "[$Hsl_b]").
  iIntros (length0 sl_rem err0) "Hpost".
  destruct err0.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & -> & _).
    apply Hfail. eexists _, _. by rewrite -app_assoc. }
  iDestruct "Hpost" as (rem) "[Hrem %Hw64]".
  wp_auto.
  wp_apply (wp_ReadBytes with "[$Hrem]").
  iIntros (ptr_obj sl_tail err1) "Hpost".
  destruct err1.
  { iDestruct "Hpost" as %Hlt. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hvalid).
    rewrite Hw64 -app_assoc in Henc.
    apply w64.enc_inj in Henc as [-> ->].
    rewrite length_app in Hlt. word. }
  iDestruct "Hpost" as (obj tail) "(Hobj & Htail & %Hbytes)".
  destruct Hbytes as [-> Hobjlen].
  wp_auto.
  iApply "HΦ". iFrame "Hobj Htail". iPureIntro.
  rewrite Hw64 -app_assoc. repeat f_equal. word.
Qed.

End proof.
End Slice1D.

End safemarshal.
