From New.generatedproof.github_com.sanjit_bhat.pav Require Import merkle.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import cryptoffi.
From New.proof.github_com.sanjit_bhat.pav Require Import safemarshal.
From New.proof.github_com.sanjit_bhat.pav.merkle_proof Require Import base.

Module merkle.
Section proof.

Inductive dec_node :=
  | DecEmpty
  | DecLeaf (label val : list w8)
  | DecInner (hash0 hash1 : list w8)
  | DecInvalid.

Definition decode_leaf (data : list w8) : option (list w8 * list w8) :=
  let rem0 := data in
  match bool_decide (length rem0 >= 8%nat) with
  | false => None
  | _ =>
    let label_len := uint.nat (le_to_u64 (take 8%nat rem0)) in
    let rem1 := drop 8%nat rem0 in
    match bool_decide (length rem1 >= label_len) with
    | false => None
    | _ =>
      let label := take label_len rem1 in
      let rem2 := drop label_len rem1 in
      match bool_decide (length rem2 >= 8%nat) with
      | false => None
      | _ =>
        let val_len := uint.nat (le_to_u64 (take 8%nat rem2)) in
        let rem3 := drop 8%nat rem2 in
        match bool_decide (length rem3 >= val_len) with
        | false => None
        | _ =>
          let val := take val_len rem3 in
          let rem4 := drop val_len rem3 in
          match bool_decide (rem4 = []) with
          | false => None
          | _ => Some (label, val)
          end
        end
      end
    end
  end.

(* [decode_node] lets us compute one dec_node of a tree inversion. *)
Definition decode_node (data : option $ list w8) :=
  match data with
  | None => DecInvalid
  | Some d =>
    match d with
    | [] => DecInvalid
    | tag :: d' =>
      if decide (tag = emptyNodeTag ∧ d' = [])
      then DecEmpty
      else if decide (tag = leafNodeTag)
      then
        match decode_leaf d' with
        | None => DecInvalid
        | Some x => DecLeaf x.1 x.2
        end
      else if decide (tag = innerNodeTag ∧ Z.of_nat (length d') = 2 * cryptoffi.hash_len)
      then
        DecInner
          (take (Z.to_nat cryptoffi.hash_len) d')
          (drop (Z.to_nat cryptoffi.hash_len) d')
      else DecInvalid
    end
  end.

Lemma decode_empty_inj d :
  decode_node d = DecEmpty →
  d = Some [emptyNodeTag].
Proof.
  rewrite /decode_node. intros.
  case_match; [|done].
  case_match; [done|].
  case_decide; [naive_solver|].
  case_decide; [by case_match|].
  by case_decide.
Qed.

Lemma decode_empty_det :
  decode_node (Some [emptyNodeTag]) = DecEmpty.
Proof.
  simpl.
  case_decide; [done|].
  naive_solver.
Qed.

Lemma decode_leaf_inj_aux d l v :
  decode_leaf d = Some (l, v) →
  d = u64_le (W64 (length l)) ++ l ++ u64_le (W64 (length v)) ++ v.
Proof.
  rewrite /decode_leaf. intros.
  case_bool_decide; [|done].
  case_bool_decide; [|done].
  case_bool_decide; [|done].
  case_bool_decide; [|done].
  case_bool_decide; [|done].
  simplify_eq/=.
  remember d as rem0.

  rewrite -{1}(take_drop 8 rem0).
  rewrite -{1}(take_drop 8 (_ ++ _ ++ _ ++ _)).
  f_equal.
  { rewrite take_app_length'; [|len].
    rewrite length_take_le; [|lia].
    rewrite w64_to_nat_id.
    rewrite le_to_u64_le; [done|].
    rewrite length_take. lia. }
  remember (uint.nat (le_to_u64 (take 8 rem0))) as labelLen.
  remember (drop 8 rem0) as rem1.

  rewrite drop_app_length'; [|len].
  rewrite -{1}(take_drop labelLen rem1).
  f_equal.
  remember (drop labelLen rem1) as rem2.

  rewrite -{1}(take_drop 8 rem2).
  rewrite -{1}(take_drop 8 (_ ++ _)).
  f_equal.
  { rewrite take_app_length'; [|len].
    rewrite length_take_le; [|lia].
    rewrite w64_to_nat_id.
    rewrite le_to_u64_le; [done|].
    rewrite length_take. lia. }
  remember (uint.nat (le_to_u64 (take 8 rem2))) as valLen.
  remember (drop 8 rem2) as rem3.

  rewrite drop_app_length'; [|len].
  rewrite -{1}(take_drop valLen rem3).
  rewrite H4.
  by list_simplifier.
Qed.

Lemma decode_leaf_inj d l v :
  decode_node d = DecLeaf l v →
  d =
  Some $
    leafNodeTag ::
    u64_le (W64 (length l)) ++ l ++
    u64_le (W64 (length v)) ++ v.
Proof.
  rewrite /decode_node. intros.
  case_match; [|done].
  case_match; [done|].
  case_decide; [naive_solver|].
  case_decide. 2: { by case_decide. }
  case_match; [|done].
  destruct p. simplify_eq/=.
  opose proof (decode_leaf_inj_aux _ _ _ _) as Heq; [done|].
  by rewrite Heq.
Qed.

Lemma decode_leaf_det_aux l v :
  length l < 2^64 →
  length v < 2^64 →
  decode_leaf (
    u64_le (W64 (length l)) ++ l ++
    u64_le (W64 (length v)) ++ v
  ) = Some (l, v).
Proof.
  intros. rewrite /decode_leaf.
  repeat (rewrite take_app_length'; [|len]).
  rewrite u64_le_to_word.
  repeat (rewrite drop_app_length'; [|len]).
  repeat (rewrite take_app_length'; [|len]).
  rewrite u64_le_to_word.
  rewrite take_ge; [|word].
  rewrite drop_ge; [|word].

  case_bool_decide as Hif.
  2: { revert Hif. len. }
  clear Hif.
  case_bool_decide as Hif.
  2: { revert Hif. len. }
  clear Hif.
  case_bool_decide as Hif.
  2: { revert Hif. len. }
  clear Hif.
  case_bool_decide as Hif.
  2: { revert Hif. len. }
  clear Hif.
  by case_bool_decide.
Qed.

Lemma decode_leaf_det l v :
  length l < 2^64 →
  length v < 2^64 →
  decode_node (
    Some $ leafNodeTag ::
    u64_le (W64 (length l)) ++ l ++
    u64_le (W64 (length v)) ++ v
  ) = DecLeaf l v.
Proof.
  intros. simpl.
  case_decide; [naive_solver|].
  case_decide; [|done].
  by rewrite decode_leaf_det_aux.
Qed.

Lemma decode_inner_inj d h0 h1 :
  decode_node d = DecInner h0 h1 →
  d = Some $ innerNodeTag :: h0 ++ h1 ∧
    Z.of_nat $ length h0 = cryptoffi.hash_len ∧
    Z.of_nat $ length h1 = cryptoffi.hash_len.
Proof.
  rewrite /decode_node. intros.
  case_match; [|done].
  case_match; [done|].
  case_decide; [naive_solver|].
  case_decide. { by case_match. }
  case_decide; [|done].
  destruct_and!.
  simplify_eq/=.
  split; [|len].
  by rewrite take_drop.
Qed.

Lemma decode_inner_det h0 h1 :
  Z.of_nat $ length h0 = cryptoffi.hash_len →
  Z.of_nat $ length h1 = cryptoffi.hash_len →
  decode_node (Some $ innerNodeTag :: h0 ++ h1) = DecInner h0 h1.
Proof.
  intros. simpl.
  case_decide; [len|].
  case_decide; [done|].
  case_decide.
  2: { intuition. revert H3. len. }
  rewrite take_app_length'; [|lia].
  by rewrite drop_app_length'; [|lia].
Qed.

(* for every node, there's only one data that decodes to it. *)
Lemma decode_node_inj n d0 d1 :
  n = decode_node d0 →
  n = decode_node d1 →
  n ≠ DecInvalid →
  d0 = d1 ∧ is_Some d1.
Proof.
  intros. destruct n; try done.
  - opose proof (decode_empty_inj d0 _) as ->; [done|].
    by opose proof (decode_empty_inj d1 _) as ->.
  - opose proof (decode_leaf_inj d0 _ _ _) as ->; [done|].
    by opose proof (decode_leaf_inj d1 _ _ _) as ->.
  - opose proof (decode_inner_inj d0 _ _ _) as [-> ?]; [done|].
    by opose proof (decode_inner_inj d1 _ _ _) as [-> ?].
Qed.

End proof.

Section dfrac_valid.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : merkle.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

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

Module Proof.
Record t :=
  mk' {
    Siblings: list w8;
    IsOtherLeaf: bool;
    LeafLabel: list w8;
    LeafVal: list w8;
  }.

Definition encodes (obj : t) (enc : list w8) : Prop :=
  sint.Z (W64 (length obj.(Siblings))) = length obj.(Siblings) ∧
  sint.Z (W64 (length obj.(LeafLabel))) = length obj.(LeafLabel) ∧
  sint.Z (W64 (length obj.(LeafVal))) = length obj.(LeafVal) ∧

  enc = (u64_le $ W64 $ length obj.(Siblings)) ++ obj.(Siblings) ++
  [(if obj.(IsOtherLeaf) then W8 1 else W8 0)] ++
  (u64_le $ W64 $ length obj.(LeafLabel)) ++ obj.(LeafLabel) ++
  (u64_le $ W64 $ length obj.(LeafVal)) ++ obj.(LeafVal).

Lemma inj {obj0 obj1 enc0 enc1 tail0 tail1} :
  enc0 ++ tail0 = enc1 ++ tail1 →
  encodes obj0 enc0 →
  encodes obj1 enc1 →
  obj0 = obj1 ∧ enc0 = enc1 ∧ tail0 = tail1.
Proof.
  intros ? (?&?&? & Henc0) (?&?&? & Henc). subst.
  list_simplifier. move: H => Henc.
  apply app_inj_1 in Henc as [Hlen_sib Henc]; [|len].
  apply (inj u64_le) in Hlen_sib.
  apply app_inj_1 in Henc as [Heq_sib Henc]; [|word].
  inv Henc as [[Heq_found Henc']].
  apply app_inj_1 in Henc' as [Hlen_label Henc]; [|len].
  apply (inj u64_le) in Hlen_label.
  apply app_inj_1 in Henc as [Heq_label Henc]; [|word].
  apply app_inj_1 in Henc as [Hlen_val Henc]; [|len].
  apply (inj u64_le) in Hlen_val.
  assert (obj0.(IsOtherLeaf) = obj1.(IsOtherLeaf)) as ?.
  { by repeat case_match. }
  apply app_inj_1 in Henc as [Heq_val Henc]; [|word].
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : merkle.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_Siblings sl_LeafLabel sl_LeafVal,
  "Hstruct" ∷ ptr ↦{d} (merkle.Proof.mk sl_Siblings
    obj.(IsOtherLeaf) sl_LeafLabel sl_LeafVal) ∗

  "Hsl_Siblings" ∷ sl_Siblings ↦*{d} obj.(Siblings) ∗
  "Hsl_LeafLabel" ∷ sl_LeafLabel ↦*{d} obj.(LeafLabel) ∗
  "Hsl_LeafVal" ∷ sl_LeafVal ↦*{d} obj.(LeafVal).

Definition wish b obj tail : iProp Σ :=
  ∃ enc,
  "%Henc_obj" ∷ ⌜encodes obj enc⌝ ∗
  "%Heq_tail" ∷ ⌜b = enc ++ tail⌝.

Lemma wish_det b obj0 obj1 tail0 tail1 :
  wish b obj0 tail0 -∗
  wish b obj1 tail1 -∗
  ⌜obj0 = obj1 ∧ tail0 = tail1⌝.
Proof.
  iNamedSuffix 1 "0".
  iNamedSuffix 1 "1".
  opose proof (inj _ Henc_obj0 Henc_obj1) as ?.
  { by subst. }
  naive_solver.
Qed.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init merkle ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! merkle.ProofDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj tail, wish b obj tail
    | false =>
      ∃ obj tail,
      "Hwish" ∷ wish b obj tail ∗
      "Hown_obj" ∷ own ptr_obj obj d ∗
      "Hsl_tail" ∷ sl_tail ↦*{d} tail
    end
  }}}.
Proof.
  wp_start as "Hsl_b". wp_auto.
  destruct b as [|b0 brest].
  - (* empty input: no valid encoding (it needs >= 8 bytes) *)
    wp_apply (safemarshal.Slice1D.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    + wp_auto. iApply "HΦ". iIntros "Hex".
      iDestruct "Hex" as (obj tail) "Hwish". iNamed "Hwish".
      destruct Henc_obj as (_ & _ & _ & Henc).
      iExFalso. iPureIntro. subst enc. apply (f_equal length) in Heq_tail.
      rewrite !length_app !u64_le_length /= in Heq_tail. lia.
    + iDestruct "Hpost1" as (sib rem1) "(Ha1 & Hb1 & %Hsl1)".
      destruct Hsl1 as [Henc1 _].
      rewrite /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Henc1.
      iExFalso. iPureIntro. apply (f_equal length) in Henc1.
      rewrite !length_app u64_le_length /= in Henc1. lia.
  - iDestruct (own_slice_dfrac_valid with "Hsl_b") as %Hvd; [simpl; lia|].
    wp_apply (safemarshal.Slice1D.wp_dec with "[$Hsl_b]").
    iIntros (a1 b1 err1) "Hpost1". destruct err1.
    { (* Siblings read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex".
      iDestruct "Hex" as (obj tail) "Hwish". iNamed "Hwish".
      destruct Henc_obj as (Hvsib & Hvlabel & Hvval & Henc).
      iApply "Hpost1". iExists obj.(Siblings), _. iPureIntro.
      rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
              /safemarshal.w64.pure_enc /safemarshal.Slice1D.valid.
      split; [rewrite Heq_tail Henc -?app_assoc // | word]. }
    iDestruct "Hpost1" as (sib rem1) "(Ha1 & Hb1 & %Hsl1)".
    wp_auto.
    wp_apply (safemarshal.bool.wp_dec with "[$Hb1]").
    iIntros (a2 b2 err2) "Hpost2". destruct err2.
    { (* IsOtherLeaf read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex".
      iDestruct "Hex" as (obj tail) "Hwish". iNamed "Hwish".
      destruct Henc_obj as (Hvsib & Hvlabel & Hvval & Henc). subst enc.
      iApply "Hpost2".
      iExists obj.(IsOtherLeaf),
        (u64_le (W64 (length obj.(LeafLabel))) ++ obj.(LeafLabel) ++
         u64_le (W64 (length obj.(LeafVal))) ++ obj.(LeafVal) ++ tail).
      iPureIntro.
      assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(Siblings)
        ([if obj.(IsOtherLeaf) then W8 1 else W8 0] ++
         u64_le (W64 (length obj.(LeafLabel))) ++ obj.(LeafLabel) ++
         u64_le (W64 (length obj.(LeafVal))) ++ obj.(LeafVal) ++ tail)) as Hwsib.
      { rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
          /safemarshal.w64.pure_enc. split; [|exact Hvsib].
        rewrite Heq_tail -?app_assoc //. }
      destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1 Hwsib) as [_ Hrem1].
      rewrite /safemarshal.bool.wish /safemarshal.bool.pure_enc Hrem1 -?app_assoc //. }
    iDestruct "Hpost2" as (rem2) "(Hb2 & %Hbool)".
    wp_auto.
    wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb2]").
    iIntros (a3 b3 err3) "Hpost3". destruct err3.
    { (* LeafLabel read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex".
      iDestruct "Hex" as (obj tail) "Hwish". iNamed "Hwish".
      destruct Henc_obj as (Hvsib & Hvlabel & Hvval & Henc). subst enc.
      iApply "Hpost3".
      iExists obj.(LeafLabel),
        (u64_le (W64 (length obj.(LeafVal))) ++ obj.(LeafVal) ++ tail).
      iPureIntro.
      assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(Siblings)
        ([if obj.(IsOtherLeaf) then W8 1 else W8 0] ++
         u64_le (W64 (length obj.(LeafLabel))) ++ obj.(LeafLabel) ++
         u64_le (W64 (length obj.(LeafVal))) ++ obj.(LeafVal) ++ tail)) as Hwsib.
      { rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
          /safemarshal.w64.pure_enc. split; [|exact Hvsib].
        rewrite Heq_tail -?app_assoc //. }
      destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1 Hwsib) as [_ Hrem1].
      rewrite /safemarshal.bool.wish /safemarshal.bool.pure_enc in Hbool.
      rewrite Hrem1 in Hbool. apply app_inj_1 in Hbool as [_ Hrem2]; [|len].
      rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
        /safemarshal.w64.pure_enc. split; [|exact Hvlabel].
      rewrite -Hrem2 -?app_assoc //. }
    iDestruct "Hpost3" as (label rem3) "(Ha3 & Hb3 & %Hsl3)".
    wp_auto.
    wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb3]").
    iIntros (a4 b4 err4) "Hpost4". destruct err4.
    { (* LeafVal read failed *)
      wp_auto. iApply "HΦ". iIntros "Hex".
      iDestruct "Hex" as (obj tail) "Hwish". iNamed "Hwish".
      destruct Henc_obj as (Hvsib & Hvlabel & Hvval & Henc). subst enc.
      iApply "Hpost4".
      iExists obj.(LeafVal), tail.
      iPureIntro.
      assert (safemarshal.Slice1D.wish (b0 :: brest) obj.(Siblings)
        ([if obj.(IsOtherLeaf) then W8 1 else W8 0] ++
         u64_le (W64 (length obj.(LeafLabel))) ++ obj.(LeafLabel) ++
         u64_le (W64 (length obj.(LeafVal))) ++ obj.(LeafVal) ++ tail)) as Hwsib.
      { rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
          /safemarshal.w64.pure_enc. split; [|exact Hvsib].
        rewrite Heq_tail -?app_assoc //. }
      destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl1 Hwsib) as [_ Hrem1].
      rewrite /safemarshal.bool.wish /safemarshal.bool.pure_enc in Hbool.
      rewrite Hrem1 in Hbool. apply app_inj_1 in Hbool as [_ Hrem2]; [|len].
      assert (safemarshal.Slice1D.wish rem2 obj.(LeafLabel)
        (u64_le (W64 (length obj.(LeafVal))) ++ obj.(LeafVal) ++ tail)) as Hwlabel.
      { rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
          /safemarshal.w64.pure_enc. split; [|exact Hvlabel].
        rewrite -Hrem2 -?app_assoc //. }
      destruct (safemarshal.Slice1D.wish_det _ _ _ _ Hsl3 Hwlabel) as [_ Hrem3].
      rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc
        /safemarshal.w64.pure_enc. split; [|exact Hvval].
      rewrite Hrem3 -?app_assoc //. }
    iDestruct "Hpost4" as (val rem4) "(Ha4 & Hb4 & %Hsl4)".
    wp_auto.
    wp_alloc l as "Hptr".
    iMod (dfractional_update_to_dfrac _ d with "Hptr") as "Hptr"; [exact Hvd|].
    wp_auto.
    iApply "HΦ".
    iExists (Proof.mk' sib a2 label val), rem4.
    destruct Hsl1 as [Heq1 Hv1]. destruct Hsl3 as [Heq3 Hv3]. destruct Hsl4 as [Heq4 Hv4].
    rewrite /safemarshal.Slice1D.wish /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc in Heq1 Heq3 Heq4.
    rewrite /safemarshal.Slice1D.valid in Hv1 Hv3 Hv4.
    rewrite /safemarshal.bool.wish /safemarshal.bool.pure_enc in Hbool.
    iSplitR.
    { iExists (u64_le (W64 (length sib)) ++ sib ++ [if a2 then W8 1 else W8 0] ++
               u64_le (W64 (length label)) ++ label ++ u64_le (W64 (length val)) ++ val).
      iSplit; iPureIntro.
      - rewrite /encodes /=. split_and!; [word | word | word | done].
      - rewrite Heq1 Hbool Heq3 Heq4 -!app_assoc //. }
    iSplitR "Hb4".
    { iExists a1, a3, a4. iFrame "Hptr Ha1 Ha3 Ha4". }
    iFrame "Hb4".
Qed.

End proof.
End Proof.
End merkle.
