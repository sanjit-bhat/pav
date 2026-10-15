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

(* [Proof] unseals publicly: [code.v] proves the hand-written encoder in [prove]. *)
Module Proof.
Record t :=
  mk' {
    Siblings: list w8;
    IsOtherLeaf: bool;
    LeafLabel: list w8;
    LeafVal: list w8;
  }.

Definition enc_fn_def obj :=
  safemarshal.Slice1D.enc_fn obj.(Siblings) ++
  safemarshal.bool.enc_fn obj.(IsOtherLeaf) ++
  safemarshal.Slice1D.enc_fn obj.(LeafLabel) ++
  safemarshal.Slice1D.enc_fn obj.(LeafVal).
Program Definition enc_fn := sealed @enc_fn_def.
Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def obj :=
  safemarshal.Slice1D.valid obj.(Siblings) ∧
  safemarshal.Slice1D.valid obj.(LeafLabel) ∧
  safemarshal.Slice1D.valid obj.(LeafVal).
Program Definition valid := sealed @valid_def.
Definition valid_unseal : valid = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal valid_unseal /enc_fn_def /valid_def. intros Heq (?&?&?) (?&?&?). repeat rewrite <- app_assoc in Heq.
  apply safemarshal.Slice1D.enc_inj in Heq as [? Heq]; [|done..].
  apply safemarshal.bool.enc_inj in Heq as [? Heq].
  apply safemarshal.Slice1D.enc_inj in Heq as [? Heq]; [|done..].
  apply safemarshal.Slice1D.enc_inj in Heq as [? ->]; [|done..].
  destruct obj, obj'. by simplify_eq/=.
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ sl_Siblings sl_LeafLabel sl_LeafVal,
  "#Hstr_Proof" ∷ ptr ↦□ (merkle.Proof.mk sl_Siblings obj.(IsOtherLeaf) sl_LeafLabel sl_LeafVal) ∗

  "#Hsl_Siblings" ∷ sl_Siblings ↦*□ obj.(Siblings) ∗
  "#Hsl_LeafLabel" ∷ sl_LeafLabel ↦*□ obj.(LeafLabel) ∗
  "#Hsl_LeafVal" ∷ sl_LeafVal ↦*□ obj.(LeafVal).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iNamed 1.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_Siblings") as %?.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_LeafLabel") as %?.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_LeafVal") as %?.
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : merkle.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init merkle ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! merkle.ProofEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_Siblings sl_LeafLabel sl_LeafVal) "(Hstr_Proof & Hsl_Siblings & Hsl_LeafLabel & Hsl_LeafVal)".
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_Siblings]") as "* (Hsl_b & Hcap_b & Hsl_Siblings & %)".
  wp_apply (safemarshal.bool.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_LeafLabel]") as "* (Hsl_b & Hcap_b & Hsl_LeafLabel & %)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_LeafVal]") as "* (Hsl_b & Hcap_b & Hsl_LeafVal & %)".
  iApply "HΦ". iFrame "Hcap_b".
  iSplitL "Hsl_b". { iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc. }
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init merkle ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! merkle.ProofDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ⌜¬ ∃ obj tail, b = enc_fn obj ++ tail ∧ valid obj⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj ∗
      sl_tail ↦*□ tail ∗
      ⌜b = enc_fn obj ++ tail⌝
    end
  }}}.
Proof.
  wp_start as "#Hsl_b". wp_auto.
  wp_apply (safemarshal.Slice1D.wp_dec with "[$Hsl_b]").
  iIntros (a1 b1 err1) "Hpost". destruct err1.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v1 rem1) "(Hv1 & Hb1 & %Hrem1)".
  iDestruct (safemarshal.Slice1D.own_valid with "Hv1") as %?.
  wp_auto.
  wp_apply (safemarshal.bool.wp_dec with "[$Hb1]").
  iIntros (a2 b2 err2) "Hpost". destruct err2.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite Hrem1 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. exact Henc. }
  iDestruct "Hpost" as (rem2) "(Hb2 & %Hrem2)".
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb2]").
  iIntros (a3 b3 err3) "Hpost". destruct err3.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite Hrem1 Hrem2 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply safemarshal.bool.enc_inj in Henc as [_ Henc].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v3 rem3) "(Hv3 & Hb3 & %Hrem3)".
  iDestruct (safemarshal.Slice1D.own_valid with "Hv3") as %?.
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb3]").
  iIntros (a4 b4 err4) "Hpost". destruct err4.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite Hrem1 Hrem2 Hrem3 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply safemarshal.bool.enc_inj in Henc as [_ Henc].
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v4 rem4) "(Hv4 & Hb4 & %Hrem4)".
  iDestruct (safemarshal.Slice1D.own_valid with "Hv4") as %?.
  wp_auto.
  wp_alloc l as "Hptr".
  iPersist "Hptr".
  wp_auto.
  iApply "HΦ". iExists (mk' v1 a2 v3 v4), rem4.
  iFrame "Hb4". iSplit; [iExists a1, a3, a4; by iFrame "∗#"|].
  iPureIntro. rewrite Hrem1 Hrem2 Hrem3 Hrem4 enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

End proof.
End Proof.

End merkle.
