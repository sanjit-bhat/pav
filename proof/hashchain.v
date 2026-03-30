From New.generatedproof.github_com.sanjit_bhat.pav Require Import hashchain.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof Require Import bytes.
From New.proof.github_com.goose_lang Require Import std.
From New.proof.github_com.sanjit_bhat.pav Require Import cryptoffi cryptoutil.

Module hashchain.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

(* hashchain is special bc same party both inverts
and hashes on more vals to compute future links. *)

(** impl / spec requirements for hashchain:
- allow for "bootstrapping", where a user starts following the hashchain
only after some epoch.
- injective lemma for security. if two hashchains have the same hash,
they commit to the same underlying values.
- optional correctness between Prover and Verifier.
Verify determ generates [newLink] from [prevLink] and [proof].

observations:
- with two bootstrapped users, injectivity becomes annoying to state.
(e.g., that two hashchains are suffixes of each other.)
if you add in hash inversion, it reduces to simple equality.

observations on hash inversion:
- to invert, the hashchain predicate needs to cover all possible decoding states.
it's easiest to do that if the predicate matches on the decoding.
i.e., normal representation predicates go from obj -> ptr (hash).
for inversion, we go from ptr -> obj.
- it's hard to have an inductive inversion proof without [limit].
there's nothing else to induct on! *)

Inductive DecChain :=
  | DecEmpty
  | DecLink (prevLink val : list w8)
  | DecInvalid.

Local Definition dec_link data : option (list w8 * list w8) :=
  let rem0 := data in
  match bool_decide (Z.of_nat $ length rem0 >= cryptoffi.hash_len) with
  | false => None
  | _ =>
    let prevLink := take (Z.to_nat cryptoffi.hash_len) rem0 in
    let val := drop (Z.to_nat cryptoffi.hash_len) rem0 in
    Some (prevLink, val)
  end.

Local Definition dec_chain data :=
  match data with
  | None => DecInvalid
  | Some d =>
    match d with
    | [] => DecEmpty
    | _ =>
      match dec_link d with
      | None => DecInvalid
      | Some x => DecLink x.1 x.2
      end
    end
  end.

Local Lemma dec_empty_inj d :
  dec_chain d = DecEmpty →
  d = Some $ [].
Proof.
  rewrite /dec_chain. intros.
  case_match; [|done].
  case_match; [done|].
  by case_match.
Qed.

Local Lemma dec_link_inj_aux d x :
  dec_link d = Some x →
  d = x.1 ++ x.2 ∧
    Z.of_nat $ length x.1 = cryptoffi.hash_len.
Proof.
  rewrite /dec_link. intros.
  case_bool_decide; [|done].
  simplify_eq/=.
  remember d as rem0.

  rewrite take_drop.
  split; [done|len].
Qed.

Lemma dec_link_inj d prevLink val :
  dec_chain d = DecLink prevLink val →
  d = Some $ prevLink ++ val ∧
    Z.of_nat $ length prevLink = cryptoffi.hash_len.
Proof.
  rewrite /dec_chain. intros.
  case_match; [|done].
  case_match; [done|].
  case_match; [|done].
  opose proof (dec_link_inj_aux _ _ _) as [Heq ?]; [done|].
  rewrite Heq.
  by simplify_eq/=.
Qed.

Local Lemma dec_link_det_aux prevLink val :
  Z.of_nat $ length prevLink = cryptoffi.hash_len →
  dec_link (prevLink ++ val) = Some (prevLink, val).
Proof.
  intros. rewrite /dec_link.
  case_bool_decide.
  2: { autorewrite with len in *. word. }
  rewrite take_app_length'; [|word].
  rewrite drop_app_length'; [|word].
  done.
Qed.

Local Lemma dec_link_det prevLink val :
  Z.of_nat $ length prevLink = cryptoffi.hash_len →
  dec_chain (Some $ prevLink ++ val) = DecLink prevLink val.
Proof.
  intros. simpl.
  case_match eqn:Heq.
  { apply (f_equal length) in Heq.
    autorewrite with len in *. word. }
  rewrite -{}Heq.
  by rewrite dec_link_det_aux.
Qed.

(* returns [vs] and [cut].
to invert all [vs], fuel should at least be [S $ length vs]. *)
Fixpoint inv_fn hash fuel : ((list $ list w8) * option (list w8))%type :=
  match fuel with 0%nat => ([], Some hash) | S fuel' =>
  match dec_chain (cryptoffi.hash_inv_fn hash) with
  | DecEmpty => ([], None)
  | DecLink prevLink v =>
    let x := inv_fn prevLink fuel' in
    (x.1 ++ [v], x.2)
  | DecInvalid => ([], Some hash)
  end end.

(* for now, intentionally left transp.
callers should use valid vs. inv_fn when needed. *)
Definition valid vs cut hash fuel :=
  inv_fn hash fuel = (vs, cut) ∧
  (∀ x, cut = Some x → Z.of_nat (length x) = cryptoffi.hash_len).

(* there are multiple parties (some operating under is_Some cut)
that rely on the HashChain API to determ compute the same hash.
lucky for us, a hashchain (unlike a merkle tree) only has one location for cuts.
so long as we externalize the one cut hash, we get determinism. *)
Lemma det hash0 hash1 fuel0 fuel1 :
  inv_fn hash0 fuel0 = inv_fn hash1 fuel1 →
  hash0 = hash1.
Proof.
  revert hash0 hash1 fuel1.
  induction fuel0; intros;
    destruct fuel1; simplify_eq/=; try done;
    try destruct (dec_chain (cryptoffi.hash_inv_fn hash0)) eqn:Hdec0;
    try destruct (dec_chain (cryptoffi.hash_inv_fn hash1)) eqn:Hdec1;
    simplify_eq/=; try done;
    try discriminate_list.
  - apply dec_empty_inj in Hdec0.
    apply dec_empty_inj in Hdec1.
    apply cryptoffi.hash_bij_r in Hdec0.
    apply cryptoffi.hash_bij_r in Hdec1.
    by simplify_eq/=.
  - list_simplifier.
    opose proof (IHfuel0 prevLink prevLink0 fuel1 _) as ->.
    { do 2 destruct (inv_fn _ _). by simplify_eq/=. }
    apply dec_link_inj in Hdec0 as [Hdec0 _].
    apply dec_link_inj in Hdec1 as [Hdec1 _].
    apply cryptoffi.hash_bij_r in Hdec0.
    apply cryptoffi.hash_bij_r in Hdec1.
    by simplify_eq/=.
Qed.

Local Lemma valid_len vs cut hash fuel :
  valid vs cut hash fuel →
  Z.of_nat (length hash) = cryptoffi.hash_len.
Proof.
  intros [Hfn ?].
  destruct fuel; simplify_eq/=; [naive_solver|].
  case_match eqn:Hdec; simplify_eq/=.
  - apply dec_empty_inj in Hdec.
    by apply cryptoffi.is_hash_len' in Hdec.
  - apply dec_link_inj in Hdec as [Hdec _].
    by apply cryptoffi.is_hash_len' in Hdec.
  - naive_solver.
Qed.

Local Lemma snoc {vs cut prevLink fuel} v nextLink :
  valid vs cut prevLink fuel →
  cryptoffi.hash_fn (prevLink ++ v) = Some nextLink →
  valid (vs ++ [v]) cut nextLink (S fuel).
Proof.
  intros Hfn Hhash%cryptoffi.hash_bij_l.
  apply valid_len in Hfn as ?.
  destruct Hfn as [Hfn ?].
  split; [|done]. simpl.
  rewrite Hhash.
  rewrite dec_link_det; [|done].
  by rewrite Hfn.
Qed.

End defs.

Section wps.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : hashchain.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

#[global] Instance : IsPkgInit (iProp Σ) hashchain := define_is_pkg_init True%I.
#[global] Instance : GetIsPkgInitWf (iProp Σ) hashchain := build_get_is_pkg_init_wf.

Lemma wp_GetEmptyLink :
  {{{ is_pkg_init hashchain }}}
  @! hashchain.GetEmptyLink #()
  {{{
    sl_hash hash, RET #sl_hash;
    "Hsl_hash" ∷ sl_hash ↦* hash ∗
    "%His_chain" ∷ ⌜valid [] None hash 1⌝
  }}}.
Proof.
  wp_start.
  wp_apply (cryptoutil.wp_Hash _ inhabitant) as "* @".
  { iApply own_slice_nil. }
  iApply "HΦ".
  iFrame.
  iPureIntro.
  split; [|done]. simpl.
  by apply cryptoffi.hash_bij_l in His_hash as ->.
Qed.

Lemma wp_GetNextLink sl_prevLink d0 prevLink sl_nextVal d1 nextVal vs cut fuel :
  {{{
    is_pkg_init hashchain ∗
    "Hsl_prevLink" ∷ sl_prevLink ↦*{d0} prevLink ∗
    "Hsl_nextVal" ∷ sl_nextVal ↦*{d1} nextVal ∗
    "%His_chain" ∷ ⌜valid vs cut prevLink fuel⌝
  }}}
  @! hashchain.GetNextLink #sl_prevLink #sl_nextVal
  {{{
    sl_nextLink nextLink, RET #sl_nextLink;
    "Hsl_prevLink" ∷ sl_prevLink ↦*{d0} prevLink ∗
    "Hsl_nextVal" ∷ sl_nextVal ↦*{d1} nextVal ∗
    "Hsl_nextLink" ∷ sl_nextLink ↦* nextLink ∗
    "%His_chain" ∷ ⌜valid (vs ++ [nextVal]) cut nextLink (S fuel)⌝
  }}}.
Proof.
  wp_start. iNamed "Hpre".
  wp_auto.
  wp_apply cryptoffi.wp_NewHasher as "* @".
  wp_apply (cryptoffi.wp_Hasher_Write with "[$Hown_hr $Hsl_prevLink]").
  iNamedSuffix 1 "0". wp_auto.
  wp_apply (cryptoffi.wp_Hasher_Write with "[$Hown_hr0 $Hsl_nextVal]").
  iNamedSuffix 1 "1". wp_auto.
  wp_apply (cryptoffi.wp_Hasher_Sum with "[$Hown_hr1]").
  { iApply own_slice_nil. }
  iIntros "*". iNamed 1.
  wp_auto.
  iApply "HΦ".
  iFrame.
  iPureIntro. by eapply snoc.
Qed.

Definition own (ptr : loc) (vs : list $ list w8) (d : dfrac) : iProp Σ :=
  ∃ sl_pred_last_link pred_last_link sl_last_link last_link sl_enc enc,
  "Hstruct" ∷ ptr ↦{d} (hashchain.HashChain.mk sl_pred_last_link sl_last_link sl_enc) ∗

  "#Hsl_pred_last_link" ∷ sl_pred_last_link ↦*□ pred_last_link ∗
  "%His_chain_pred" ∷ ⌜∀ x vs',
    vs = vs' ++ [x] →
    valid vs' None pred_last_link (S $ length vs')⌝ ∗

  "#Hsl_last_link" ∷ sl_last_link ↦*□ last_link ∗
  "%His_chain" ∷ ⌜valid vs None last_link (S $ length vs)⌝ ∗

  "Hsl_enc" ∷ sl_enc ↦*{d} enc ∗
  "Hsl_enc_cap" ∷ own_slice_cap w8 sl_enc d ∗
  "%" ∷ ⌜enc = mjoin vs⌝ ∗
  "%Hsame_len" ∷ ⌜Forall (λ x, length x = Z.to_nat cryptoffi.hash_len) vs⌝.

#[global] Instance own_dfractional ptr vs :
  DFractional (λ d, own ptr vs d).
Proof.
  rewrite /own. split.
  - intros ??. iSplit.
    + iNamed 1.
      iDestruct "Hstruct" as "[? ?]".
      iDestruct "Hsl_enc" as "[? ?]".
      iDestruct "Hsl_enc_cap" as "[? ?]".
      by iFrame "∗#".
    + iIntros "[H0 H1]".
      iNamedSuffix "H0" "0".
      iNamedSuffix "H1" "1".
      iCombine "Hstruct0 Hstruct1" as "Hstruct" gives %?.
      simplify_eq/=.
      iCombine "Hsl_enc0 Hsl_enc1" as "Hsl_enc".
      iCombine "Hsl_enc_cap0 Hsl_enc_cap1" as "Hsl_enc_cap".
      by iFrame "∗#%".
  - apply _.
  - intros ?. iNamed 1.
    iPersist "Hstruct Hsl_enc Hsl_enc_cap".
    iModIntro. by iFrame "Hstruct #".
Qed.

Lemma wp_New :
  {{{ is_pkg_init hashchain }}}
  @! hashchain.New #()
  {{{ ptr, RET #ptr; "Hown_HashChain" ∷ own ptr [] 1 }}}.
Proof.
  wp_start.
  wp_apply wp_GetEmptyLink as "* @".
  iPersist "Hsl_hash".
  wp_apply wp_alloc as "* H0".
  iApply "HΦ".
  iFrame "∗#".
  iDestruct own_slice_nil as "$".
  iDestruct own_slice_nil as "$".
  iDestruct own_slice_cap_nil as "$".
  iSplit; [|done].
  iIntros (???).
  discriminate_list.
Qed.

Lemma wp_HashChain_Append ptr_c vs sl_v d0 v :
  {{{
    is_pkg_init hashchain ∗
    "Hown_HashChain" ∷ own ptr_c vs 1 ∗
    "Hsl_val" ∷ sl_v ↦*{d0} v ∗
    "%Hlen_val" ∷ ⌜Z.of_nat $ length v = cryptoffi.hash_len⌝
  }}}
  ptr_c @! (go.PointerType hashchain.HashChain) @! "Append" #sl_v
  {{{
    sl_newLink newLink, RET #sl_newLink;
    "Hown_HashChain" ∷ own ptr_c (vs ++ [v]) 1 ∗
    "Hsl_val" ∷ sl_v ↦*{d0} v ∗
    "#Hsl_newLink" ∷ sl_newLink ↦*□ newLink ∗
    "%His_chain" ∷ ⌜valid (vs ++ [v]) None newLink (S $ S $ length vs)⌝
  }}}.
Proof.
  wp_start. iNamed "Hpre". iNamed "Hown_HashChain".
  wp_auto.
  iDestruct (own_slice_len with "Hsl_val") as %?.
  wp_apply wp_Assert.
  { iPureIntro. apply bool_decide_eq_true. word. }
  wp_apply (wp_GetNextLink with "[Hsl_val]").
  { iFrame "∗#%". }
  iIntros "*". iNamedSuffix 1 "_n".
  iPersist "Hsl_prevLink_n Hsl_nextLink_n".
  wp_auto.
  wp_apply (wp_slice_append with "[$Hsl_enc $Hsl_enc_cap $Hsl_nextVal_n]")
    as "* (Hsl_enc & Hsl_enc_cap & Hsl_nextVal_n)".
  iApply "HΦ".
  iFrame "∗#%".
  autorewrite with len.
  replace (_ + 1)%nat with (S $ length vs) by lia.
  iFrame "%".
  repeat iSplit.
  - iIntros (?? Heq).
    apply app_inj_tail in Heq as [-> ->].
    iFrame "#%".
  - iPureIntro. subst. rewrite join_app. by list_simplifier.
  - iPureIntro. apply Forall_snoc. split; [done|word].
Qed.

(* unlike most other pav wishes, [wish_Proof] doesn't tie down all
inputs and outputs of [hashchain.Verify].
it only says that [proof] deterministically decodes to [newVals].
the remaining input is [prevLink].
it's not referenced because it's client-tracked.
the outputs ([extLen], [newVal], [newLink]) aren't referenced
because they deterministically derive from [prevLink] and [newVals]. *)
Definition wish_Proof (proof : list w8) newVals :=
  Forall (λ x, length x = Z.to_nat cryptoffi.hash_len) newVals ∧
  proof = mjoin newVals.

Lemma wish_Proof_det proof newVals0 newVals1 :
  wish_Proof proof newVals0 →
  wish_Proof proof newVals1 →
  newVals0 = newVals1.
Proof.
  intros (?&?) (?&?).
  subst.
  opose proof (join_same_len_inj _ _ _ _ _ _ ltac:(done)) as ->; [|done..].
  word.
Qed.

Lemma wp_Verify sl_prevLink d0 prevLink sl_proof d1 proof old_vs cut fuel :
  {{{
    is_pkg_init hashchain ∗
    "Hsl_prevLink" ∷ sl_prevLink ↦*{d0} prevLink ∗
    "Hsl_proof" ∷ sl_proof ↦*{d1} proof ∗
    "%His_chain" ∷ ⌜valid old_vs cut prevLink fuel⌝
  }}}
  @! hashchain.Verify #sl_prevLink #sl_proof
  {{{
    (extLen : w64) sl_newVal newVal sl_newLink newLink err,
    RET (#extLen, #sl_newVal, #sl_newLink, #err);
    "Hsl_newVal" ∷ sl_newVal ↦*{d1} newVal ∗
    "Hsl_newLink" ∷ sl_newLink ↦*{d0} newLink ∗
    "Hgenie" ∷
      match err with
      | true => ¬ ∃ newVals, ⌜wish_Proof proof newVals⌝
      | false =>
        ∃ newVals,
        "%Hwish_chain" ∷ ⌜wish_Proof proof newVals⌝ ∗
        "%HextLen" ∷ ⌜uint.Z extLen = length newVals⌝ ∗
        "%HnewVal" ∷ ⌜newVal = default [] (last newVals)⌝ ∗
        "%His_chain" ∷ ⌜valid (old_vs ++ newVals) cut newLink (fuel + (length newVals))⌝
      end
  }}}.
Proof.
  wp_start. iNamed "Hpre".
  wp_auto.
  apply valid_len in His_chain as ?.
  iDestruct (own_slice_len with "Hsl_proof") as %[? ?].

  wp_if_destruct.
  2: {
    iApply "HΦ".
    iDestruct own_slice_nil as "$".
    iDestruct own_slice_nil as "$".
    iFrame.
    iIntros ((?&Hsame_len&?)).
    apply join_same_len_length in Hsame_len.
    word. }
  iPersist "extLen".
  remember (word.divu _ _) as extLen.

  iAssert (
    ∃ (i : w64) sl_proof sl_newLink newLink sl_newVal newVal newVals,
    "i" ∷ i_ptr ↦ i ∗
    "%Hlt_i" ∷ ⌜uint.Z i ≤ uint.Z extLen⌝ ∗

    "proof" ∷ proof_ptr ↦ sl_proof ∗
    "newVal" ∷ newVal_ptr ↦ sl_newVal ∗
    "newLink" ∷ newLink_ptr ↦ sl_newLink ∗

    "Hsl_proof" ∷ sl_proof ↦*{d1} drop (Z.to_nat (uint.Z i * cryptoffi.hash_len)) proof ∗
    "Hsl_newVal" ∷ sl_newVal ↦*{d1} newVal ∗
    "Hsl_newLink" ∷ sl_newLink ↦*{d0} newLink ∗

    "(%Hsame_len&%Henc)" ∷ ⌜wish_Proof
      (take (Z.to_nat (uint.Z i * cryptoffi.hash_len)) proof)
      newVals⌝ ∗
    "%" ∷ ⌜length newVals = uint.nat i⌝ ∗
    "->" ∷ ⌜newVal = default [] (last newVals)⌝ ∗
    "%His_chain" ∷ ⌜valid (old_vs ++ newVals) cut newLink (fuel + (length newVals))⌝
  )%I with "[$i $newLink $newVal $proof Hsl_prevLink Hsl_proof]" as "IH".
  { iDestruct own_slice_nil as "?".
    iFrame "∗#".
    iExists [].
    list_simplifier.
    ereplace (?[x] + 0)%nat with (?x) by lia.
    iFrame "#%".
    rewrite take_0'; [|word].
    repeat iSplit; try done.
    word. }
  clear His_chain.
  wp_for "IH".
  case_bool_decide.

  2: {
    wp_auto.
    rewrite take_ge in Henc; [|word].
    iApply "HΦ".
    replace i with extLen in * by word.
    iFrame "∗#%".
    repeat iSplit; try done.
    word. }

  rewrite -wp_fupd.
  iRename "Hsl_newVal" into "Hsl_newVal_old".
  wp_auto.
  iDestruct (own_slice_wf with "Hsl_proof") as %?.
  iDestruct (own_slice_len with "Hsl_proof") as %[Hlen_proof _].
  rewrite length_drop in Hlen_proof.
  case_decide. 2: { exfalso. word. }
  wp_auto.
  case_decide. 2: { exfalso. word. }
  wp_auto.
  iDestruct (own_slice_slice (W64 32) (W64 32) with "Hsl_proof")
    as "(Hsl_newVal&_&Hsl_proof)"; [word|].
  wp_apply (wp_GetNextLink with "[$Hsl_newLink $Hsl_newVal]") as "* @"; [done|].
  iMod (own_slice_update_to_dfrac d0 with "Hsl_nextLink") as "Hsl_nextLink".
  { (* TODO: need to extract [✓ d0] from Hsl_prevLink.
    one easy fix: prove validity OR empty list.
    this seems like a "hack" that works for the goose v4 slice model.
    but at its core, we're dealing with a zero-sized alloc problem,
    and make({}struct, 10) is still zero-sized. *)
    admit. }
  iModIntro.
  wp_for_post.
  iFrame "newLink ∗".

  iEval (rewrite drop_drop) in "Hsl_proof".
  replace (uint.Z (word.add _ _)) with (uint.Z i + 1) by word.
  replace (Z.to_nat (uint.Z i * cryptoffi.hash_len) + sint.nat (W64 32))%nat
    with (Z.to_nat ((uint.Z i + 1) * cryptoffi.hash_len))%nat by word.
  iFrame "Hsl_proof".

  list_simplifier.
  Opaque valid.
  iExists _. repeat iSplit; try iPureIntro.
  6: { exact_eq His_chain0. len. }
  - word.
  - apply Forall_snoc. split; [done|len].
  - rewrite join_app.
    rewrite (take_subslice (Z.to_nat (uint.Z i * cryptoffi.hash_len))); [|word].
    f_equal; [done|].
    rewrite subslice_take_drop'.
    list_simplifier.
    repeat f_equal. word.
  - len.
  - rewrite last_snoc /=. f_equal; word.
  (* TODO: [word] in goose v4 seems to take much longer than in goose v3. *)
Admitted.

Lemma wp_HashChain_Prove c vs d (prevLen : w64) :
  {{{
    is_pkg_init hashchain ∗
    "Hown_HashChain" ∷ own c vs d ∗
    "%Hlt_prevLen" ∷ ⌜uint.Z prevLen <= length vs⌝
  }}}
  c @! (go.PointerType hashchain.HashChain) @! "Prove" #prevLen
  {{{
    sl_proof proof, RET #sl_proof;
    let newVals := drop (uint.nat prevLen) vs in
    "Hown_HashChain" ∷ own c vs d ∗
    "Hsl_proof" ∷ sl_proof ↦* proof ∗

    "%Hwish" ∷ ⌜wish_Proof proof newVals⌝
  }}}.
Proof.
  wp_start. iNamed "Hpre". iNamed "Hown_HashChain".
  wp_auto.
  iDestruct (own_slice_len with "Hsl_enc") as %?.
  apply join_same_len_length in Hsame_len as ?.
  iDestruct (own_slice_wf with "Hsl_enc") as %?.
  case_decide; [|word].
  wp_auto.
  remember (word.mul _ _) as split.
  iDestruct (own_slice_slice split split with "Hsl_enc")
    as "(Hsl0&Hsl1&Hsl2)"; [word|].
  wp_apply (bytes.wp_Clone with "[$Hsl2]") as "* @".
  iDestruct (own_slice_slice with "[$Hsl0 $Hsl1 $Hsl_b]") as "?"; [word|].

  iApply "HΦ".
  iFrame "∗#%".
  iPureIntro. subst.
  split. { by apply Forall_drop. }
  erewrite join_same_len_drop; [|done|word].
  f_equal. word.
Qed.

Lemma wp_HashChain_Bootstrap c vs d old_vs last_val :
  {{{
    is_pkg_init hashchain ∗
    "Hown_HashChain" ∷ own c vs d ∗
    "->" ∷ ⌜vs = old_vs ++ [last_val]⌝
  }}}
  c @! (go.PointerType hashchain.HashChain) @! "Bootstrap" #()
  {{{
    sl_bootLink bootLink sl_proof proof, RET (#sl_bootLink, #sl_proof);
    "Hown_HashChain" ∷ own c vs d ∗
    "#Hsl_bootLink" ∷ sl_bootLink ↦*□ bootLink ∗
    "Hsl_proof" ∷ sl_proof ↦* proof ∗

    "%His_bootLink" ∷ ⌜valid old_vs None bootLink (S $ length old_vs)⌝ ∗
    "%Hwish" ∷ ⌜wish_Proof proof [last_val]⌝
  }}}.
Proof.
  wp_start. iNamed "Hpre". iNamed "Hown_HashChain". wp_auto.
  iDestruct (own_slice_len with "Hsl_enc") as %?.
  apply join_same_len_length in Hsame_len as Hlen.
  rewrite app_length /= in Hlen.
  iDestruct (own_slice_wf with "Hsl_enc") as %?.
  case_decide; [|word].
  wp_auto.
  remember (word.sub _ _) as split.
  iDestruct (own_slice_slice split split with "Hsl_enc")
    as "(Hsl0&Hsl1&Hsl2)"; [word|].
  wp_apply (bytes.wp_Clone with "[$Hsl2]") as "* @".
  iDestruct (own_slice_slice with "[$Hsl0 $Hsl1 $Hsl_b]") as "?"; [word|].

  iApply "HΦ".
  opose proof (His_chain_pred _ _ _); [done|].
  iFrame "∗#%".
  iPureIntro. subst. split.
  - apply Forall_snoc in Hsame_len as [??].
    by rewrite Forall_singleton.
  - replace (sint.nat (word.sub _ _)) with
      (length old_vs * Z.to_nat cryptoffi.hash_len)%nat by word.
    erewrite <-join_same_len_drop; [|done|len].
    by rewrite drop_app_length.
Qed.

End wps.

#[global] Opaque inv_fn own wish_Proof.
End hashchain.
