From New.generatedproof.github_com.sanjit_bhat.pav Require Import merkle.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import cryptoffi.

From New.proof.github_com.sanjit_bhat.pav.merkle_proof Require Import base serde.

(* TODO: should prob make this Opaque def. *)
Notation get_bit l n := (bytes_to_bits l !!! n : bool).

#[global] Tactic Notation "solve_bool" :=
  match goal with
  | H : ?x = negb ?x |- _ => by destruct x
  | H : negb ?x = ?x |- _ => by destruct x
  | |- ?x ≠ negb ?x => by destruct x
  | |- negb ?x ≠ ?x => by destruct x
  end.

#[global] Tactic Notation "destruct_exis" := repeat
  match goal with
  | H : ∃ _, _ |- _ => destruct H as (?&H)
  end.

#[global] Tactic Notation "rw_hash" := repeat
  match goal with
  | H0 : context[cryptoffi.hash_inv_fn ?h], H1 : cryptoffi.hash_fn _ = Some ?h |- _ =>
    apply cryptoffi.hash_bij_l in H1; rewrite {}H1 in H0
  | H1 : cryptoffi.hash_fn _ = Some ?h |- context[cryptoffi.hash_inv_fn ?h] =>
    apply cryptoffi.hash_bij_l in H1; rewrite {}H1
  end.

Module merkle.
Import base.merkle serde.merkle.
Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : merkle.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

(** tree. *)

(* [Cut]s denote a cut off tree.
for inv trees, they come from invalid hashes,
while for partial trees, it's just an unknown-origin hash.
unifying these two types of Cuts allows for unified tree predicates.

a different approach to invalid inv trees bubbles invalidness all the way to the top,
i.e., inversion resulting in option map.
that has the undesirable effect of invalidness "stopping the proof". *)
Inductive tree :=
  | Empty
  | Leaf (label val : list w8)
  | Inner (child0 child1 : tree)
  | Cut (hash : list w8).

(** tree paths. *)

Fixpoint find' t depth label :=
  match t with
  | Empty => None
  | Leaf l v => Some (l, v)
  | Inner c0 c1 =>
    let c := if get_bit label depth then c1 else c0 in
    find' c (S depth) label
  | Cut _ => None (* [None] matches [to_map]. *)
  end.
Definition find t label := find' t 0 label.
#[local] Hint Unfold find : merkle.

Definition found_nonmemb label (found : option $ (list w8 * list w8)%type) :=
  match found with
  | None => True
  | Some (found_label, _) => label ≠ found_label
  end.

Definition is_entry t label oval :=
  ∃ f,
  find t label = f ∧
  match oval with
  | Some v => f = Some (label, v)
  | None => found_nonmemb label f
  end.
#[local] Hint Unfold is_entry : merkle.

(** relation bw map interp and paths. *)

Fixpoint to_map' t pref : gmap (list w8) (list w8) :=
  (* using [prefix_total] allows other preds (e.g., [is_entry])
  to operate under an easier (and weaker), length-extended leaf model.
  this reduces proof burden.
  e.g., [find] doesn't need to track depth bounds. *)
  match t with
  | Leaf label val =>
    if decide (prefix_total pref (bytes_to_bits label))
      then {[label := val ]} else ∅
  | Inner child0 child1 =>
    to_map' child0 (pref ++ [false]) ∪
    to_map' child1 (pref ++ [true])
  | _ => ∅
  end.
Definition to_map t := to_map' t [].
#[local] Hint Unfold to_map : merkle.

Lemma to_map_Some t pref label :
  is_Some (to_map' t pref !! label) →
  prefix_total pref (bytes_to_bits label).
Proof.
  revert pref.
  induction t; simpl; intros ? Hsome.
  - by simpl_map.
  - case_decide; [|by simpl_map].
    destruct (decide (label0 = label)).
    + by subst.
    + by simpl_map.
  - apply lookup_union_is_Some in Hsome.
    destruct_or!.
    + apply IHt1 in Hsome.
      by eapply prefix_total_app_l.
    + apply IHt2 in Hsome.
      by eapply prefix_total_app_l.
  - by simpl_map.
Qed.

Lemma to_map_None_strong t pref label :
  ¬ prefix_total pref (bytes_to_bits label) →
  to_map' t pref !! label = None.
Proof.
  revert pref.
  induction t; simpl; intros; try done.
  - case_decide; [|done].
    by destruct (decide (label = label0)); subst; simpl_map.
  - intuition.
    apply lookup_union_None_2.
    + eapply IHt1.
      by intros ?%prefix_total_app_l.
    + eapply IHt2.
      by intros ?%prefix_total_app_l.
Qed.

Lemma to_map_None t pref bit label :
  get_bit label (length pref) = negb bit →
  to_map' t (pref ++ [bit]) !! label = None.
Proof.
  intros.
  eapply to_map_None_strong.
  intros ?%prefix_total_snoc_inv.
  intuition. subst. solve_bool.
Qed.

Notation pref_ext p l := (p ++ [get_bit l (length p)]) (only parsing).

Lemma entry_to_lookup t label oval :
  is_entry t label oval →
  to_map t !! label = oval.
Proof.
  autounfold with merkle.
  remember ([]) as pref.
  replace (0%nat) with (length pref) by (by subst).
  intros (?&?&?).
  assert (prefix_total pref (bytes_to_bits label)).
  { subst. apply prefix_total_nil. }
  clear Heqpref.
  generalize dependent pref.

  induction t; simpl; intros.
  - case_match; by subst.
  - case_match; case_decide; simplify_eq/=; by simpl_map.
  - replace (S _) with (length $ pref_ext pref label) in * by len.
    intuition. rewrite lookup_union.
    case_match.
    + erewrite (to_map_None t1); [|done..].
      erewrite IHt2; cycle 1; [done|..].
      { by apply prefix_total_snoc. }
      by simplify_option_eq.
    + erewrite (to_map_None t2); [|done..].
      erewrite IHt1; cycle 1; [done|..].
      { by apply prefix_total_snoc. }
      by simplify_option_eq.
  - simpl_map. case_match; by subst.
Qed.

Lemma lookup_to_entry t label :
  is_entry t label (to_map t !! label).
Proof.
  autounfold with merkle.
  remember ([]) as pref.
  replace (0%nat) with (length pref) by (by subst).
  assert (prefix_total pref (bytes_to_bits label)).
  { subst. apply prefix_total_nil. }
  clear Heqpref.
  generalize dependent pref.

  induction t; simpl; intros.
  - simpl_map. naive_solver.
  - eexists. intuition.
    case_decide; destruct (decide (label = label0)); subst; by simpl_map.
  - replace (S _) with (length $ pref_ext pref label) in * by len.
    intuition. rewrite lookup_union.
    destruct (get_bit _ _) eqn:?.
    + erewrite (to_map_None t1); [|done].
      rewrite left_id.
      eapply IHt2; try done.
      by apply prefix_total_snoc.
    + erewrite (to_map_None t2); [|done].
      rewrite right_id.
      eapply IHt1; try done.
      by apply prefix_total_snoc.
  - simpl_map. naive_solver.
Qed.

Lemma entry_eq_lookup t label oval :
  is_entry t label oval ↔ to_map t !! label = oval.
Proof.
  split.
  - by apply entry_to_lookup.
  - intros. subst. by apply lookup_to_entry.
Qed.

(** relation bw sorted'ness and paths. *)

(* used in put op termination and find correctness. *)
Fixpoint is_sorted' t pref :=
  match t with
  | Leaf label val => prefix_total pref (bytes_to_bits label)
  | Inner c0 c1 =>
    is_sorted' c0 (pref ++ [false]) ∧
    is_sorted' c1 (pref ++ [true])
  | _ => True
  end.
Definition is_sorted t := is_sorted' t [].
#[local] Hint Unfold is_sorted : merkle.

(* very similar to [to_map_Some]. *)
Lemma is_sorted_find_pref t pref label fl fv :
  find' t (length pref) label = Some (fl, fv) →
  is_sorted' t pref →
  prefix_total pref (bytes_to_bits fl).
Proof.
  revert pref.
  induction t; simpl; intros; simplify_eq/=; try done.
  intuition.
  replace (S _) with (length (pref ++
    [if get_bit label (length pref) then true else false])) in * by len.
  case_match.
  - eapply prefix_total_app_l.
    by eapply IHt2.
  - eapply prefix_total_app_l.
    by eapply IHt1.
Qed.

Lemma find_to_bit_eq t0 t1 pref label fl fv :
  find' (Inner t0 t1) (length pref) label = Some (fl, fv) →
  is_sorted' t0 (pref ++ [false]) →
  is_sorted' t1 (pref ++ [true]) →
  get_bit label (length pref) = get_bit fl (length pref).
Proof.
  simpl. intros Hf **.
  replace (S _) with (length (pref ++ [get_bit label (length pref)])) in Hf by len.
  eapply is_sorted_find_pref in Hf.
  2: { by case_match. }
  eapply prefix_total_snoc_inv in Hf.
  intuition.
Qed.

(** inv trees / maps. *)

(* the overall structure of [is_full_tree] is a bit unconventional.
from the hash [h], it recursively computes (via [decode_node]) the tree [t].
a few consequences:
- it "resolves" the tree to the maximum extent possible.
- it limits invalid nodes only to when they're generated by decoding.
this allows proving [is_full_tree_inj].

[fuel] prevents infinite recursion.
NOTE: many of the below cases are invariant to whether fuel=0 or S l'.
to prevent duplicate proof branches, we use strong induction: [lt_wf_ind]. *)
Fixpoint tree_inv_fn' h fuel : tree :=
  match fuel with 0%nat => Cut h | S fuel' =>
  match decode_node (cryptoffi.hash_inv_fn h) with
  | DecEmpty => Empty
  | DecLeaf l v => Leaf l v
  | DecInner h0 h1 => Inner (tree_inv_fn' h0 fuel') (tree_inv_fn' h1 fuel')
  | DecInvalid => Cut h
  end end.
Definition tree_inv_fn h := tree_inv_fn' h (S max_depth).
#[local] Hint Unfold tree_inv_fn : merkle.

Definition inv_fn h := to_map $ tree_inv_fn h.
#[local] Hint Unfold inv_fn : merkle.

(* TODO: rename to is_tree. *)
(** cut trees. *)

(* [is_cut_tree] has a more traditional structure,
computing the hash [h] from the tree [t]. some consequences:
- it allows for trees that arbitrary cut off paths.
therefore, there are many trees with the same hash.
- it's hash structure more closely follows the code,
which make it easier to establish (and probably to use in lemmas). *)
Fixpoint is_cut_tree (t : tree) (h : list w8) :=
  match t with
  | Empty =>
    cryptoffi.hash_fn [emptyNodeTag] = Some h
  | Leaf label val =>
    length label < 2^64 ∧
    length val < 2^64 ∧
    cryptoffi.hash_fn ([leafNodeTag] ++
      (u64_le $ W64 $ length label) ++ label ++
      (u64_le $ W64 $ length val) ++ val) = Some h
  | Inner child0 child1 =>
    ∃ h0 h1,
    is_cut_tree child0 h0 ∧
    is_cut_tree child1 h1 ∧
    cryptoffi.hash_fn ([innerNodeTag] ++ h0 ++ h1) = Some h
  | Cut ch =>
    h = ch ∧
    Z.of_nat $ length h = cryptoffi.hash_len
  end.

Fixpoint is_cutless t :=
  match t with
  | Cut _ => False
  | Inner child0 child1 => is_cutless child0 ∧ is_cutless child1
  | _ => True
  end.

Fixpoint is_cutless_path' t depth label :=
  match t with
  | Cut _ => False
  | Inner c0 c1 =>
    let c := if get_bit label depth then c1 else c0 in
    is_cutless_path' c (S depth) label
  | _ => True
  end.
Definition is_cutless_path t label := is_cutless_path' t 0 label.
#[local] Hint Unfold is_cutless_path : merkle.

Lemma is_cutless_to_path t label :
  is_cutless t →
  is_cutless_path t label.
Proof.
  autounfold with merkle.
  remember 0%nat as depth. clear Heqdepth.
  revert depth.
  induction t; intros; simplify_eq/=; try done.
  case_match; naive_solver.
Qed.

Lemma is_cut_tree_len t h:
  is_cut_tree t h →
  Z.of_nat $ length h = cryptoffi.hash_len.
Proof.
  destruct t; simpl; intros;
    destruct_and?; try done.
  1-2: by eapply cryptoffi.is_hash_len.
  destruct_exis.
  eapply cryptoffi.is_hash_len.
  naive_solver.
Qed.

Lemma is_cut_tree_det t h0 h1 :
  is_cut_tree t h0 →
  is_cut_tree t h1 →
  h0 = h1.
Proof.
  revert h0 h1.
  induction t; simpl; intros; destruct_and?; simplify_eq/=; try done.
  destruct H as (h00&h01&?).
  destruct H0 as (h10&h11&?).
  destruct_and!.
  ospecialize (IHt1 h00 h10 _ _); [done..|].
  ospecialize (IHt2 h01 h11 _ _); [done..|].
  by simplify_eq/=.
Qed.

Definition cut_cut_reln t0 t1 h :=
  is_cut_tree t0 h ∧ is_cut_tree t1 h.

Lemma cut_cut_reln_Cut h h0 h1 :
  cut_cut_reln (Cut h0) (Cut h1) h →
  h = h0 ∧ h = h1.
Proof. intros (?&?); simpl in *; destruct_and?; by subst. Qed.

Lemma cut_cut_reln_Empty t h :
  cut_cut_reln Empty t h →
  (∀ h, t ≠ Cut h) →
  t = Empty.
Proof.
  destruct t; intros (Ht0&Ht1) **; simpl in *; destruct_and?; try naive_solver.
  - apply cryptoffi.hash_bij_l in Ht0.
    apply cryptoffi.hash_bij_l in H3.
    by simplify_eq/=.
  - destruct_exis. destruct_and?.
    apply cryptoffi.hash_bij_l in Ht0.
    apply cryptoffi.hash_bij_l in H3.
    by simplify_eq/=.
Qed.

Lemma cut_cut_reln_Leaf l v t h :
  cut_cut_reln (Leaf l v) t h →
  (∀ h, t ≠ Cut h) →
  t = Leaf l v.
Proof.
  destruct t; intros (Ht0&Ht1) **; simpl in *; destruct_and?; try naive_solver.
  - apply cryptoffi.hash_bij_l in H3.
    apply cryptoffi.hash_bij_l in Ht1.
    by simplify_eq/=.
  - apply cryptoffi.hash_bij_l in H6.
    apply cryptoffi.hash_bij_l in H3.
    list_simplifier.
    rename H4 into Henc.
    apply app_inj_1 in Henc as [Hlen_label Henc]; [|len].
    apply (inj u64_le) in Hlen_label.
    apply app_inj_1 in Henc as [<- Henc]; [|word].
    by apply app_inj_1 in Henc as [_ <-]; [|len].
  - destruct_exis. destruct_and?.
    apply cryptoffi.hash_bij_l in H3.
    apply cryptoffi.hash_bij_l in H6.
    by simplify_eq/=.
Qed.

Lemma cut_cut_reln_Inner c0 c1 t h :
  cut_cut_reln (Inner c0 c1) t h →
  (∀ h, t ≠ Cut h) →
  ∃ c0' c1' h0 h1,
    t = Inner c0' c1' ∧
    cut_cut_reln c0 c0' h0 ∧
    cut_cut_reln c1 c1' h1.
Proof.
  destruct t; intros (Ht0&Ht1) **; simpl in *; destruct_and?; try naive_solver.
  - destruct_exis. destruct_and?.
    apply cryptoffi.hash_bij_l in H3.
    apply cryptoffi.hash_bij_l in Ht1.
    by simplify_eq/=.
  - destruct_exis. destruct_and?.
    apply cryptoffi.hash_bij_l in H6.
    apply cryptoffi.hash_bij_l in H3.
    by simplify_eq/=.
  - destruct_exis. destruct_and?.
    apply cryptoffi.hash_bij_l in H6.
    apply cryptoffi.hash_bij_l in H3.
    list_simplifier.
    apply is_cut_tree_len in H1 as ?.
    apply is_cut_tree_len in H5 as ?.
    apply is_cut_tree_len in H0 as ?.
    apply is_cut_tree_len in H2 as ?.
    rename H4 into Henc.
    apply app_inj_1 in Henc as [<- <-]; [|word].
    by repeat eexists.
Qed.

#[local] Tactic Notation "tree_reln" := repeat
  match goal with
  | H : cut_cut_reln Empty _ _ |- _ =>
    eapply cut_cut_reln_Empty in H as ->; [|done]; clear H
  | H : cut_cut_reln (Leaf _ _) _ _ |- _ =>
    eapply cut_cut_reln_Leaf in H as ->; [|done]; clear H
  | H : cut_cut_reln (Inner _ _) _ _ |- _ =>
    let Hchild0 := fresh "Hchild" in
    let Hchild1 := fresh "Hchild" in
    eapply cut_cut_reln_Inner in H as (?&?&?&?&->&Hchild0&Hchild1);
      [|done]; clear H
  end.

(** inv <-> cut tree reln. *)

Fixpoint is_fuel' t fuel {struct fuel} :=
  match fuel with 0%nat => False | S fuel' =>
  match t with
  | Inner c0 c1 => is_fuel' c0 fuel' ∧ is_fuel' c1 fuel'
  | _ => True
  end end.
Definition is_fuel t := is_fuel' t (S max_depth).
#[local] Hint Unfold is_fuel : merkle.

Lemma cut_inv_Empty fuel h :
  is_cut_tree Empty h →
  tree_inv_fn' h (S fuel) = Empty.
Proof.
  simpl. intros.
  rw_hash.
  by rewrite decode_empty_det.
Qed.

Lemma cut_inv_Leaf {label val} fuel h :
  is_cut_tree (Leaf label val) h →
  tree_inv_fn' h (S fuel) = Leaf label val.
Proof.
  simpl. intros. destruct_and?.
  rw_hash.
  by rewrite decode_leaf_det.
Qed.

Lemma cut_inv_Inner t0 t1 fuel h :
  is_cut_tree (Inner t0 t1) h →
  ∃ h0 h1,
    tree_inv_fn' h (S fuel) = Inner (tree_inv_fn' h0 fuel) (tree_inv_fn' h1 fuel) ∧
    is_cut_tree t0 h0 ∧
    is_cut_tree t1 h1.
Proof.
  simpl. intros.
  destruct_exis. destruct_and?.
  rw_hash.
  apply is_cut_tree_len in H0 as ?.
  apply is_cut_tree_len in H as ?.
  rewrite decode_inner_det; [|done..].
  naive_solver.
Qed.

#[local] Tactic Notation "tree_inv" := repeat
  match goal with
  | H0 : is_cut_tree Empty ?h, H1 : context[tree_inv_fn' ?h (S _)] |- _ =>
    eapply cut_inv_Empty in H0 as Ht; erewrite Ht in H1; clear Ht
  | H0 : is_cut_tree Empty ?h |- context[tree_inv_fn' ?h (S _)] =>
    eapply cut_inv_Empty in H0 as Ht; erewrite Ht; clear Ht
  | H0 : is_cut_tree (Leaf _ _) ?h, H1 : context[tree_inv_fn' ?h (S _)] |- _ =>
    eapply cut_inv_Leaf in H0 as Ht; erewrite Ht in H1; clear Ht
  | H0 : is_cut_tree (Leaf _ _) ?h |- context[tree_inv_fn' ?h (S _)] =>
    eapply cut_inv_Leaf in H0 as Ht; erewrite Ht; clear Ht
  | H0 : is_cut_tree (Inner _ _) ?h, H1 : context[tree_inv_fn' ?h (S _)] |- _ =>
    let Hchild0 := fresh "Hchild" in
    let Hchild1 := fresh "Hchild" in
    eapply cut_inv_Inner in H0 as (?&?&Ht&Hchild0&Hchild1);
      erewrite Ht in H1; clear Ht
  | H0 : is_cut_tree (Inner _ _) ?h |- context[tree_inv_fn' ?h (S _)] =>
    let Hchild0 := fresh "Hchild" in
    let Hchild1 := fresh "Hchild" in
    eapply cut_inv_Inner in H0 as (?&?&Ht&Hchild0&Hchild1);
      erewrite Ht; clear Ht
  end.

#[local] Tactic Notation "tree_det" := repeat
  match goal with
  | H0 : is_cut_tree ?t _, H1 : is_cut_tree ?t _ |- _ =>
      tryif constr_eq H0 H1 then fail 1 else
      pose proof (is_cut_tree_det _ _ _ H0 H1) as ->; clear H1
  end.

#[global] Opaque is_cut_tree tree_inv_fn'.

Lemma full_entry_txfer t0 h label oval :
  is_entry t0 label oval →
  is_cutless_path t0 label →
  is_fuel t0 →
  is_cut_tree t0 h →
  is_entry (tree_inv_fn h) label oval.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  revert h fuel depth.
  induction t0; simpl; intros * ??? Hc;
    destruct fuel; try done; simpl in *.
  - tree_inv. naive_solver.
  - tree_inv. naive_solver.
  - tree_inv.
    destruct_and?.
    simpl. case_match.
    + by eapply IHt0_2.
    + by eapply IHt0_1.
Qed.

Lemma cut_inv t h :
  is_cutless t →
  is_fuel t →
  is_cut_tree t h →
  tree_inv_fn h = t.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  revert h fuel.
  induction t; simpl; intros * ?? Hc;
    destruct fuel; try done; simpl in *.
  - by tree_inv.
  - by tree_inv.
  - tree_inv.
    destruct_and?.
    erewrite <-IHt1; [|done..].
    erewrite <-IHt2; [|done..].
    by subst.
Qed.

(** const label len -- needed for put op termination. *)

Fixpoint is_const_label_len t :=
  match t with
  | Leaf label val => Z.of_nat (length label) = cryptoffi.hash_len
  | Inner c0 c1 => is_const_label_len c0 ∧ is_const_label_len c1
  | _ => True
  end.

Lemma find_on_const_label_len t label l v :
  find t label = Some (l, v) →
  is_const_label_len t →
  Z.of_nat (length l) = cryptoffi.hash_len.
Proof.
  autounfold with merkle.
  remember 0%nat as depth. clear Heqdepth.
  revert t depth.
  induction t; intros; simplify_eq/=; try done.
  case_match; naive_solver.
Qed.

(** gallina tree ops.

need gallina transl of Golang [merkle.put] for determ spec.
determ needed bc user might call [VerifyMemb] multiple times on same tree,
expecting dig to be equal across calls.
to guarantee that, [merkle.proofToTree] needs to determ make tree from
inputted proof, and [merkle.put] needs to determ update tree with label, val. *)

(* NOTE: the code has tricky termination reasoning due to put-into-leaf
expanding common label bits into inner nodes.
this reasoning is reflected into gallina using [fuel].
NOTE: separating [depth] from [fuel] allows us to separate
label-index reasoning from termination reasoning.
otherwise, we'd have to track that, e.g., fuel <= max_depth. *)
Fixpoint pure_put' t depth label val (fuel : nat) :=
  let b := get_bit label depth in
  let new := Leaf label val in
  (* Golang put won't run out of fuel. *)
  match fuel with 0%nat => None | S fuel' =>
  match t with
  | Empty => Some new
  | Leaf label' val' =>
    if decide (label = label') then Some new else
    let b' := get_bit label' depth in
    (* for rocq fixpoint checker,
    structure so we only make recursive calls with fuel'. *)
    (* put 1. into Inner Empty Empty. *)
    let t0_0 := if b' then Empty else t in
    let t0_1 := if b' then t else Empty in
    let t0 := if b then t0_1 else t0_0 in
    (* put 2. into Inner with one Leaf. *)
    t1 ← pure_put' t0 (S depth) label val fuel';
    let t2_0 := if b then t0_0 else t1 in
    let t2_1 := if b then t1 else t0_1 in
    Some $ Inner t2_0 t2_1
  | Inner c0 c1 =>
    let t0 := if b then c1 else c0 in
    t1 ← pure_put' t0 (S depth) label val fuel';
    let t2_0 := if b then c0 else t1 in
    let t2_1 := if b then t1 else c1 in
    Some $ Inner t2_0 t2_1
  | Cut _ => None (* Golang put won't hit Cut. *)
  end end.
Definition pure_put t label val := pure_put' t 0 label val (S max_depth).
#[local] Hint Unfold pure_put : merkle.

#[local] Tactic Notation "destruct_put" :=
  repeat (progress (try case_decide; simplify_option_eq; try case_match)).

(* [sibs] order reversed from code for easier fixpoint. *)
Fixpoint pure_newShell' depth label (sibs : list $ list w8) :=
  match sibs with
  | [] => Empty
  | h :: sibs' =>
    let cut := Cut h in
    let t := pure_newShell' (S depth) label sibs' in
    let c0 := if get_bit label depth then cut else t in
    let c1 := if get_bit label depth then t else cut in
    Inner c0 c1
  end.
Definition pure_newShell label sibs := pure_newShell' 0 label sibs.
#[local] Hint Unfold pure_newShell : merkle.

Definition pure_proofToTree label sibs oleaf :=
  let t := pure_newShell label sibs in
  match oleaf with
  | None => Some t
  | Some (l, v) => pure_put t l v
  end.
#[local] Hint Unfold pure_proofToTree : merkle.

(** invariants on [pure_put]. *)

Lemma put_impl_non_cut {depth label val fuel} t :
  is_Some (pure_put' t depth label val fuel) →
  ∀ h, t ≠ Cut h.
Proof. intros []. destruct fuel; try done. naive_solver. Qed.

Lemma const_label_len_over_put t t' label val :
  pure_put t label val = Some t' →
  is_const_label_len t →
  length label = Z.to_nat (cryptoffi.hash_len) →
  is_const_label_len t'.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  intros.
  generalize dependent t.
  revert t' depth.
  induction fuel; [done|].
  intros *.
  destruct t; simpl; intros; try done;
    destruct_put; intuition; [word|..]; by eapply IHfuel.
Qed.

Lemma put_impl_cutless_pre t label val :
  is_Some (pure_put t label val) →
  is_cutless_path t label.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  revert t depth.
  induction fuel; [naive_solver|].
  intros *.
  destruct t; simpl; intros []; try done.
  simplify_option_eq.
  case_match; eapply IHfuel; naive_solver.
Qed.

Lemma cutless_new_put t t' label val :
  pure_put t label val = Some t' →
  is_cutless_path t' label.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  revert t t' depth.
  induction fuel; [done|].
  intros *.
  destruct t; simpl; intros; try done;
    destruct_put; try done; by eapply IHfuel.
Qed.

Lemma cutless_path_over_put t t' label0 label1 val :
  pure_put t label1 val = Some t' →
  is_cutless_path t label0 →
  is_cutless_path t' label0.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  revert t t' depth.
  induction fuel; [done|].
  intros *.
  destruct t; simpl; intros; try done;
    destruct_put; try done; by eapply IHfuel.
Qed.

Lemma cutless_over_put t label val t' :
  pure_put t label val = Some t' →
  is_cutless t →
  is_cutless t'.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  revert t t' depth.
  induction fuel; [done|].
  intros *.
  destruct t; simpl; intros; try done;
    destruct_put; intuition; by eapply IHfuel.
Qed.

(* [pure_put] definitionally guarantees [fuel] down the put path.
for [Inner] nodes down the opposite path, it preserves [fuel]. *)
Lemma is_fuel_over_put t t' label val :
  pure_put t label val = Some t' →
  is_fuel t →
  is_fuel t'.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  revert t t' depth.
  induction fuel; [done|].
  intros *.
  destruct t; simpl; intros; try done.
  - by simplify_eq/=.
  - case_decide. { by simplify_eq/=. }
    simplify_option_eq.
    destruct fuel; [done|].
    repeat case_match; intuition; by eapply IHfuel.
  - simplify_option_eq.
    intuition; repeat case_match; try done; naive_solver.
Qed.

Lemma is_sorted_over_put t t' label val :
  pure_put t label val = Some t' →
  is_sorted t →
  is_sorted t'.
Proof.
  autounfold with merkle.
  remember ([]) as pref.
  replace (0%nat) with (length pref) by (by subst).
  assert (prefix_total pref (bytes_to_bits label)).
  { subst. apply prefix_total_nil. }
  clear Heqpref.
  remember (S max_depth) as fuel. clear Heqfuel.
  generalize dependent pref.
  revert t t'.

  induction fuel; [done|].
  intros *.
  destruct t; simpl; intros; try done.
  - by simplify_eq/=.
  - case_decide. { by simplify_eq/=. }
    simplify_option_eq.
    replace (S _) with (length $ pref_ext pref label) in * by len.
    assert (prefix_total (pref_ext pref label) (bytes_to_bits label)).
    { by eapply prefix_total_snoc. }
    assert (prefix_total (pref_ext pref label0) (bytes_to_bits label0)).
    { by eapply prefix_total_snoc. }
    repeat case_match; try done;
      simplify_eq/=; intuition;
      by eapply IHfuel.
  - simplify_option_eq.
    replace (S _) with (length $ pref_ext pref label) in * by len.
    assert (prefix_total (pref_ext pref label) (bytes_to_bits label)).
    { by eapply prefix_total_snoc. }
    repeat case_match; try done;
      simplify_eq/=; intuition;
      by eapply IHfuel.
Qed.

Lemma put_new_entry t t' label val :
  pure_put t label val = Some t' →
  is_entry t' label (Some val).
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  intros.
  eexists. intuition.
  generalize dependent depth.
  revert t t'.
  induction fuel; [done|].
  intros *.
  destruct t; simpl; intros; try done;
    destruct_put; naive_solver.
Qed.

Lemma old_entry_over_put t t' label label' oval' val :
  pure_put t label val = Some t' →
  label ≠ label' →
  is_entry t label' oval' →
  is_entry t' label' oval'.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  intros.
  generalize dependent depth.
  revert t t'.
  induction fuel; [done|].
  intros *.
  destruct t; simpl; intros ? (?&?&?); try done;
    destruct_put; try naive_solver.
Qed.

(* easier [map_eq] extensional proof vs. using fin_map reductions. *)
Lemma to_map_over_put t t' label val :
  pure_put t label val = Some t' →
  to_map t' = <[label:=val]>(to_map t).
Proof.
  intros. apply map_eq. intros.
  destruct (decide (label = i)); subst; simpl_map.
  - apply entry_eq_lookup.
    by eapply put_new_entry.
  - rewrite -entry_eq_lookup.
    eapply old_entry_over_put; [done..|].
    by apply entry_eq_lookup.
Qed.

Lemma rw_bit0 (b0 b1 : bool) {A} (x0 x1 : A) :
  (if b0
    then
      if b1 then x0 else x1
    else
      if b1 then x1 else x0)
  =
  if decide (b0 = b1) then x0 else x1.
Proof. by repeat case_match. Qed.

Lemma cut_inv_put t0 t1 h0 h1 label val :
  (* for "generating" Empty hashes.
  this applies when parent spawns new Empty node that it doesn't itself have. *)
  (∃ h, is_cut_tree Empty h) →
  pure_put t0 label val = Some t1 →
  is_cut_tree t0 h0 →
  is_cut_tree t1 h1 →
  pure_put (tree_inv_fn h0) label val = Some $ tree_inv_fn h1.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  intros (?&Hempty).
  revert h0 h1 t0 t1 depth.
  induction fuel; [done|].
  destruct t0; intros * ? Hc0 Hc1; simplify_eq/=.
  - by tree_inv.
  - tree_inv.
    case_decide.
    { simplify_eq/=. by tree_inv. }
    simplify_option_eq.
    rename Heqo into Hput.
    tree_inv.
    eremember (get_bit label _) as b. clear Heqb.
    eremember (get_bit label0 _) as b'. clear Heqb'.
    rewrite rw_bit0 in Hput.
    f_equal.
    ospecialize (IHfuel
      (* control flow that determines put input hash. *)
      (if decide (b = b') then _ else _)
      (* control flow that determines put output hash. *)
      (if b then _ else _)).
    eapply IHfuel in Hput as Hput_inv; cycle 1.
    { by case_decide. }
    { by destruct b. }
    clear IHfuel.
    destruct fuel; [done|].
    destruct b, b'; case_decide; try done;
      tree_inv; congruence.
  - tree_inv.
    simplify_option_eq. rename Heqo into Hput.
    tree_inv.
    eremember (get_bit label _) as b. clear Heqb.
    ospecialize (IHfuel
      (if b then _ else _)
      (if b then _ else _)).
    eapply IHfuel in Hput as Hput_inv; cycle 1.
    { by destruct b. }
    { by destruct b. }
    clear IHfuel.
    replace (tree_inv_fn' (if b then x1 else x0) fuel) with
      (if b then tree_inv_fn' x1 fuel else tree_inv_fn' x0 fuel) in Hput_inv.
    2: { by case_match. }
    rewrite Hput_inv /=.
    f_equal.
    case_match; by tree_det.
Qed.

Lemma cut_cut_hash_over_put t0 t1 h label val t0' t1' h' :
  pure_put t0 label val = Some t0' →
  pure_put t1 label val = Some t1' →
  cut_cut_reln t0 t1 h →
  is_cut_tree t0' h' →
  is_cut_tree t1' h'.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  revert t0 t1 h t0' t1' h' depth.
  induction fuel; [done|].
  intros * Hput0 Hput1 **.
  opose proof (put_impl_non_cut t0 _) as ?; [done|].
  opose proof (put_impl_non_cut t1 _) as ?; [done|].
  destruct t0; intros; try done.
  - tree_reln. by simplify_eq/=.
  - tree_reln. by simplify_eq/=.
  - tree_reln.
    simplify_option_eq.
    with_strategy transparent [is_cut_tree] simpl in *.
    destruct_exis. destruct_and?.
    pose proof Hchild as [].
    pose proof Hchild0 as [].
    case_match; tree_det.
    + eapply IHfuel in Hchild0 as ?; cycle 1; [done..|].
      naive_solver.
    + eapply IHfuel in Hchild as ?; cycle 1; [done..|].
      naive_solver.
Qed.

(* TODO: upstream smth like this. *)
Lemma bind_is_Some {A B} (f : A → option B) (mx : option A) :
  is_Some (mx ≫= f) ↔ is_Some mx ∧ (∀ x, mx = Some x → is_Some (f x)).
Proof. destruct mx; naive_solver. Qed.

Lemma put_Some t label val :
  (* for max depth. *)
  is_fuel t →
  Z.of_nat (length label) = cryptoffi.hash_len →
  is_const_label_len t →
  is_sorted t →
  (* for no Cut. *)
  is_cutless_path t label →
  is_Some (pure_put t label val).
Proof.
  autounfold with merkle.
  assert (∃ x, x = S max_depth) as [fuel Heq]; [by eexists|].
  rewrite -[in is_fuel' _ _]Heq.
  rewrite -[in pure_put' _ _ _ _ _]Heq.
  remember [] as pref.
  assert (prefix_total pref (bytes_to_bits label)).
  { subst. apply prefix_total_nil. }
  replace 0%nat with (length pref); [|by subst].
  assert (length pref + fuel = S max_depth)%nat.
  { subst. simpl. lia. }
  clear Heq Heqpref.
  intros.
  generalize dependent t.
  generalize dependent pref.

  induction fuel; [done|].
  intros.
  destruct t; simpl in *; try done.

  - case_decide; [done|].
    destruct fuel.
    (* fuel=0. show labels actually equal. *)
    { opose proof (prefix_total_full _ (bytes_to_bits label) _ _);
        [|done|]; [by len|].
      opose proof (prefix_total_full _ (bytes_to_bits label0) _ _);
        [|done|]; [by len|].
      simplify_eq/=. }

    apply bind_is_Some.
    split; try done.
    replace (S _) with (length $ pref_ext pref label) in * by len.
    eapply IHfuel; repeat case_match; try done; [|len|..];
      by eapply prefix_total_snoc.
  - destruct_and?.
    destruct fuel; [done|].
    apply bind_is_Some.
    split; try done.
    replace (S _) with (length $ pref_ext pref label) in * by len.
    eapply IHfuel; repeat case_match; try done; [..|len|len];
      by eapply prefix_total_snoc.
Qed.

(** invariants on [pure_newShell]. *)

Lemma fuel_on_newShell label sibs :
  length sibs ≤ max_depth →
  is_fuel (pure_newShell label sibs).
Proof.
  autounfold with merkle.
  remember (max_depth) as fuel.
  remember 0%nat as depth.
  assert (depth + fuel ≤ max_depth) by lia.
  clear Heqfuel Heqdepth.
  generalize dependent depth.
  revert fuel.
  induction sibs; try done.
  simpl. intros.
  destruct fuel; try done.
  opose proof (IHsibs fuel (S depth) _ _); [lia..|].
  by case_match.
Qed.

Lemma const_label_on_newShell label sibs :
  is_const_label_len (pure_newShell label sibs).
Proof.
  autounfold with merkle.
  remember 0%nat as depth. clear Heqdepth.
  revert depth.
  induction sibs; try done.
  simpl. intros.
  by case_match.
Qed.

Lemma sorted_on_newShell label sibs :
  is_sorted (pure_newShell label sibs).
Proof.
  autounfold with merkle.
  remember [] as pref.
  replace 0%nat with (length pref) by (by subst).
  clear Heqpref.
  revert pref.
  induction sibs; try done.
  simpl. intros.
  opose proof (IHsibs (pref ++ [if get_bit label (length pref) then true else false])).
  replace (length (_ ++ _)) with (S (length pref)) in * by len.
  by case_match.
Qed.

Lemma cutless_on_newShell label sibs :
  is_cutless_path (pure_newShell label sibs) label.
Proof.
  autounfold with merkle.
  remember 0%nat as depth. clear Heqdepth.
  revert depth.
  induction sibs; try done.
  simpl. intros.
  by case_match.
Qed.

Lemma newShell_None label sibs :
  is_entry (pure_newShell label sibs) label None.
Proof.
  exists None. split; [|done].
  autounfold with merkle.
  remember 0%nat as depth. clear Heqdepth.
  revert depth.
  induction sibs; try done.
  simpl. intros.
  by case_match.
Qed.

End proof.
End merkle.

#[global] Tactic Notation "tree_det" := repeat
  match goal with
  | H0 : merkle.is_cut_tree ?t _, H1 : merkle.is_cut_tree ?t _ |- _ =>
      tryif constr_eq H0 H1 then fail 1 else
      pose proof (merkle.is_cut_tree_det _ _ _ H0 H1) as ->; clear H1
  end.

#[export] Hint Unfold merkle.find merkle.is_entry merkle.to_map merkle.is_sorted
  merkle.tree_inv_fn merkle.inv_fn merkle.is_cutless_path merkle.is_fuel
  merkle.pure_put merkle.pure_newShell merkle.pure_proofToTree
  : merkle.
