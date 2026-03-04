From New.generatedproof.github_com.sanjit_bhat.pav Require Import merkle.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import cryptoffi.

From New.proof.github_com.sanjit_bhat.pav.merkle_proof Require Import base serde.

(* TODO: should prob make this Opaque def. *)
Notation get_bit l n := (bytes_to_bits l !!! n : bool).

Module merkle.
Import base.merkle serde.merkle.
Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : merkle.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

(** tree. *)

(* [Cut]s denote a cut off tree.
for full trees, they come from invalid hashes,
while for partial trees, it's just an unknown-origin hash.
unifying these two types of Cuts allows for unified tree predicates.

a different approach to invalid full trees bubbles invalidness all the way to the top,
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

Tactic Notation "solve_bool" :=
  match goal with
  | H : ?x = negb ?x |- _ => by destruct x
  | H : negb ?x = ?x |- _ => by destruct x
  | |- ?x ≠ negb ?x => by destruct x
  | |- negb ?x ≠ ?x => by destruct x
  end.

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

(** full trees / maps. *)

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

Local Tactic Notation "destruct_exis" := repeat
  match goal with
  | H : ∃ _, _ |- _ => destruct H as (?&H)
  end.

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

(** full <-> cut tree reln. *)

Fixpoint is_fuel' t fuel :=
  match fuel with 0%nat => False | S fuel' =>
  match t with
  | Inner c0 c1 => is_fuel' c0 fuel' ∧ is_fuel' c1 fuel'
  | _ => True
  end end.
Definition is_fuel t := is_fuel' t (S max_depth).
#[local] Hint Unfold is_fuel : merkle.

Definition cut_full_reln' ct ft fuel h :=
  is_cut_tree ct h ∧ tree_inv_fn' h fuel = ft.
Definition cut_full_reln ct ft h := cut_full_reln' ct ft (S max_depth) h.
#[local] Hint Unfold cut_full_reln : merkle.

Local Tactic Notation "rw_hash" := repeat
  match goal with
  | H0 : context[cryptoffi.hash_inv_fn ?h], H1 : cryptoffi.hash_fn _ = Some ?h |- _ =>
    apply cryptoffi.hash_bij_l in H1; rewrite {}H1 in H0
  | H1 : cryptoffi.hash_fn _ = Some ?h |- context[cryptoffi.hash_inv_fn ?h] =>
    apply cryptoffi.hash_bij_l in H1; rewrite {}H1
  end.

Lemma cut_full_reln_Empty ft fuel h :
  cut_full_reln' Empty ft (S fuel) h → ft = Empty.
Proof.
  intros (Hc&Hf). simpl in *.
  rw_hash.
  by rewrite decode_empty_det in Hf.
Qed.

Lemma cut_full_reln_Leaf {label val} ft fuel h :
  cut_full_reln' (Leaf label val) ft (S fuel) h → ft = Leaf label val.
Proof.
  intros (Hc&Hf). simpl in *. destruct_and?.
  rw_hash.
  by rewrite decode_leaf_det in Hf.
Qed.

Lemma cut_full_reln_Inner ft t0 t1 fuel h :
  cut_full_reln' (Inner t0 t1) ft (S fuel) h →
  ∃ t2 t3 h0 h1,
    ft = Inner t2 t3 ∧
    is_cut_tree t0 h0 ∧
    is_cut_tree t1 h1 ∧
    tree_inv_fn' h0 fuel = t2 ∧
    tree_inv_fn' h1 fuel = t3.
Proof.
  intros (Hc&Hf). simpl in *.
  destruct_exis. destruct_and?.
  rw_hash.
  apply is_cut_tree_len in H as ?.
  apply is_cut_tree_len in H1 as ?.
  rewrite decode_inner_det in Hf; [|done..].
  naive_solver.
Qed.

Lemma init_to_reln_Empty fuel :
  is_pkg_init (PROP:=iProp Σ) merkle -∗
  ⌜∃ h, cut_full_reln' Empty Empty (S fuel) h⌝.
Proof.
  iIntros "#Hpkg".
  iDestruct (is_pkg_init_access with "[$]") as "/= #Hinit".
  rewrite /is_initialized. iNamed "Hinit".
  iPureIntro.
  eexists. split; try done. simpl.
  rw_hash.
  by rewrite decode_empty_det.
Qed.

Lemma cut_to_full_Empty fuel h :
  is_cut_tree Empty h →
  tree_inv_fn' h (S fuel) = Empty.
Proof.
  simpl. intros.
  rw_hash.
  by rewrite decode_empty_det.
Qed.

Lemma cut_to_full_Leaf fuel l v h :
  is_cut_tree (Leaf l v) h →
  tree_inv_fn' h (S fuel) = Leaf l v.
Proof.
  simpl. intros. destruct_and?.
  rw_hash.
  by rewrite decode_leaf_det.
Qed.

Lemma full_entry_txfer t0 t1 h label oval :
  is_entry t0 label oval →
  is_cutless_path t0 label →
  is_fuel t0 →
  cut_full_reln t0 t1 h →
  is_entry t1 label oval.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  revert t1 h fuel depth.
  induction t0; simpl; intros * ??? Hreln;
    destruct fuel; try done.
  - apply cut_full_reln_Empty in Hreln as ->. naive_solver.
  - apply cut_full_reln_Leaf in Hreln as ->. naive_solver.
  - apply cut_full_reln_Inner in Hreln as (?&?&?&?&?).
    destruct_and?. subst.
    simpl. case_match.
    + by eapply IHt0_2.
    + by eapply IHt0_1.
Qed.

Lemma cut_to_full t h :
  is_cutless t →
  is_fuel t →
  is_cut_tree t h →
  tree_inv_fn h = t.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  revert h fuel.
  induction t; simpl; intros; destruct_and?;
    destruct fuel; try done; simpl.
  - rw_hash. by rewrite decode_empty_det.
  - rw_hash. by rewrite decode_leaf_det.
  - destruct_exis. destruct_and?.
    rw_hash.
    apply is_cut_tree_len in H1 as ?.
    apply is_cut_tree_len in H as ?.
    rewrite decode_inner_det; [|done..].
    erewrite <-IHt1; [|done..].
    by erewrite <-IHt2; [|done..].
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
  (* Golang put won't run out of fuel. *)
  match fuel with 0%nat => None | S fuel' =>
  match t with
  | Empty => Some (Leaf label val)
  | Leaf label' val' =>
    if decide (label = label') then Some (Leaf label val) else
    (* "unfolding" the two leaf puts lets us use [fuel'] in recur calls. *)
    (* put 1. *)
    let t0_0 := if get_bit label' depth then Empty else t in
    let t0_1 := if get_bit label' depth then t else Empty in
    let t0 := if get_bit label depth then t0_1 else t0_0 in
    (* put 2. *)
    match pure_put' t0 (S depth) label val fuel' with None => None | Some t1 =>
    let t2_0 := if get_bit label depth then t0_0 else t1 in
    let t2_1 := if get_bit label depth then t1 else t0_1 in
    Some $ Inner t2_0 t2_1
    end
  | Inner c0 c1 =>
    let t0 := if get_bit label depth then c1 else c0 in
    match pure_put' t0 (S depth) label val fuel' with None => None | Some t1 =>
    let t2_0 := if get_bit label depth then c0 else t1 in
    let t2_1 := if get_bit label depth then t1 else c1 in
    Some $ Inner t2_0 t2_1
    end
  | Cut _ => None (* Golang put won't hit Cut. *)
  end end.
Definition pure_put t label val := pure_put' t 0 label val (S max_depth).
#[local] Hint Unfold pure_put : merkle.

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

Lemma put_impl_non_cut t depth label val fuel :
  is_Some (pure_put' t depth label val (S fuel)) →
  ∀ h, t ≠ Cut h.
Proof. naive_solver. Qed.

Lemma const_label_len_over_put t t' label val :
  is_const_label_len t →
  pure_put t label val = Some t' →
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
  destruct t; simpl; intros;
    try case_decide; try case_match;
    simplify_eq/=; try done.
  - word.
  - repeat case_match;
      simplify_eq/=; intuition;
      by (eapply IHfuel; [|done..]).
  - repeat case_match; try done; naive_solver.
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
  destruct t; simpl; intros; try done.
  case_match; try done.
  case_match; by eapply IHfuel.
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
  destruct t; simpl; intros;
    repeat case_decide; repeat case_match; simplify_eq/=; try done;
    repeat case_match; try done;
    by eapply IHfuel.
Qed.

Lemma cutless_path_over_put t t' label0 label1 val :
  is_cutless_path t label0 →
  pure_put t label1 val = Some t' →
  is_cutless_path t' label0.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  revert t t' depth.
  induction fuel; [done|].
  intros *.
  destruct t; simpl; intros;
    repeat case_decide; repeat case_match; simplify_eq/=; try done;
    repeat case_match; try done;
    (by eapply IHfuel; [|done]).
Qed.

Lemma cutless_over_put t label val t' :
  is_cutless t →
  pure_put t label val = Some t' →
  is_cutless t'.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  revert t t' depth.
  induction fuel; [done|].
  intros *.
  destruct t; simpl; intros;
    repeat case_decide; repeat case_match; simplify_eq/=; try done;
    intuition; (by eapply IHfuel; [|done]).
Qed.

(* [pure_put] definitionally guarantees [fuel] down the put path.
for [Inner] nodes down the opposite path, it preserves [fuel]. *)
Lemma is_fuel_over_put t t' label val :
  is_fuel t →
  pure_put t label val = Some t' →
  is_fuel t'.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  revert t t' depth.
  induction fuel; [done|].
  intros *.
  destruct t; simpl; intros;
    try case_decide; try case_match;
    simplify_eq/=; try done.
  - repeat case_match; try done;
      simplify_eq/=; intuition;
      repeat case_match; try done;
      (eapply IHfuel; [|done]);
      simpl; by repeat case_match.
  - intuition; repeat case_match; try done; naive_solver.
Qed.

Lemma is_sorted_over_put t t' label val :
  is_sorted t →
  pure_put t label val = Some t' →
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
  destruct t; simpl; intros;
    try case_decide; try case_match;
    simplify_eq/=; try done.
  - replace (S _) with (length $ pref_ext pref label) in * by len.
    assert (prefix_total (pref_ext pref label) (bytes_to_bits label)).
    { by eapply prefix_total_snoc. }
    assert (prefix_total (pref_ext pref label0) (bytes_to_bits label0)).
    { by eapply prefix_total_snoc. }
    repeat case_match; try done;
      simplify_eq/=; intuition;
      by (eapply IHfuel; last done).
  - replace (S _) with (length $ pref_ext pref label) in * by len.
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
  destruct t; simpl; intros;
    try case_decide; try case_match;
    simplify_eq/=; try done;
    repeat case_match; simplify_eq/=; naive_solver.
Qed.

Lemma old_entry_over_put t t' label label' oval' val :
  is_entry t label' oval' →
  pure_put t label val = Some t' →
  label ≠ label' →
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
  destruct t; simpl; intros (?&?&?); intros;
    try case_decide; try case_match;
    simplify_eq/=.
  1-2: naive_solver.
  all: repeat case_match; simplify_eq/=; try congruence; naive_solver.
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
    eapply old_entry_over_put; [|done..].
    by apply entry_eq_lookup.
Qed.

Lemma cut_full_over_put t0 t0' t1 h0 h1 label val :
  cut_full_reln t0 t0' h0 →
  pure_put t0 label val = Some t1 →
  is_cut_tree t1 h1 →
  pure_put t0' label val = Some $ tree_inv_fn h1.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  revert t0 t0' t1 h0 h1 depth.
  induction fuel; [done|].
  destruct t0; intros; simplify_eq/=; destruct_and?.
  - apply cut_full_reln_Empty in H. subst.
    rw_hash. by rewrite decode_leaf_det.
  - apply cut_full_reln_Leaf in H. subst.
    case_decide.
    { simplify_eq/=. destruct_and?.
      rw_hash. by rewrite decode_leaf_det. }
    case_match; try done.
    simplify_eq/=.
    destruct_exis. destruct_and?.
    apply is_cut_tree_len in H0 as ?.
    apply is_cut_tree_len in H1 as ?.
    rw_hash.
    rewrite decode_inner_det; [|done..].
    f_equal.
    repeat case_match.
Admitted.

(* note: [pure_put] doesn't compute hash, so this lemma can't give [cut_full_reln].
instead, it must require it. *)
Lemma cut_full_over_put t0 t0' t1 t1' h0 h1 label val :
  (* to demonstrate Empty hash. *)
  is_pkg_init merkle -∗
  cut_full_reln t0 t0' h0 -∗
  ⌜pure_put t0 label val = Some t1⌝ -∗
  cut_full_reln t1 t1' h1 -∗
  ⌜pure_put t0' label val = Some t1'⌝.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  iIntros "#Hinit".
  iInduction fuel as [? IH] using lt_wf_ind forall (t0 t0' t1 t1' h0 h1 depth).
  iNamedSuffix 1 "0". iIntros "%Hput". iNamedSuffix 1 "1".

  rewrite pure_put_unfold in Hput.
  destruct t0; try done.
  - (* get t0'. *)
    iDestruct (cut_full_reln_Empty t0' with "[$]") as %->.
    rewrite pure_put_unfold.
    simplify_eq/=.
    (* get t1'. *)
    by iDestruct (cut_full_reln_Leaf t1' with "[$]") as %->.

  - (* get t0'. *)
    iDestruct (cut_full_reln_Leaf t0' with "[$]") as %->.
    rewrite pure_put_unfold.
    simplify_eq/=. rewrite Hput.
    (* t1 casework, to get t1'. *)
    case_decide; try case_match; simplify_eq/=.
    { by iDestruct (cut_full_reln_Leaf t1' with "[$]") as %->. }
    iSpecialize ("IH" $! n with "[]"); [word|].
    case_match; try done.
    simplify_eq/=.
    iDestruct (cut_full_reln_Inner with "[$]") as
      "{Hct1 Hft1} (%&%&%&%&%& #Hchild0_ct1 & #Hchild1_ct1 & #Hchild0_ft1 & #Hchild1_ft1)".
    simplify_eq/=.

    (* t1=Inner case. very tricky. *)
    ereplace
      (if get_bit label depth
        then if get_bit label0 depth then ?[a] else ?[b]
        else if get_bit label0 depth then ?b else ?a)
      with
      (if decide (get_bit label depth = get_bit label0 depth) then ?a else ?b) in H0.
    2: { by repeat case_match. }

    (* massage full tree children to look like cut tree children. *)
    iAssert (∃ t0', is_full_tree' (if get_bit label depth then
      if get_bit label0 depth then Empty else Leaf label0 val0 else t0') h2 n)%I as "[% Ht0]".
    { destruct (get_bit label _).
      2: { iFrame "#". }
      destruct (get_bit label0 depth).
      { by iDestruct (cut_to_full_Empty with "[$]") as "$". }
      { by iDestruct (cut_to_full_Leaf with "[$]") as "$". } }

    iAssert (∃ t1', is_full_tree' (if get_bit label depth then t1'
      else if get_bit label0 depth then Leaf label0 val0 else Empty) h3 n)%I as "[% Ht1]".
    { destruct (get_bit label _).
      { iFrame "#". }
      destruct (get_bit label0 depth).
      { by iDestruct (cut_to_full_Leaf with "[$]") as "$". }
      { by iDestruct (cut_to_full_Empty with "[$]") as "$". } }

    iDestruct (is_full_tree_inj with "Hchild0_ft1 Ht0") as %->.
    iDestruct (is_full_tree_inj with "Hchild1_ft1 Ht1") as %->.
    iClear "Ht0 Ht1".

    (* learn that t0 recursive put call gives massaged form. *)
    iDestruct (init_to_reln_Empty with "[$]") as "[% #Hreln_Empty]".
    iDestruct ("IH" $! _
      (if decide (get_bit label depth = get_bit label0 depth) then _ else _)
      _
      (if get_bit label depth then _ else _)
      (if decide (get_bit label depth = get_bit label0 depth) then _ else _)
      (* dep label, recur out is some child. *)
      (if get_bit label depth then h3 else h2)
      with "[][//][]") as "%".
    { case_decide.
      - iFrame "Hct0".
        iDestruct (cut_to_full_Leaf with "[$]") as "$".
      - iFrame "#". }
    { destruct (get_bit label _); iFrame "#". }

    iPureIntro. simplify_eq/=. by repeat case_match.

  - (* get t0'. *)
    case_match; try done.
    iSpecialize ("IH" $! n with "[]"); [word|].

    iDestruct (cut_full_reln_Inner with "[]") as
      "{Hct0 Hft0} (%&%&%&%&%& #Hchild0_ct0 & #Hchild1_ct0 & #Hchild0_ft0 & #Hchild1_ft0)".
    { iFrame "Hct0 #". }
    simpl in *. case_match; try done. simplify_eq/=.

    (* get t1'. *)
    iDestruct (cut_full_reln_Inner with "[]") as
      "{Hct1 Hft1} (%&%&%&%&%& #Hchild0_ct1 & #Hchild1_ct1 & #Hchild0_ft1 & #Hchild1_ft1)".
    { iFrame "Hct1 #". }
    simplify_eq/=.

    (* t0 / t1 (the final full tree children) aren't just the recur put out.
    they correspond to additional branching, as shown in the final cut trees.
    we need to make the branching structure evident. *)
    iAssert (∃ t0', is_full_tree'
      (if get_bit label depth then t2 else t0') h4 n)%I as "[% Ht0]".
    { destruct (get_bit label _).
      2: { iFrame "#". }
      iDestruct (is_cut_tree_det with "Hchild0_ct0 Hchild0_ct1") as %->.
      by iFrame "#". }
    iAssert (∃ t1', is_full_tree'
      (if get_bit label depth then t1' else t3) h5 n)%I as "[% Ht1]".
    { destruct (get_bit label _).
      { iFrame "#". }
      iDestruct (is_cut_tree_det with "Hchild1_ct0 Hchild1_ct1") as %->.
      by iFrame "#". }
    iDestruct (is_full_tree_inj with "Hchild0_ft1 Ht0") as %->.
    iDestruct (is_full_tree_inj with "Hchild1_ft1 Ht1") as %->.
    iClear "Ht0 Ht1".

    iDestruct ("IH" $! _
      (if get_bit label depth then _ else _)
      _
      (if get_bit label depth then _ else _)
      (if get_bit label depth then h3 else h2)
      (if get_bit label depth then h5 else h4)
      with "[][//][]") as "->".
    { case_match; iFrame "#". }
    { case_match; iFrame "#". }

    simplify_eq/=. iPureIntro. by case_match.
Qed.

Lemma cut_cut_hash_over_put t0 t1 h label val t0' t1' h' :
  cut_cut_reln t0 t1 h -∗
  ⌜pure_put t0 label val = Some t0'⌝ -∗
  ⌜pure_put t1 label val = Some t1'⌝ -∗
  is_cut_tree t0' h' -∗
  is_cut_tree t1' h'.
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel. clear Heqfuel.
  remember 0%nat as depth. clear Heqdepth.
  iInduction fuel as [? IH] using lt_wf_ind forall (t0 t1 h t0' t1' h' depth).
  iIntros "#Hreln %Hput0 %Hput1 #Hhash_t0'".
  rewrite pure_put_unfold in Hput0.

  destruct t0; try done.
  - iDestruct (cut_cut_reln_Empty with "Hreln [%]") as %->.
    { by eapply put_impl_non_cut. }
    rewrite pure_put_unfold in Hput1.
    simplify_eq/=.
    iFrame "#".
  - iDestruct (cut_cut_reln_Leaf with "Hreln [%]") as %->.
    { by eapply put_impl_non_cut. }
    rewrite pure_put_unfold in Hput1.
    case_decide.
    { simplify_eq/=. iFrame "#". }
    case_match; try done.
    simpl in *.
    case_match; try done.
    simplify_eq/=.
    iFrame "#".
  - iDestruct (cut_cut_reln_Inner with "Hreln [%]") as "(%&%&%&%&->&#Hreln0&#Hreln1)".
    { by eapply put_impl_non_cut. }
    rewrite pure_put_unfold in Hput1.
    case_match; try done.
    simpl in *.
    destruct (pure_put' _ _ _ _ _) eqn:? in Hput0; try done.
    destruct (pure_put' _ _ _ _ _) eqn:? in Hput1; try done.
    simplify_eq/=.
    iSpecialize ("IH" $! n with "[]"); [word|].
    iNamed "Hhash_t0'".
    case_match.
    + iDestruct ("IH" with "Hreln1 [//][//][$]") as "$".
      iNamed "Hreln0".
      iDestruct (is_cut_tree_det with "Hchild0 Ht0") as %->.
      iFrame "#".
    + iDestruct ("IH" with "Hreln0 [//][//][$]") as "$".
      iNamed "Hreln1".
      iDestruct (is_cut_tree_det with "Hchild1 Ht0") as %->.
      iFrame "#".
Qed.

Tactic Notation "rw_pure_put" := repeat
  match goal with
  | H : pure_put' _ _ _ _ _ = None |- _ => rewrite -{}H
  end.

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
  assert (∃ x, x = max_depth) as [fuel Heq]; [by eexists|].
  rewrite -[in is_fuel' _ _]Heq.
  rewrite -[in pure_put' _ _ _ _ _]Heq.
  remember [] as pref.
  assert (prefix_total pref (bytes_to_bits label)).
  { subst. apply prefix_total_nil. }
  replace 0%nat with (length pref); [|by subst].
  assert (length pref + fuel = max_depth)%nat.
  { subst. simpl. lia. }
  clear Heq Heqpref.
  intros.
  generalize dependent t.
  generalize dependent pref.

  induction fuel as [? IH] using lt_wf_ind.
  intros. rewrite pure_put_unfold.
  destruct t; simpl in *; try done.

  - case_decide; [done|].
    destruct fuel.
    (* fuel=0. show labels actually equal. *)
    { opose proof (prefix_total_full _ (bytes_to_bits label) _ _);
        [|done|]; [by len|].
      opose proof (prefix_total_full _ (bytes_to_bits label0) _ _);
        [|done|]; [by len|].
      simplify_eq/=. }

    ospecialize (IH fuel _); [lia|].
    destruct (pure_put' _ _ _ _ _) eqn:?; [done|]. rw_pure_put.
    replace (S _) with (length $ pref_ext pref label) in * by len.
    eapply IH; repeat case_match; try done; [|len|..];
      by eapply prefix_total_snoc.
  - destruct fuel; [done|].
    ospecialize (IH fuel _); [lia|].
    intuition.
    destruct (pure_put' _ _ _ _ _) eqn:?; [done|]. rw_pure_put.
    replace (S _) with (length $ pref_ext pref label) in * by len.
    eapply IH; repeat case_match; try done; [..|len|len];
      by eapply prefix_total_snoc.
Qed.

(** invariants on [pure_newShell]. *)

Lemma fuel_on_newShell label sibs :
  length sibs ≤ max_depth →
  is_fuel (pure_newShell label sibs).
Proof.
  autounfold with merkle.
  remember (S max_depth) as fuel.
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

#[export] Hint Unfold merkle.find merkle.is_entry merkle.to_map merkle.is_sorted
  merkle.is_full_tree merkle.is_map merkle.is_cutless_path
  merkle.is_fuel merkle.cut_full_reln
  merkle.pure_put merkle.pure_newShell merkle.pure_proofToTree
  : merkle.
