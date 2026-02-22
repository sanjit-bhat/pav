From New.generatedproof.github_com.sanjit_bhat.pav Require Import merkle.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof Require Import bytes.
From New.proof.github_com.goose_lang Require Import primitive std.
From New.proof.github_com.sanjit_bhat.pav Require Import cryptoffi cryptoutil safemarshal.
From New.proof.github_com.tchajed Require Import marshal.

Notation emptyNodeTag := (W8 0) (only parsing).
Notation leafNodeTag := (W8 1) (only parsing).
Notation innerNodeTag := (W8 2) (only parsing).

Notation cutNodeTy := (W8 0) (only parsing).
Notation leafNodeTy := (W8 1) (only parsing).
Notation innerNodeTy := (W8 2) (only parsing).

(* number of bits in hash.
nat bc in merkle theory, depth used as nat for easy induction. *)
Definition max_depth := (Z.to_nat cryptoffi.hash_len * 8)%nat.
Lemma max_depth_unfold : max_depth = (Z.to_nat cryptoffi.hash_len * 8)%nat.
Proof. done. Qed.
#[global] Hint Rewrite max_depth_unfold : word.
#[global] Opaque max_depth.

(* used to [autounfold] top-level recursive defs. *)
Create HintDb merkle.

Module merkle.
Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : merkle.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition is_initialized : iProp Σ :=
  ∃ sl_emptyHash emptyHash,
  "#HemptyHash" ∷ (global_addr merkle.emptyHash) ↦□ sl_emptyHash ∗
  "#Hsl_emptyHash" ∷ sl_emptyHash ↦*□ emptyHash ∗
  "#His_emptyHash" ∷ cryptoffi.is_hash (Some [emptyNodeTag]) emptyHash.

#[global] Instance : IsPkgInit (iProp Σ) merkle := define_is_pkg_init is_initialized.
#[global] Instance : GetIsPkgInitWf (iProp Σ) merkle := build_get_is_pkg_init_wf.

Lemma wp_initialize' get_is_pkg_init :
  get_is_pkg_init_prop merkle get_is_pkg_init →
  {{{ own_initializing get_is_pkg_init }}}
    merkle.initialize' #()
  {{{ RET #(); own_initializing get_is_pkg_init ∗ is_pkg_init merkle }}}.
Proof. Admitted.

End proof.
End merkle.
