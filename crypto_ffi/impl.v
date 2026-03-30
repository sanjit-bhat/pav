(** FFI module for cryptographic primitives. *)
From stdpp Require Import gmap vector fin_maps.
From RecordUpdate Require Import RecordSet.

From Perennial.Helpers Require Import CountableTactics Transitions Integers ByteString.
From Perennial.goose_lang Require Import lang.

Set Default Proof Using "Type".
Set Printing Projections.

(** * The Crypto extension to GooseLang: primitive operations [Trusted definitions!] *)

Inductive CryptoOp : Set :=
| Hash
.
#[global]
Instance eq_CryptoOp : EqDecision CryptoOp.
Proof. solve_decision. Defined.
#[global]
Instance CryptoOp_fin : Countable CryptoOp.
Proof. solve_countable CryptoOp_rec 1%nat. Qed.

Definition crypto_op : ffi_syntax.
Proof.
  refine (mkExtOp CryptoOp _ _ unit _ _).
Defined.

Record crypto_global_state : Type := {
  crypto_hash_prev_data : list (list w8);
  crypto_hash_proph_id : proph_id;
}.

Global Instance crypto_global_state_inhabited : Inhabited crypto_global_state :=
  populate {| crypto_hash_prev_data := []; crypto_hash_proph_id := inhabitant |}.

Record crypto_node_state : Type := {
}.

Global Instance crypto_node_state_inhabited : Inhabited crypto_node_state :=
  populate (Build_crypto_node_state).

Definition crypto_model : ffi_model.
Proof.
  refine (mkFfiModel crypto_node_state crypto_global_state _ _).
Defined.

Section crypto.
  (* these are local instances on purpose, so that importing this file doesn't
  suddenly cause all FFI parameters to be inferred as the crypto model *)
  Existing Instances crypto_op crypto_model.

  Existing Instances r_mbind r_fmap.
  Context {go_gctx : GoGlobalContext}.

  Context (hash_fn : list w8 → list w8).

  Definition is_crypto_ffi_step (op : CryptoOp) (v : val) (e' : expr)
    (σ σ' : ffi_state) (g g' : ffi_global_state) : Prop :=
    match op with
    | Hash =>
        ∃ data,
        v = #data ∧
        σ = σ' ∧
        if decide (data ∈ g.(crypto_hash_prev_data)) then
          e' = #() ∧ g' = g
        else (* data ∉ crypto_hash_prev_data *)
          if decide ((hash_fn data) ∈ (hash_fn <$> g.(crypto_hash_prev_data))) then
            g' = g ∧ e' = (GoInstruction AngelicExit #())
          else
            g' = set crypto_hash_prev_data (.++ [data]) g ∧
            e' = (ResolveProph #g.(crypto_hash_proph_id) "data";;
                  #(hash_fn data))%E

    end.

  Definition ffi_step (op : CryptoOp) (v : val) : transition (state*global_state) expr :=
    '(e', s', w') ← suchThat
      (λ '(σ, g) '(e', σ', w'),
         let _ := σ.(go_state).(go_lctx) in
         let w := g.(global_world) in
         (σ' = σ.(world) ∧ w' = g.(global_world) ∧ e' = ExternalOp op v) ∨
         is_crypto_ffi_step op v e' σ.(world) σ' g.(global_world) w')
      (gen:=fallback_genPred _);
    modify (λ '(σ, g), (set world (const s') σ, set global_world (const w') g));;
    ret e'.

  Local Instance crypto_semantics : ffi_semantics crypto_op crypto_model :=
    { ffi_step := ffi_step;
      ffi_crash_step := eq; }.
End crypto.
