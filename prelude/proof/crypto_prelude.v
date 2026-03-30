From Cryptoffi Require Import crypto_ffi.
From New.proof Require Export proof_prelude.
From New Require Export atomic_fupd.
From New Require Export crypto_prelude.

#[global]
Existing Instances crypto_semantics crypto_interp.
#[global]
Existing Instances goose_cryptoGS goose_cryptoNodeGS.

(* Make sure Z_scope is open. *)
Local Lemma Z_scope_test : (0%Z) + (0%Z) = 0%Z.
Proof. done. Qed.
