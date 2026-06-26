From New.golang Require Import defn.
From Cryptoffi Require Export impl.

#[global]
Existing Instances crypto_op crypto_model.
(** * Crypto user-facing operations. *)
Section crypto.
  Context {go_gctx : GoGlobalContext}.

  (** Type: func(string) string.
  [ExternalOp Hash] already performs the prophecy-resolve internally (see
  [is_crypto_ffi_step] in [crypto_ffi/impl.v]), so no extra [Resolve] wrapper is
  needed here; the proph id is the internal [crypto_hash_proph_id]. *)
  Definition TrustedHashⁱᵐᵖˡ : val :=
    λ: "data", ExternalOp Hash "data".

End crypto.
