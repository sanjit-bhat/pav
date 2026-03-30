From New.golang Require Import defn.
From Cryptoffi Require Export impl.

#[global]
Existing Instances crypto_op crypto_model.
(** * Crypto user-facing operations. *)
Section crypto.
  Context {go_gctx : GoGlobalContext}.

  (** Type: func(uint64) Listener *)
  Definition TrustedHashⁱᵐᵖˡ : val :=
    λ: "data", ExternalOp Hash "data".

End crypto.
