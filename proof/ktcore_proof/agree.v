From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.
From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi hashchain merkle safemarshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  key_map sigpred staged_keys.

Module ktcore.
Import key_map.ktcore sigpred.sigpred staged_keys.ktcore.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Local Definition kt_ptsto_def γ ep uid opt_pk : iProp Σ :=
  ∃ dig,
  "#Hlook_dig" ∷ mono_list_idx_own γ.(sigpred.cfg.digs) ep dig ∗
  "%Heq_pk" ∷ ⌜last $ ktcore.to_pks γ.(sigpred.cfg.vrf_pk) uid dig = opt_pk⌝.
Program Definition kt_ptsto := sealed @kt_ptsto_def.
Definition kt_ptsto_unseal : kt_ptsto = _ := seal_eq _.

End proof.

Global Notation "( γ , ep , uid ) ↪KT opt_pk" :=
  (kt_ptsto γ ep uid opt_pk) (at level 20).

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Local Ltac unseal := rewrite ?kt_ptsto_unseal /kt_ptsto_def.

Global Instance kt_ptsto_pers γ ep uid opt_pk :
  Persistent ((γ, ep, uid) ↪KT opt_pk).
Proof. unseal. apply _. Qed.

Lemma kt_ptsto_agree γ ep uid opt_pk0 opt_pk1 :
  (γ, ep, uid) ↪KT opt_pk0 -∗
  (γ, ep, uid) ↪KT opt_pk1 -∗
  ⌜opt_pk0 = opt_pk1⌝.
Proof.
  unseal. iNamedSuffix 1 "0". iNamedSuffix 1 "1".
  iDestruct (mono_list_idx_agree with "Hlook_dig0 Hlook_dig1") as %->.
  by subst.
Qed.

End proof.
End ktcore.
