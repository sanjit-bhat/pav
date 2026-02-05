From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi cryptoutil hashchain merkle safemarshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  serde.

Module ktcore.
Import serde.ktcore.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _, !globalsGS Σ} {go_ctx : GoContext}.
Context `{!pavG Σ}.

Definition is_MapLabel vrf_pk uid ver map_label : iProp Σ :=
  let enc := MapLabel.pure_enc (MapLabel.mk' uid ver) in
  cryptoffi.is_vrf_out vrf_pk (Some enc) map_label.

Lemma is_MapLabel_det pk uid ver map_label0 map_label1 :
  is_MapLabel pk uid ver map_label0 -∗
  is_MapLabel pk uid ver map_label1 -∗
  ⌜map_label0 = map_label1⌝.
Proof.
  rewrite /is_MapLabel.
  iIntros "#H0 #H1".
  iDestruct (cryptoffi.is_vrf_out_det with "H0 H1") as %->.
  done.
Qed.

(* externalize [rand] bc some clients want to determ
derive [map_val] from [kt_pk]. *)
Definition is_MapVal kt_pk rand map_val : iProp Σ :=
  let enc := CommitOpen.pure_enc (CommitOpen.mk' kt_pk rand) in
  cryptoffi.is_hash (Some enc) map_val.

Lemma is_MapVal_det pk rand map_val0 map_val1 :
  is_MapVal pk rand map_val0 -∗
  is_MapVal pk rand map_val1 -∗
  ⌜map_val0 = map_val1⌝.
Proof.
  iIntros "#H0 #H1".
  iDestruct (cryptoffi.is_hash_det with "H0 H1") as %->.
  done.
Qed.

End proof.
End ktcore.
