From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.
From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi hashchain merkle safemarshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  agree key_map serde.

Module sigpred.
Import agree.ktcore key_map.ktcore serde.ktcore.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

(** VRF sig. *)

Definition vrfP γ (vrfPk : list w8) : iProp Σ :=
  let γ' := γ.(AdtrAgree.agree) in
  "%Heq_vrfPk" ∷ ⌜vrfPk = γ'.(Agree.vrf_pk)⌝.

Definition vrfP_aux γ enc : iProp Σ :=
  ∃ vrfPk,
  "%Henc" ∷ ⌜enc = VrfSig.pure_enc (VrfSig.mk' (W8 VrfSigTag) vrfPk)⌝ ∗
  "%Hvalid" ∷ ⌜safemarshal.Slice1D.valid vrfPk⌝ ∗
  "#Hsigpred" ∷ vrfP γ vrfPk.

Lemma vrfP_evid γ vrfPk0 vrfPk1 :
  vrfP γ vrfPk0 -∗
  vrfP γ vrfPk1 -∗
  ⌜vrfPk0 = vrfPk1⌝.
Proof.
  rewrite /vrfP. iNamedSuffix 1 "0". iNamedSuffix 1 "1".
  by simplify_eq/=.
Qed.

(** link sig. *)

Definition linkP γ (ep : w64) link : iProp Σ :=
  ∃ digs,
  let γ' := γ.(AdtrAgree.agree) in
  "%Hinv" ∷ ⌜hashchain.valid digs γ.(AdtrAgree.cut)
    link (S $ uint.nat ep)⌝ ∗
  "#Hlb_digs" ∷ mono_list_lb_own γ'.(Agree.digs) digs ∗
  "%Hlen_digs" ∷ ⌜S $ uint.nat ep = (γ'.(Agree.digs_start) + length digs)%nat⌝ ∗
  (* we started auditing at least by this epoch. *)
  "%Hlt_audit" ∷ ⌜(γ'.(Agree.digs_start) + γ.(AdtrAgree.audit_start))%nat ≤ uint.nat ep⌝ ∗
  "%Hmono_plain" ∷ ⌜mono_plain γ'.(Agree.vrf_pk) (drop γ.(AdtrAgree.audit_start) digs)⌝.

Definition linkP_aux γ enc : iProp Σ :=
  ∃ ep link,
  "%Henc" ∷ ⌜enc = LinkSig.pure_enc (LinkSig.mk' (W8 LinkSigTag) ep link)⌝ ∗
  "%Hvalid" ∷ ⌜safemarshal.Slice1D.valid link⌝ ∗
  "#Hsigpred" ∷ linkP γ ep link.

Definition P γ enc : iProp Σ :=
  vrfP_aux γ enc ∨ linkP_aux γ enc.

#[global] Instance P_pers γ e : Persistent (P γ e).
Proof. apply _. Qed.

Lemma linkP_evid γ ep link0 link1 :
  linkP γ ep link0 -∗
  linkP γ ep link1 -∗
  ⌜link0 = link1⌝.
Proof.
  rewrite /linkP. iIntros "H0 H1".
  iNamedSuffix "H0" "0". iNamedSuffix "H1" "1".
  iDestruct (mono_list_lb_valid with "Hlb_digs0 Hlb_digs1") as %Hpref.
  assert (digs = digs0) as ->.
  { assert (length digs = length digs0) by word.
    destruct Hpref as [Ht|Ht];
      (apply prefix_length_eq in Ht; [done|lia]). }
  by opose proof (hashchain.det' Hinv0 Hinv1) as ->.
Qed.

End proof.
End sigpred.
