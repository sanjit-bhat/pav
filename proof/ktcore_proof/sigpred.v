From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.
From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi hashchain merkle safemarshal.

About merkle.inv_fn.
From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  key_map serde.

Module ktcore.
Import key_map.ktcore serde.ktcore.

Module sigpred.

Module cfg.
Record t :=
  mk {
    vrf : gname;

    digs : gname;
    (* below are "metadata" about digs. *)
    (* epoch of first dig. *)
    start_ep : gname;
    (* the hashchain cut. *)
    cut : gname;
    (* the offset in digs after which auditor started monitoring. *)
    audit_offset : gname;
  }.
End cfg.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

(** VRF sig. *)

Definition vrfP γ (vrfPk : list w8) : iProp Σ :=
  "#Hshot" ∷ dghost_var γ.(cfg.vrf) (□) vrfPk.

Definition vrfP_aux γ enc : iProp Σ :=
  ∃ vrfPk,
  "%Henc" ∷ ⌜enc = ktcore.VrfSig.pure_enc (ktcore.VrfSig.mk' (W8 ktcore.VrfSigTag) vrfPk)⌝ ∗
  "%Hvalid" ∷ ⌜safemarshal.Slice1D.valid vrfPk⌝ ∗
  "#Hsigpred" ∷ vrfP γ vrfPk.

Lemma vrfP_evid γ vrfPk0 vrfPk1 :
  vrfP γ vrfPk0 -∗
  vrfP γ vrfPk1 -∗
  ⌜vrfPk0 = vrfPk1⌝.
Proof.
  rewrite /vrfP. iNamedSuffix 1 "0". iNamedSuffix 1 "1".
  by iCombine "Hshot0 Hshot1" gives %[_ ->].
Qed.

(** Link sig. *)

Definition mono digs audit_offset :=
  let hidden_maps := merkle.inv_fn <$> digs in
  (* ⊆ on hidden maps is stronger than on plain maps. *)
  list_reln (drop audit_offset hidden_maps) (⊆).

Definition linkP γ (ep : w64) link : iProp Σ :=
  ∃ start_ep audit_offset,
  let '(digs, cut) := hashchain.inv_fn link (S $ S $ uint.nat ep) in
  "#Hlb_digs" ∷ mono_list_lb_own γ.(cfg.digs) digs ∗
  "#His_start" ∷ dghost_var γ.(cfg.start_ep) (□) start_ep ∗
  "%Hlen_digs" ∷ ⌜S $ uint.nat ep = (start_ep + length digs)%nat⌝ ∗
  "#His_cut" ∷ dghost_var γ.(cfg.cut) (□) cut ∗
  "#His_offset" ∷ dghost_var γ.(cfg.audit_offset) (□) audit_offset ∗
  "%Hmono" ∷ ⌜mono digs audit_offset⌝.

Definition linkP_aux γ enc : iProp Σ :=
  ∃ ep link,
  "%Henc" ∷ ⌜enc = ktcore.LinkSig.pure_enc (ktcore.LinkSig.mk' (W8 ktcore.LinkSigTag) ep link)⌝ ∗
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
  iNamed "H0". iNamed "H1".
  case_match eqn:Hinv0.
  case_match eqn:Hinv1.
  iNamedSuffix "H0" "0". iNamedSuffix "H1" "1".
  iCombine "His_start0 His_start1" gives %[_ ->].
  iCombine "His_cut0 His_cut1" gives %[_ ->].
  iDestruct (mono_list_lb_valid with "Hlb_digs0 Hlb_digs1") as %Hpref.
  assert (l = l0) as ->.
  { assert (length l = length l0) by word.
    destruct Hpref as [Ht|Ht];
      (apply prefix_length_eq in Ht; [done|lia]). }
  opose proof (hashchain.det link0 link1 _ _ _) as ->; [|done].
  erewrite Hinv0. by erewrite Hinv1.
Qed.

(*
Lemma sigpred_links_inv_grow start_ep links link digs dig cut maps m :
  (∀ prev_map, last maps = Some prev_map → prev_map ⊆ m) →
  sigpred_links_inv start_ep links digs cut maps -∗
  merkle.is_map m dig -∗
  hashchain.is_chain (digs ++ [dig]) cut link
    (uint.nat start_ep + length links + 1)%nat -∗
  sigpred_links_inv start_ep (links ++ [link]) (digs ++ [dig]) cut (maps ++ [m]).
Proof.
  iIntros (Hsub) "@ #His_map #His_link".
  rewrite /sigpred_links_inv.
  autorewrite with len in *.
  iSplit; [word|].
  iSplit.
  { rewrite big_sepL_snoc.
    iSplit.
    - iApply (big_sepL_impl with "Hlinks").
      iIntros "!> *". iIntros (?%lookup_lt_Some). iNamedSuffix 1 "0".
      iExactEq "His_link0". rewrite /named. f_equal.
      rewrite take_app_le; [|word].
      f_equal. word.
    - simpl. iExactEq "His_link". rewrite /named.
      f_equal; [|word].
      rewrite take_ge; [done|len]. }
  iSplit.
  { rewrite big_sepL2_snoc.
    iSplit.
    - iApply (big_sepL2_impl with "Hmaps").
      iIntros "!> *". iIntros (?%lookup_lt_Some ?). iNamedSuffix 1 "0".
      iExists _. iSplit.
      + rewrite lookup_app_l; [|word].
        iPureIntro. exact_eq Hlook_dig0. f_equal. word.
      + done.
    - iExists _. iSplit.
      + rewrite lookup_app_r; [|word].
        rewrite list_lookup_singleton_Some.
        iPureIntro. split; [|done]. word.
      + done. }
  { iPureIntro. by apply list_reln_snoc. }
Qed.
*)

End proof.
End sigpred.
End ktcore.
