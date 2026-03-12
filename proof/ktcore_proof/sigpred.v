From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.
From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi hashchain merkle safemarshal.

About merkle.inv_fn.
From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  key_map serde.

Module ktcore.
Import key_map.ktcore serde.ktcore.

(*
to refresh, structure of digs pred:
- there's a mono_list of digs.
mono is important. means that two sigs at diff epochs overlap.
- auditor gets starting link at some StartEpoch.
invert with fuel:=StartEpoch to get some digs.
when inverting, could fewer digs than StartEpoch.
could invert to cut.

reqs:
- need to state that maps are mono.
but which maps? hidden or plain?
- from hidden mono, can derive plain mono.
so let's do that.
*)

Module sigpred_cfg.
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
End sigpred_cfg.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition sigpred_vrf γ (vrfPk : list w8) : iProp Σ :=
  "#Hshot" ∷ dghost_var γ.(sigpred_cfg.vrf) (□) vrfPk.

Definition sigpred_vrf_aux γ enc : iProp Σ :=
  ∃ vrfPk,
  "%Henc" ∷ ⌜enc = ktcore.VrfSig.pure_enc (ktcore.VrfSig.mk' (W8 ktcore.VrfSigTag) vrfPk)⌝ ∗
  "%Hvalid" ∷ ⌜safemarshal.Slice1D.valid vrfPk⌝ ∗
  "#Hsigpred" ∷ sigpred_vrf γ vrfPk.

Definition digs_mono digs audit_offset :=
  let hidden_maps := merkle.inv_fn <$> digs in
  (* ⊆ on hidden maps is stronger than on plain maps. *)
  list_reln (drop audit_offset hidden_maps) (⊆).

Definition sigpred_link γ (ep : w64) link : iProp Σ :=
  ∃ start_ep audit_offset,
  let '(digs, cut) := hashchain.inv_fn link (S $ S $ uint.nat ep) in
  "#Hlb_digs" ∷ mono_list_lb_own γ.(sigpred_cfg.digs) digs ∗
  "#His_start" ∷ dghost_var γ.(sigpred_cfg.start_ep) (□) start_ep ∗
  "%Hlen_digs" ∷ ⌜S $ uint.nat ep = (start_ep + length digs)%nat⌝ ∗
  "#His_cut" ∷ dghost_var γ.(sigpred_cfg.cut) (□) cut ∗
  "#His_offset" ∷ dghost_var γ.(sigpred_cfg.audit_offset) (□) audit_offset ∗
  "%Hmono" ∷ ⌜digs_mono digs audit_offset⌝.

Definition sigpred_link_aux γ enc : iProp Σ :=
  ∃ ep link,
  "%Henc" ∷ ⌜enc = ktcore.LinkSig.pure_enc (ktcore.LinkSig.mk' (W8 ktcore.LinkSigTag) ep link)⌝ ∗
  "%Hvalid" ∷ ⌜safemarshal.Slice1D.valid link⌝ ∗
  "#Hsigpred" ∷ sigpred_link γ ep link.

Definition sigpred γ enc : iProp Σ :=
  sigpred_vrf_aux γ enc ∨ sigpred_link_aux γ enc.

#[global] Instance sigpred_pers γ e : Persistent (sigpred γ e).
Proof. apply _. Qed.

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

End proof.
End ktcore.
