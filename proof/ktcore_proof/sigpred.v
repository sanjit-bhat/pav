From New.proof Require Import proof_prelude.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.
From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi hashchain merkle safemarshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  key_map serde.

Module ktcore.
Import key_map.ktcore serde.ktcore.

Module sigpred_cfg.
Record t :=
  mk {
    vrf : gname;
    (* the epoch of the first hist idx.
    the auditor has no way of knowing if the server's digs start from epoch 0. *)
    start_ep : gname;
    (* the len offset after which auditor started monitoring. *)
    audit_offset : gname;
    hist : gname;
  }.
End sigpred_cfg.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _, !globalsGS Σ} {go_ctx : GoContext}.
Context `{!pavG Σ}.

Definition sigpred_vrf γ (vrfPk : list w8) : iProp Σ :=
  "#Hshot" ∷ ghost_var γ.(sigpred_cfg.vrf) (□) vrfPk.

Definition sigpred_vrf_aux γ enc : iProp Σ :=
  ∃ vrfPk,
  "%Henc" ∷ ⌜enc = ktcore.VrfSig.pure_enc (ktcore.VrfSig.mk' (W8 ktcore.VrfSigTag) vrfPk)⌝ ∗
  "%Hvalid" ∷ ⌜safemarshal.Slice1D.valid vrfPk⌝ ∗
  "#Hsigpred" ∷ sigpred_vrf γ vrfPk.

Definition sigpred_links_inv (start_ep : w64) links digs cut maps : iProp Σ :=
  (* [offset] is the number of [digs] prior to [links] starting.
  we leave [digs] un-tied to [start_ep], even tho it's implicitly
  constrained by [is_chain]. *)
  let offset := (length digs - length links)%nat in
  "%Hlt_digs_links" ∷ ⌜length links ≤ length digs⌝ ∗
  "#Hlinks" ∷ ([∗ list] idx ↦ link ∈ links,
    let n_digs := (offset + idx + 1)%nat in
    let ep := (uint.nat start_ep + idx)%nat in
    "#His_link" ∷ hashchain.is_chain (take n_digs digs) cut link (S ep)) ∗
  "#Hmaps" ∷ ([∗ list] idx ↦ _;m ∈ links;maps,
    ∃ dig,
    "%Hlook_dig" ∷ ⌜digs !! (offset + idx)%nat = Some dig⌝ ∗
    "#His_map" ∷ merkle.is_map m dig) ∗
  "%Hmono" ∷ ⌜list_reln maps (⊆)⌝.

Definition sigpred_links γ (ep : w64) link : iProp Σ :=
  (* [links] are all audited. they start from [start_ep]. *)
  ∃ start_ep links digs cut maps,
  (* externalize start_ep so that users agree on the epochs associated with links. *)
  "#Hshot" ∷ ghost_var γ.(sigpred_cfg.start_ep) (□) start_ep ∗
  "#Hlb" ∷ mono_list_lb_own γ.(sigpred_cfg.links) links ∗
  "%Hlook" ∷ ⌜links !! (uint.nat ep - uint.nat start_ep)%nat = Some link⌝ ∗
  "#Hinv" ∷ sigpred_links_inv start_ep links digs cut maps.

Definition sigpred_links_aux γ enc : iProp Σ :=
  ∃ ep link,
  "%Henc" ∷ ⌜enc = ktcore.LinkSig.pure_enc (ktcore.LinkSig.mk' (W8 ktcore.LinkSigTag) ep link)⌝ ∗
  "%Hvalid" ∷ ⌜safemarshal.Slice1D.valid link⌝ ∗
  "#Hsigpred" ∷ sigpred_links γ ep link.

Definition sigpred γ enc : iProp Σ :=
  sigpred_vrf_aux γ enc ∨ sigpred_links_aux γ enc.

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
