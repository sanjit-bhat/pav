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
    digs_info : gname;
  }.
End cfg.

Module digs_info.
Record t :=
  mk {
    (* epoch of first dig. *)
    start_ep : nat;
    (* the hashchain cut. *)
    cut : option $ list w8;
    (* the offset in digs after which auditor started monitoring. *)
    audit_offset : nat;
  }.
End digs_info.

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

(** link sig. *)

Definition mono_maps digs :=
  let hidden_maps := merkle.inv_fn <$> digs in
  (* ⊆ on hidden maps is stronger than on plain maps. *)
  list_reln hidden_maps (⊆).

Definition linkP γ (ep : w64) link : iProp Σ :=
  ∃ digs info,
  "%Hinv" ∷ ⌜hashchain.inv_fn link (S $ S $ uint.nat ep) = (digs, info.(digs_info.cut))⌝ ∗
  "#Hlb_digs" ∷ mono_list_lb_own γ.(cfg.digs) digs ∗
  "#His_info" ∷ dghost_var γ.(cfg.digs_info) (□) info ∗
  "%Hlen_digs" ∷ ⌜S $ uint.nat ep = (info.(digs_info.start_ep) + length digs)%nat⌝ ∗
  "%Hmono_maps" ∷ ⌜mono_maps (drop info.(digs_info.audit_offset) digs)⌝.

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
  iNamedSuffix "H0" "0". iNamedSuffix "H1" "1".
  iCombine "His_info0 His_info1" gives %[_ ->].
  iDestruct (mono_list_lb_valid with "Hlb_digs0 Hlb_digs1") as %Hpref.
  assert (digs = digs0) as ->.
  { assert (length digs = length digs0) by word.
    destruct Hpref as [Ht|Ht];
      (apply prefix_length_eq in Ht; [done|lia]). }
  opose proof (hashchain.det link0 link1 _ _ _) as ->; [|done].
  erewrite Hinv0. by erewrite Hinv1.
Qed.

(** staged / committed keys. *)

Definition is_staged_keys vrf_pk digs uid keys next_ver :=
  let hidden_maps := merkle.inv_fn <$> digs in
  let plain_maps := plain_inv_fn vrf_pk <$> hidden_maps in
  match last plain_maps with
  | None => next_ver = 0%nat
  | Some plain => length $ plain !!! uid = next_ver
  end ∧
  ( mono_maps digs →
    Forall2 (λ plain opt_key, last $ plain !!! uid = opt_key) plain_maps keys ).

(* TODO: generalize opt_pk from key_map defn. *)
Definition in_hidden vrf_pk (hidden : gmap (list w8) (list w8)) uid (ver : nat) opt_pk :=
  ∃ map_label,
  map_label_fn vrf_pk uid (W64 ver) map_label ∧
  match opt_pk with
  | None =>
    hidden !! map_label = None
  | Some pk =>
    ∃ rand map_val,
    map_val_fn pk rand map_val ∧
    hidden !! map_label = Some map_val
  end.

Lemma is_staged_keys_grow_last vrf_pk digs new_digs last_dig uid keys next_ver :
  let digs' := digs ++ new_digs in
  let keys' := keys ++ replicate (length new_digs) (default None (last keys)) in
  let last_m := merkle.inv_fn last_dig in
  is_staged_keys vrf_pk digs uid keys next_ver →
  last digs' = Some last_dig →
  in_hidden vrf_pk last_m uid next_ver None →
  is_staged_keys vrf_pk digs' uid keys' next_ver.
Proof. Admitted.

Lemma is_staged_keys_grow_new vrf_pk digs new_digs last_dig uid keys new_key next_ver :
  let digs' := digs ++ new_digs in
  let last_m := merkle.inv_fn last_dig in
  is_staged_keys vrf_pk digs uid keys next_ver →
  last digs' = Some last_dig →
  in_hidden vrf_pk last_m uid next_ver (Some new_key) →
  in_hidden vrf_pk last_m uid (S next_ver) None →
  ∃ (num_old num_new : nat),
    let keys' :=
      keys ++
      replicate num_old (default None (last keys)) ++
      replicate (S num_new) (Some new_key) in
    num_old + S num_new = length new_digs ∧
    is_staged_keys vrf_pk digs' uid keys' (S next_ver).
Proof. Admitted.

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

(* TODO: stitch together sigs from multiple auditors,
who each have audited overlapping epoch ranges. *)
