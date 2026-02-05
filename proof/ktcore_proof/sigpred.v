From New.proof Require Import proof_prelude.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.
From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi hashchain merkle safemarshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  common serde.

Module ktcore.
Import common.ktcore serde.ktcore.

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

(* gmap from uid's to list of pks (indexed by version). *)
Definition keys_ty := gmap w64 (list $ list w8).

(* FIXME: needed for lia to unify [length digs] terms where one has keys_ty and
the other has its unfolding *)
#[global] Hint Unfold keys_ty : word.

Definition keys_sub : relation keys_ty := map_included (λ _, prefix).

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _, !globalsGS Σ} {go_ctx : GoContext}.
Context `{!pavG Σ}.

Definition decode_map_label odata :=
  rem0 ← odata;
  guard (length rem0 ≥ 8);;
  let uid := le_to_u64 (take 8 rem0) in
  let rem1 := drop 8 rem0 in
  guard (length rem1 ≥ 8);;
  let ver := le_to_u64 (take 8 rem1) in
  Some (uid, uint.nat ver).

Definition decode_map_val odata :=
  rem0 ← odata;
  guard (length rem0 ≥ 8);;
  let pk_len := sint.nat (le_to_u64 (take 8 rem0)) in
  let rem1 := drop 8 rem0 in
  guard (length rem1 ≥ pk_len);;
  let pk := take pk_len rem1 in
  (* drop the remaining rand. we don't need that. *)
  Some (pk).

Definition is_decode_map_label vrf_pk map_label obj : iProp Σ :=
  ∃ odata,
  "#His_vrf_out" ∷ cryptoffi.is_vrf_out vrf_pk odata map_label ∗
  "%Hdec" ∷ ⌜obj = decode_map_label odata⌝.

Definition is_decode_map_val map_val obj : iProp Σ :=
  ∃ odata,
  "#His_hash" ∷ cryptoffi.is_hash odata map_val ∗
  "%Hdec" ∷ ⌜obj = decode_map_val odata⌝.

(* maybe change. *)
Definition is_flat_keys vrf_pk hidden flat : iProp Σ :=
  ∃ decoded,
  "#Hdec" ∷ ([∗ list] kv;d ∈ map_to_list hidden;decoded,
    is_decode_map_label vrf_pk kv.1 d.1 ∗
    is_decode_map_val kv.2 d.2) ∗
  "%Hflat" ∷ ⌜flat = omap (λ '(olabel, oval),
    '(uid, ver) ← olabel;
    pk ← oval;
    Some (uid, ver, pk)) decoded⌝.

(*
structuring the hidden -> plain computation:
- merkle labels are structurally unique.
combined with is_vrf_out_inj, have unique (uid, ver).
merkle val gives pk.
- assemble into gmap uid (gmap ver pk).
- now deal with each uid. gmap ver pk.
- want to compute longest contiguous prefix.
can write fixpoint for that, but with what max ver?
size (gmap ver pk) is an easy over-approx.
*)

Definition is_plain_keys (vrf_pk : list w8) (hidden : gmap (list w8) (list w8))
    (plain : keys_ty) : iProp Σ.
Admitted.

(* used by clients who agree across the same digs. *)
Lemma is_plain_keys_det vrf_pk hidden plain0 plain1 :
  is_plain_keys vrf_pk hidden plain0 -∗
  is_plain_keys vrf_pk hidden plain1 -∗
  ⌜plain0 = plain1⌝.
Proof. Admitted.

(* used by auditor.
to prove, is_plain_keys can't require bijection. *)
Lemma is_plain_keys_invert vrf_pk hidden :
  ⊢ ∃ plain, is_plain_keys vrf_pk hidden plain.
Proof. Admitted.

(* used by auditor.
maybe could be generalized? *)
Lemma is_plain_keys_over_sub vrf_pk hidden0 hidden1 plain0 plain1 :
  hidden0 ⊆ hidden1 →
  is_plain_keys vrf_pk hidden0 plain0 -∗
  is_plain_keys vrf_pk hidden1 plain1 -∗
  ⌜keys_sub plain0 plain1⌝.
Proof. Admitted.

(* hidden is fully made up of contiguous versions.
i.e., hidden and the computed plain are bijective. *)
Definition is_contig (vrf_pk : list w8) (hidden : gmap (list w8) (list w8)) : iProp Σ.
Admitted.

(* used in server update. *)
Lemma is_plain_keys_add vrf_pk hidden plain uid kt_pk label val rand :
  let pks := plain !!! uid in
  is_plain_keys vrf_pk hidden plain -∗
  is_contig vrf_pk hidden -∗
  is_MapLabel vrf_pk uid (length pks) label -∗
  is_MapVal kt_pk rand val -∗
  let hidden' := <[label:=val]>hidden in
  let plain' := <[uid:=pks ++ [kt_pk]]>plain in
  is_plain_keys vrf_pk hidden' plain' ∗ is_contig vrf_pk hidden'.
Proof. Admitted.

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
