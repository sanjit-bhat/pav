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

Local Definition to_plain vrf_pk dig := plain_inv_fn vrf_pk (merkle.inv_fn dig).
Arguments to_plain /.

Local Definition to_pks vrf_pk uid dig := to_plain vrf_pk dig !!! uid.
Arguments to_pks /.

(* after auditing, learn that client digs equal auditor digs.
also learn [mono_maps], so "apply" that in [is_staged_keys]. *)
Definition is_committed_keys vrf_pk digs uid keys :=
  Forall2 (λ dig opt_key,
    last $ to_pks vrf_pk uid dig = opt_key) digs keys.

Definition is_staged_keys vrf_pk digs uid keys next_ver :=
  (* next_ver doesn't have meaning without digs. *)
  match last digs with None => False | Some last_dig =>
    in_hidden vrf_pk (merkle.inv_fn last_dig) uid next_ver None end ∧
  ( mono_maps digs →
    match last digs with None => False | Some last_dig =>
      length $ to_pks vrf_pk uid last_dig = next_ver end ∧
    is_committed_keys vrf_pk digs uid keys ).

Lemma commit_staged vrf_pk digs uid keys next_ver :
  is_staged_keys vrf_pk digs uid keys next_ver →
  mono_maps digs →
  is_committed_keys vrf_pk digs uid keys.
Proof. rewrite /is_staged_keys. naive_solver. Qed.

(* TODO: maybe could be iff. *)
Lemma list_reln_app {A} R (l0 l1 : list A) :
  list_reln (l0 ++ l1) R →
  list_reln l0 R ∧ list_reln l1 R.
Proof. Admitted.

Lemma list_reln_box {A B} R0 R1 (f : A → B) (l0 : list A) :
  list_reln l0 R0 →
  (∀ x0 x1, R0 x0 x1 → R1 (f x0) (f x1)) →
  list_reln (f <$> l0) R1.
Proof. Admitted.

Lemma plain_mono_lookup vrf_pk uid {digs i j xi xj} :
  mono_maps digs →
  digs !! i = Some xi →
  digs !! j = Some xj →
  (i ≤ j)%nat →
  to_pks vrf_pk uid xi `prefix_of` to_pks vrf_pk uid xj.
Proof.
  rewrite /mono_maps. intros Hmono Hlook0 Hlook1 **.
  apply (list_reln_box _ keys_sub (plain_inv_fn vrf_pk)) in Hmono.
  2: { eapply plain_inv_mono. }
  opose proof (list_reln_trans_refl _ _ Hmono _ _ _ _ _ _ _) as Hsub.
  { rewrite !list_lookup_fmap.
    by erewrite Hlook0. }
  { rewrite !list_lookup_fmap.
    by erewrite Hlook1. }
  { done. }
  specialize (Hsub uid).
  simpl.
  rewrite !lookup_total_alt.
  destruct (_ !! uid), (_ !! uid); try done.
  simpl in *. apply prefix_nil.
Qed.

Lemma is_staged_init vrf_pk digs last_dig uid :
  let keys := replicate (length digs) None in
  last digs = Some last_dig →
  in_hidden vrf_pk (merkle.inv_fn last_dig) uid 0 None →
  is_staged_keys vrf_pk digs uid keys 0.
Proof.
  rewrite /is_staged_keys. intros Hlast_dig Hnone.
  rewrite Hlast_dig.
  assert (to_pks vrf_pk uid last_dig = []) as Hnil.
  { eapply inv_fn_None_bound in Hnone as ?.
    simpl. by destruct (plain_inv_fn _ _ !!! _). }
  split; try done.
  intros Hmono.
  split. { by rewrite Hnil. }
  clear Hnone.

  rewrite /is_committed_keys.
  apply Forall2_same_length_lookup.
  split; [len|].
  intros * Hlook Hrepl.
  rewrite last_lookup in Hlast_dig.
  apply lookup_replicate in Hrepl as [-> ?].
  opose proof (plain_mono_lookup vrf_pk uid Hmono Hlook Hlast_dig _) as Hpref; [len|].
  rewrite Hnil in Hpref.
  by apply prefix_nil_inv in Hpref as ->.
Qed.

Lemma lookup_app_r' {A} (l1 l2 : list A) i :
  l2 !! i = (l1 ++ l2) !! (i + length l1)%nat.
Proof. rewrite lookup_app_r; [|lia]. f_equal. lia. Qed.

Lemma prefix_eq {A} (l1 l2 : list A) :
  l1 `prefix_of` l2 →
  l2 `prefix_of` l1 →
  l1 = l2.
Proof. intros ? ?%prefix_length. by apply prefix_length_eq. Qed.

(* grow staged keys by replicating the last existing key. *)
Lemma is_staged_keys_grow_last vrf_pk digs new_digs new_dig uid keys old_key next_ver :
  let digs' := digs ++ new_digs in
  let keys' := keys ++ replicate (length new_digs) old_key in
  let new_m := merkle.inv_fn new_dig in
  is_staged_keys vrf_pk digs uid keys next_ver →
  last digs' = Some new_dig →
  last keys = Some old_key →
  in_hidden vrf_pk new_m uid next_ver None →
  is_staged_keys vrf_pk digs' uid keys' next_ver.
Proof.
  rewrite /is_staged_keys. intros [_ Hstage] Hnew_dig Hold_key Hnone.
  rewrite Hnew_dig.
  split; try done.
  intros Hmono.
  odestruct (Hstage _) as [Hver Hkeys].
  { unfold mono_maps in *.
    rewrite fmap_app in Hmono.
    apply list_reln_app in Hmono.
    naive_solver. }
  clear Hstage.
  destruct (last digs) as [old_dig|] eqn:Hold_dig; try done.
  assert (last $ to_pks vrf_pk uid old_dig = old_key).
  { rewrite /is_committed_keys in Hkeys.
    apply Forall2_last in Hkeys.
    rewrite Hold_dig Hold_key in Hkeys.
    by inv Hkeys. }
  subst.
  rewrite !last_lookup in Hold_dig Hnew_dig.
  eapply lookup_app_l_Some in Hold_dig.
  eassert (to_pks vrf_pk uid old_dig = to_pks vrf_pk uid new_dig) as Heq_pks.
  { opose proof (plain_mono_lookup vrf_pk uid Hmono Hold_dig Hnew_dig _) as ?; [len|].
    eapply inv_fn_None_bound in Hnone.
    eapply prefix_length_eq; [done|].
    simpl in *. lia. }
  clear Hold_key Hnone.

  (* approach: bring all facts to plain maps layer,
  then do the core reasoning there. *)
  split. { by rewrite -Heq_pks. }
  rewrite /is_committed_keys in Hkeys |-*.
  eapply Forall2_app; [done|].
  clear Hkeys.
  eapply Forall2_same_length_lookup.
  split; [len|].
  intros ? mid_dig * Hlook_mid Hrepl.
  apply lookup_replicate in Hrepl as [-> ?].
  rewrite (lookup_app_r' digs) in Hlook_mid.
  opose proof (plain_mono_lookup vrf_pk uid Hmono Hold_dig Hlook_mid _) as Hpref_reg0; [len|].
  opose proof (plain_mono_lookup vrf_pk uid Hmono Hlook_mid Hnew_dig _) as Hpref_reg1; [len|].
  f_equal. rewrite -Heq_pks in Hpref_reg1.
  by eapply prefix_eq.
Qed.

(* grow staged keys by adding a new key. *)
Lemma is_staged_keys_grow_new vrf_pk digs new_digs new_dig uid keys old_key new_key next_ver :
  let digs' := digs ++ new_digs in
  let new_m := merkle.inv_fn new_dig in
  is_staged_keys vrf_pk digs uid keys next_ver →
  last digs' = Some new_dig →
  last keys = Some old_key →
  in_hidden vrf_pk new_m uid next_ver (Some new_key) →
  in_hidden vrf_pk new_m uid (S next_ver) None →
  ∃ (num_old num_new : nat),
    let keys' :=
      keys ++
      replicate num_old old_key ++
      replicate (S num_new) (Some new_key) in
    num_old + S num_new = length new_digs ∧
    is_staged_keys vrf_pk digs' uid keys' (S next_ver).
Proof. Admitted.
(*
- need to [decide] ep s.t. ep !! next_ver = None and S ep !! next_ver = Some.
then, after we get mono_maps, can use prefix on plain
reasoning to prove the goal.
- but: currently, is_staged_keys (w/o mono_maps) tells us nothing about old_dig.
need to strengthen it to mention next_ver, even w/o mono_maps. *)

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
