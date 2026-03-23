From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.
From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi hashchain merkle safemarshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  key_map serde.

Module ktcore.
Import key_map.ktcore serde.ktcore.

Module sigpred.

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

Module cfg.
Record t :=
  mk {
    vrf_pk : list w8;
    digs : gname;
    info : digs_info.t;
  }.
End cfg.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

(** VRF sig. *)

Definition vrfP γ (vrfPk : list w8) : iProp Σ :=
  "%Heq_vrfPk" ∷ ⌜vrfPk = γ.(cfg.vrf_pk)⌝.

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
  by simplify_eq/=.
Qed.

(** link sig. *)

Definition mono_maps digs :=
  let hidden_maps := merkle.inv_fn <$> digs in
  (* ⊆ on hidden maps is stronger than on plain maps. *)
  list_reln hidden_maps (⊆).

Definition linkP γ (ep : w64) link : iProp Σ :=
  ∃ digs,
  "%Hinv" ∷ ⌜hashchain.inv_fn link (S $ S $ uint.nat ep) =
    (digs, γ.(cfg.info).(digs_info.cut))⌝ ∗
  "#Hlb_digs" ∷ mono_list_lb_own γ.(cfg.digs) digs ∗
  "%Hlen_digs" ∷ ⌜S $ uint.nat ep = (γ.(cfg.info).(digs_info.start_ep) + length digs)%nat⌝ ∗
  "%Hmono_maps" ∷ ⌜mono_maps (drop γ.(cfg.info).(digs_info.audit_offset) digs)⌝.

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
(* treat [to_plain] almost like Notation. unfold with [simpl]. *)
Arguments to_plain /.

Local Definition to_pks vrf_pk uid dig := to_plain vrf_pk dig !!! uid.
Arguments to_pks /.

(* after auditing, learn that client digs equal auditor digs.
also learn [mono_maps], so "apply" that in [is_staged_keys]. *)
Definition is_committed_keys vrf_pk digs uid keys :=
  Forall2 (λ dig opt_key,
    last $ to_pks vrf_pk uid dig = opt_key) digs keys.

Definition is_staged_keys vrf_pk digs uid keys next_ver :=
  ∃ last_dig,
  (* [next_ver] only has meaning with some digs. *)
  last digs = Some last_dig ∧
  in_hidden vrf_pk (merkle.inv_fn last_dig) uid next_ver None ∧
  ( mono_maps digs →
    length $ to_pks vrf_pk uid last_dig = next_ver ∧
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
  eexists. repeat (split; [done|]).
  intros Hmono.
  assert (to_pks vrf_pk uid last_dig = []) as Hnil.
  { eapply inv_fn_None_bound in Hnone as ?.
    simpl. by destruct (plain_inv_fn _ _ !!! _). }
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
  rewrite /is_staged_keys. intros (old_dig&Hold_dig&_&Hstage) Hnew_dig Hold_key Hnone.
  eexists. repeat (split; [done|]).
  intros Hmono.
  odestruct (Hstage _) as (Hver&Hkeys).
  { unfold mono_maps in *.
    rewrite fmap_app in Hmono.
    apply list_reln_app in Hmono.
    naive_solver. }
  clear Hstage.
  assert (old_key = last $ to_pks vrf_pk uid old_dig) as ->.
  { rewrite /is_committed_keys in Hkeys.
    apply Forall2_last in Hkeys.
    rewrite Hold_dig Hold_key in Hkeys.
    by inv Hkeys. }
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
    (* [S num_new] implicitly says there's at least one [new_digs]
    that has [new_key]. *)
    num_old + S num_new = length new_digs ∧
    is_staged_keys vrf_pk digs' uid keys' (S next_ver).
Proof.
  rewrite /is_staged_keys.
  intros (old_dig&Hold_dig&Hnone'&Hstage) Hnew_dig Hold_key Hsome Hnone.
  assert (last new_digs = Some new_dig) as Hnew_dig'.
  { destruct (last new_digs) eqn:Ht.
    { by rewrite last_app Ht in Hnew_dig. }
    exfalso.
    apply last_None in Ht.
    list_simplifier.
    by opose proof (in_hidden_det Hnone' Hsome). }
  clear Hnone'.

  assert (∃ grow_idx grow_dig,
    new_digs !! grow_idx = Some grow_dig ∧
    in_hidden vrf_pk (merkle.inv_fn grow_dig) uid next_ver (Some new_key) ∧
    ( mono_maps new_digs →
      ∀ j y,
        new_digs !! j = Some y →
        (j < grow_idx)%nat →
        in_hidden vrf_pk (merkle.inv_fn y) uid next_ver None ))
    as (grow_idx&grow_dig&Hgrow_dig&Hgrow_some&Hgrow_none).
  { clear -Hsome Hnew_dig'.
    destruct Hsome as (map_label&?&map_val&?).
    destruct_exis. destruct_and?.
    opose proof (list_find_elem_of
      (λ x, merkle.inv_fn x !! map_label = Some map_val)
      new_digs
      _ _ _) as ([grow_idx ?]&Hfind).
    { by apply last_Some_elem_of. }
    { done. }
    apply list_find_Some in Hfind as (Hlook_grow&?&Hfind).
    do 2 eexists.
    split; try done.
    split. { rewrite /in_hidden. naive_solver. }
    intros Hmono * Hlook_prior **.
    ospecialize (Hfind _ _ _ _); [done..|].
    eremember (merkle.inv_fn y !! _) as foo.
    assert (foo = None ∨ (∃ map_val', foo = Some map_val' ∧ map_val ≠ map_val')) as Hdec.
    { destruct foo; naive_solver. }
    subst. clear Hfind.
    rewrite /in_hidden.
    destruct Hdec; [naive_solver|].
    exfalso. destruct_exis. destruct_and?.
    eapply list_reln_trans_refl in Hmono; cycle 1.
    1-2: apply _.
    { rewrite list_lookup_fmap. by erewrite Hlook_prior. }
    { rewrite list_lookup_fmap. by erewrite Hlook_grow. }
    { lia. }
    eapply lookup_weaken in Hmono; [|done].
    by simplify_eq/=. }
  clear Hnew_dig'.

  exists grow_idx, (length new_digs - S grow_idx)%nat.
  split. { apply lookup_lt_Some in Hgrow_dig. lia. }
  eexists. do 2 (split; [done|]).
  intros Hmono.
  pose proof Hmono as Ht.
  rewrite /mono_maps fmap_app in Ht.
  apply list_reln_app in Ht as [Ht0 Ht1].
  odestruct (Hstage _) as (Hver&Hkeys); [done|].
  clear Hstage.
  ospecialize (Hgrow_none _); [done|].
  clear Ht0 Ht1.

  assert (old_key = last $ to_pks vrf_pk uid old_dig) as ->.
  { rewrite /is_committed_keys in Hkeys.
    apply Forall2_last in Hkeys.
    rewrite Hold_dig Hold_key in Hkeys.
    by inv Hkeys. }
  clear Hold_key.
  rewrite !last_lookup in Hold_dig Hnew_dig.
  eapply (lookup_app_l_Some _ new_digs) in Hold_dig.
  erewrite (lookup_app_r' digs) in Hgrow_dig.
  setoid_rewrite (lookup_app_r' digs) in Hgrow_none.

  assert (to_pks vrf_pk uid old_dig ++ [new_key] = to_pks vrf_pk uid grow_dig)
    as Heq_old_grow.
  { eapply inv_fn_None_bound in Hnone.
    opose proof (plain_mono_lookup vrf_pk uid Hmono Hold_dig Hgrow_dig _)
      as [ext_pks Hgrow_pks]; [len|].
    opose proof (plain_mono_lookup vrf_pk uid Hmono Hgrow_dig Hnew_dig _)
      as ?%prefix_length.
    { apply lookup_lt_Some in Hgrow_dig. lia. }
    rewrite Hgrow_pks. f_equal.
    destruct ext_pks.
    - exfalso.
      list_simplifier.
      rewrite -Hgrow_pks in Hgrow_some.
      clear -Hgrow_some.
      rewrite lookup_total_alt in Hgrow_some.
      destruct (_ !! uid) eqn:Hlook_uid; simpl in *.
      + opose proof (inv_fn_out_pks _ _ _ Hlook_uid) as Hpks; [done|].
        opose proof (pks_in_hidden_snoc Hpks Hgrow_some) as Hpks'.
        opose proof (inv_fn_inp_pks _ _ _ Hpks' _) as (?&?&Hpref); [done|..].
        { len. }
        list_simplifier.
        by eapply prefix_snoc_not.
      + opose proof (inv_fn_inp_pks _ [new_key] _ _ _).
        2: { by intros ?* [-> ->]%list_lookup_singleton_Some. }
        1-2: done.
        destruct_exis. destruct_and?.
        simplify_eq/=.
    - destruct ext_pks.
      2: {
        exfalso.
        apply (f_equal length) in Hgrow_pks.
        autorewrite with len in *.
        simpl in *. lia. }
      f_equal.
      apply (f_equal (.!! next_ver)) in Hgrow_pks.
      rewrite -Hver lookup_snoc Hver in Hgrow_pks.
      rewrite /= lookup_total_alt in Hgrow_pks.
      destruct (_ !! uid) eqn:Hlook_uid; simpl in *; try done.
      opose proof (inv_fn_out_lookup _ _ _ Hlook_uid Hgrow_pks) as Hsome'; [done|].
      opose proof (in_hidden_det Hgrow_some Hsome').
      by simplify_eq/=. }

  assert (to_pks vrf_pk uid grow_dig = to_pks vrf_pk uid new_dig)
    as Heq_grow_new.
  { eapply inv_fn_None_bound in Hnone.
    opose proof (plain_mono_lookup vrf_pk uid Hmono Hgrow_dig Hnew_dig _)
      as [ext_pks Hnew_pks].
    { apply lookup_lt_Some in Hgrow_dig. lia. }
    destruct ext_pks; [by list_simplifier|].
    apply (f_equal length) in Hnew_pks.
    rewrite -Heq_old_grow in Hnew_pks.
    autorewrite with len in *.
    simpl in *. lia. }
  clear Hsome Hnone Hgrow_some.

  split. { rewrite -Heq_grow_new -Heq_old_grow. len. }
  apply lookup_lt_Some in Hgrow_dig as ?.
  autorewrite with len in *.
  replace (S (_ - _)) with (length new_digs - grow_idx)%nat; [|lia].
  rewrite /is_committed_keys in Hkeys |-*.
  eapply Forall2_app; [done|].
  clear Hkeys.
  eapply Forall2_same_length_lookup.
  split; [len|].
  intros ? mid_dig * Hmid_dig Hrepl.
  rewrite (lookup_app_r' digs) in Hmid_dig.
  apply lookup_app_Some in Hrepl as [Hrepl|[? Hrepl]].
  - apply lookup_replicate in Hrepl as [-> ?].
    opose proof (Hgrow_none _ _ _ _) as Hnone; [done..|].
    clear Hgrow_none.
    eapply inv_fn_None_bound in Hnone.
    opose proof (plain_mono_lookup vrf_pk uid Hmono Hold_dig Hmid_dig _) as Hpref_reg0; [len|].
    f_equal. symmetry.
    eapply prefix_length_eq; [done|].
    simpl in *. lia.
  - apply lookup_replicate in Hrepl as [-> ?].
    autorewrite with len in *.
    opose proof (plain_mono_lookup vrf_pk uid Hmono Hgrow_dig Hmid_dig _) as Hpref_reg0; [len|].
    opose proof (plain_mono_lookup vrf_pk uid Hmono Hmid_dig Hnew_dig _) as Hpref_reg1; [len|].
    rewrite -Heq_grow_new in Hpref_reg1.
    opose proof (prefix_eq _ _ Hpref_reg0 Hpref_reg1) as <-.
    by rewrite -Heq_old_grow last_snoc.
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

(* TODO: stitch together sigs from multiple auditors,
who each have audited overlapping epoch ranges. *)
