From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.
From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi hashchain merkle safemarshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  key_map.

Module ktcore.
Import key_map.ktcore.

(* TODO: upstream. *)
Lemma list_reln_app {A} R (l0 l1 : list A) :
  list_reln (l0 ++ l1) R →
  list_reln l0 R ∧ list_reln l1 R.
Proof.
  rewrite /list_reln. intros Happ. split.
  - intros i x y Hx Hy.
    eapply Happ.
    + rewrite lookup_app_l; [done|eapply lookup_lt_Some; done].
    + rewrite lookup_app_l; [done|eapply lookup_lt_Some; done].
  - intros i x y Hx Hy.
    apply (Happ (i + length l0)%nat).
    + rewrite lookup_app_r; last lia.
      replace (i + length l0 - length l0)%nat with i by lia. done.
    + rewrite lookup_app_r; last lia.
      replace (S (i + length l0) - length l0)%nat with (S i) by lia. done.
Qed.

Lemma lookup_app_r' {A} (l1 l2 : list A) i :
  l2 !! i = (l1 ++ l2) !! (i + length l1)%nat.
Proof. rewrite lookup_app_r; [|lia]. f_equal. lia. Qed.

Lemma prefix_eq {A} (l1 l2 : list A) :
  l1 `prefix_of` l2 →
  l2 `prefix_of` l1 →
  l1 = l2.
Proof. intros ? ?%prefix_length. by apply prefix_length_eq. Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Definition is_staged_keys vrf_pk digs uid keys next_ver :=
  ∃ last_dig,
  (* [next_ver] only has meaning with some digs. *)
  last digs = Some last_dig ∧
  (* need unconditional [next_ver] knowledge to prove that
  [is_staged_keys_grow_new] unconditionally produces [new_dig]. *)
  in_hidden vrf_pk (merkle.inv_fn last_dig) uid next_ver None ∧
  ( mono_plain vrf_pk digs →
    length $ to_pks vrf_pk uid last_dig = next_ver ∧
    keys = last <$> ((λ x, to_pks vrf_pk uid x) <$> digs) ).

Lemma is_staged_init vrf_pk dig uid :
  in_hidden vrf_pk (merkle.inv_fn dig) uid 0 None →
  is_staged_keys vrf_pk [dig] uid [None] 0.
Proof.
  rewrite /is_staged_keys /=. intros Hnone.
  eexists. repeat (split; [done|]).
  intros Hmono.
  assert (to_pks vrf_pk uid dig = []) as ->; [|done].
  eapply inv_fn_None_bound in Hnone as ?.
  by destruct (plain_inv_fn _ _ !!! _).
Qed.

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
  odestruct (Hstage _) as (Hver&->).
  { unfold mono_plain in *.
    rewrite !fmap_app in Hmono.
    apply list_reln_app in Hmono.
    naive_solver. }
  clear Hstage.
  assert (old_key = last $ to_pks vrf_pk uid old_dig) as ->.
  { rewrite !fmap_last Hold_dig in Hold_key.
    by simplify_eq/=. }
  rewrite !last_lookup in Hold_dig Hnew_dig.
  eapply lookup_app_l_Some in Hold_dig.
  eassert (to_pks vrf_pk uid old_dig = to_pks vrf_pk uid new_dig) as Heq_pks.
  { opose proof (mono_plain_lookup uid Hmono Hold_dig Hnew_dig _) as ?; [len|].
    eapply inv_fn_None_bound in Hnone.
    eapply prefix_length_eq; [done|].
    simpl in *. lia. }
  clear Hold_key Hnone.

  (* approach: bring all facts to plain maps layer,
  then do the core reasoning there. *)
  split. { by rewrite -Heq_pks. }
  list_simplifier. f_equal.
  eapply list_eq_same_length; [done|len|].
  intros * _ Hrepl Hlook_mid.
  apply lookup_replicate in Hrepl as [-> ?].
  apply list_lookup_fmap_Some in Hlook_mid as (?&->&Hlook_mid).
  apply list_lookup_fmap_Some in Hlook_mid as (mid_dig&->&Hlook_mid).
  rewrite (lookup_app_r' digs) in Hlook_mid.
  opose proof (mono_plain_lookup uid Hmono Hold_dig Hlook_mid _) as Hpref_reg0; [len|].
  opose proof (mono_plain_lookup uid Hmono Hlook_mid Hnew_dig _) as Hpref_reg1; [len|].
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

  assert (
    mono_plain vrf_pk (digs ++ new_digs) →
    to_pks vrf_pk uid old_dig ++ [new_key] = to_pks vrf_pk uid new_dig) as Heq_old_new.
  { intros Hmono.
    odestruct (Hstage _) as (Hver&Hkeys).
    { unfold mono_plain in *.
      rewrite /mono_plain !fmap_app in Hmono.
      by apply list_reln_app in Hmono as []. }
    clear Hstage.
    rewrite !last_lookup in Hold_dig Hnew_dig.
    eapply (lookup_app_l_Some _ new_digs) in Hold_dig.
    opose proof (mono_plain_lookup uid Hmono Hold_dig Hnew_dig _)
      as [ext_pks Hgrow_pks]; [len|].
    rewrite Hgrow_pks. f_equal.
    destruct ext_pks as [|new_key'].
    - exfalso.
      list_simplifier.
      rewrite lookup_total_alt in Hgrow_pks.
      destruct (_ !! uid) as [pks|] eqn:Heq_pks; simpl in *.
      + subst.
        opose proof (inv_fn_inp_pks _ (_ ++ [_]) _ _ _) as (?&?&?%prefix_length).
        2: {
          apply pks_in_hidden_snoc; [|done].
          by eapply inv_fn_out_pks. }
        { done. }
        { len. }
        simplify_eq/=.
        autorewrite with len in *.
        lia.
      + rewrite -Hgrow_pks in Hnone Hsome. simpl in *.
        opose proof (inv_fn_inp_pks _ [new_key] _ _ _).
        2: { by intros ?* [-> ->]%list_lookup_singleton_Some. }
        1-2: done.
        destruct_exis. destruct_and?.
        simplify_eq/=.
    - destruct ext_pks.
      2: {
        exfalso.
        apply (f_equal length) in Hgrow_pks.
        autorewrite with len in *.
        eapply inv_fn_None_bound in Hnone.
        simpl in *. lia. }
      f_equal.
      apply (f_equal (.!! next_ver)) in Hgrow_pks.
      rewrite -Hver lookup_snoc Hver in Hgrow_pks.
      rewrite /= lookup_total_alt in Hgrow_pks.
      destruct (_ !! uid) eqn:Hlook_uid; simpl in *; try done.
      opose proof (inv_fn_out_lookup _ _ _ Hlook_uid Hgrow_pks) as Hsome'; [done|].
      opose proof (in_hidden_det Hsome Hsome').
      by simplify_eq/=. }

  destruct (list_find
    (λ dig, length $ to_pks vrf_pk uid dig = S next_ver)
    new_digs) as [[grow_idx grow_dig]|] eqn:Hfind.
  2: {
    exists (length new_digs - 1)%nat, 0%nat.
    split.
    { rewrite last_lookup in Hnew_dig'.
      apply lookup_lt_Some in Hnew_dig'.
      lia. }
    rewrite last_app Hnew_dig'.
    eexists.
    do 2 (split; [done|]).

    intros Hmono. exfalso.
    apply list_find_None in Hfind.
    eapply Forall_lookup_1 in Hfind as Hnew_len; cycle 1.
    { by erewrite <-last_lookup. }
    clear Hnew_dig' Hfind.
    ospecialize (Heq_old_new _); [done|].
    odestruct (Hstage _) as (Hver&Hkeys).
    { unfold mono_plain in *.
      rewrite /mono_plain !fmap_app in Hmono.
      by apply list_reln_app in Hmono as []. }
    clear Hstage.
    apply (f_equal length) in Heq_old_new.
    autorewrite with len in *. lia. }
  clear Hnew_dig'.

  apply list_find_Some in Hfind as (Hgrow_dig&Hgrow_len&Hfind).
  exists grow_idx, (length new_digs - S grow_idx)%nat.
  split. { apply lookup_lt_Some in Hgrow_dig. lia. }
  eexists. do 2 (split; [done|]).
  clear Hsome Hnone.
  intros Hmono.
  ospecialize (Heq_old_new _); [done|].
  odestruct (Hstage _) as (Hver&->).
  { unfold mono_plain in *.
    rewrite /mono_plain !fmap_app in Hmono.
    by apply list_reln_app in Hmono as []. }
  clear Hstage.
  split.
  { apply (f_equal length) in Heq_old_new.
    autorewrite with len in *. lia. }

  assert (old_key = last $ to_pks vrf_pk uid old_dig) as ->.
  { rewrite !fmap_last Hold_dig in Hold_key.
    by simplify_eq/=. }
  clear Hold_key.
  rewrite !last_lookup in Hold_dig Hnew_dig.
  eapply (lookup_app_l_Some _ new_digs) in Hold_dig.
  erewrite (lookup_app_r' digs) in Hgrow_dig.
  setoid_rewrite (lookup_app_r' digs) in Hfind.

  apply lookup_lt_Some in Hgrow_dig as ?.
  autorewrite with len in *.
  replace (S (_ - _)) with (length new_digs - grow_idx)%nat; [|lia].
  list_simplifier. f_equal.
  eapply list_eq_same_length; [done|len|].
  intros * _ Hrepl Hlook_mid.
  apply list_lookup_fmap_Some in Hlook_mid as (?&->&Hlook_mid).
  apply list_lookup_fmap_Some in Hlook_mid as (mid_dig&->&Hmid_dig).
  rewrite (lookup_app_r' digs) in Hmid_dig.
  apply lookup_app_Some in Hrepl as [Hrepl|[? Hrepl]].
  - apply lookup_replicate in Hrepl as [-> ?].
    opose proof (Hfind _ _ _ _) as Hnone; [done..|].
    opose proof (mono_plain_lookup uid Hmono Hold_dig Hmid_dig _) as [ext_pks Hgrow_pks]; [len|].
    rewrite Hgrow_pks.
    opose proof (mono_plain_lookup uid Hmono Hmid_dig Hgrow_dig _) as ?%prefix_length; [len|].
    apply (f_equal length) in Hgrow_pks.
    autorewrite with len in *.
    assert (length ext_pks = 0%nat) as ?%nil_length_inv by lia.
    by list_simplifier.
  - apply lookup_replicate in Hrepl as [-> ?].
    autorewrite with len in *.
    opose proof (mono_plain_lookup uid Hmono Hgrow_dig Hmid_dig _) as ?%prefix_length; [len|].
    opose proof (mono_plain_lookup uid Hmono Hmid_dig Hnew_dig _) as [ext_pks Hgrow_pks]; [len|].
    rewrite {}Hgrow_pks in Heq_old_new.
    apply (f_equal length) in Heq_old_new as ?.
    autorewrite with len in *.
    assert (length ext_pks = 0%nat) as ?%nil_length_inv by lia.
    list_simplifier.
    by rewrite -Heq_old_new last_snoc.
Qed.

End proof.
End ktcore.
