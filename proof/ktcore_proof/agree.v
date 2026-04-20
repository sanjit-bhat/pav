From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.
From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi hashchain merkle safemarshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  key_map sigpred staged_keys.

Module ktcore.
Import key_map.ktcore sigpred.sigpred staged_keys.ktcore.

(* TODO: upstream. *)
Lemma last_drop_Some {A} (l : list A) x n :
  last l = Some x →
  (n < length l)%nat →
  last (drop n l) = Some x.
Proof.
  intros (?&->)%last_Some ?.
  autorewrite with len in *.
  rewrite drop_app_le; [|lia].
  by rewrite last_snoc.
Qed.

(* TODO: upstream. *)
Lemma list_reln_snoc' {A} R (l : list A) a :
  list_reln (l ++ [a]) R → list_reln l R.
Proof.
  rewrite /list_reln. intros Hr * Hlook0 Hlook1.
  eapply lookup_app_l_Some in Hlook0, Hlook1.
  by eapply Hr.
Qed.

(* TODO: upstream. *)
Lemma list_reln_app' {A} R (l0 : list A) l1 :
  list_reln l0 R →
  list_reln l1 R →
  (∀ x0 x1, last l0 = Some x0 → head l1 = Some x1 → R x0 x1) →
  list_reln (l0 ++ l1) R.
Proof.
  intros Hl0. induction l1 using rev_ind; [by list_simplifier|].
  intros Hl1 Hr.
  rewrite (assoc _).
  apply list_reln_snoc.
  - apply IHl1.
    + by eapply list_reln_snoc'.
    + intros * ? Hhead. eapply Hr; [done|].
      by rewrite head_snoc Hhead.
  - clear IHl1.
    destruct l1 using rev_ind; [|clear IHl1].
    + list_simplifier.
      intros **. by apply Hr.
    + rewrite (assoc _) last_snoc.
      intros **. simplify_eq/=.
      rewrite -(assoc _) in Hl1.
      apply list_reln_app in Hl1 as [_ Hl1].
      rewrite /list_reln in Hl1.
      by eapply (Hl1 0%nat).
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

(* a simpler (but too weak for multi-auditor) way to state this is with
(γsigpred, ep, uid, opt_pk). *)
Definition kt_ptsto γdigs vrf_pk digs_start_ep ep uid opt_pk : iProp Σ :=
  ∃ dig,
  "#Hidx_dig" ∷ mono_list_idx_own γdigs (ep - digs_start_ep) dig ∗
  "%Heq_pk" ∷ ⌜last $ ktcore.to_pks vrf_pk uid dig = opt_pk⌝.

(* (ab)use sigpred.cfg for Client, even tho it's not an Auditor.
audit_offset is when Client started tracking its own key. *)
Definition is_staged_keys γcli uid keys : iProp Σ :=
  ∃ digs next_ver,
  "#Hlb_digs" ∷ mono_list_lb_own γcli.(cfg.digs) digs ∗
  "%Hstaged" ∷ ⌜staged_keys γcli.(cfg.vrf_pk) (drop (audit_offsetγ γcli) digs)
    uid keys next_ver⌝.

Definition is_audit γcli γadtr ep : iProp Σ :=
  ∃ (digs : list $ list w8),
  "#Hcli_digs" ∷ mono_list_lb_own γcli.(cfg.digs) digs ∗
  "#Hadtr_digs" ∷ mono_list_lb_own γadtr.(cfg.digs) digs ∗
  "%Hlen_digs" ∷ ⌜Z.of_nat $ length digs = S ep - start_epγ γcli⌝ ∗
  "%Hmono_plain" ∷ ⌜mono_plain γadtr.(cfg.vrf_pk)
    (drop (audit_offsetγ γadtr) digs)⌝ ∗

  "%Heq_vrf" ∷ ⌜γcli.(cfg.vrf_pk) = γadtr.(cfg.vrf_pk)⌝ ∗
  "%Heq_start" ∷ ⌜start_epγ γcli = start_epγ γadtr⌝ ∗
  "%Heq_cut" ∷ ⌜γcli.(cfg.info).(digs_info.cut) =
    γadtr.(cfg.info).(digs_info.cut)⌝.

End proof.

Global Notation "γdigs ↪KT[ vrf_pk , digs_start_ep , ep , uid ] opt_pk" :=
  (kt_ptsto γdigs vrf_pk digs_start_ep ep uid opt_pk)
  (at level 20, format "γdigs  ↪KT[ vrf_pk ,  digs_start_ep ,  ep ,  uid ]  opt_pk").

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Lemma kt_ptsto_agree γdigs vrf_pk digs_start_ep ep uid opt_pk0 opt_pk1 :
  γdigs ↪KT[vrf_pk, digs_start_ep, ep, uid] opt_pk0 -∗
  γdigs ↪KT[vrf_pk, digs_start_ep, ep, uid] opt_pk1 -∗
  ⌜opt_pk0 = opt_pk1⌝.
Proof.
  iNamedSuffix 1 "0". iNamedSuffix 1 "1".
  iDestruct (mono_list_idx_agree with "Hidx_dig0 Hidx_dig1") as %->.
  by subst.
Qed.

Lemma kt_ptsto_txfer γcli γadtr ep uid opt_pk audit_ep :
  γcli.(cfg.digs) ↪KT[γcli.(cfg.vrf_pk), start_epγ γcli, ep, uid] opt_pk -∗
  is_audit γcli γadtr audit_ep -∗
  ⌜γadtr.(cfg.info).(digs_info.start_ep) +
    γadtr.(cfg.info).(digs_info.audit_offset) ≤ ep ≤ audit_ep⌝ -∗
  γadtr.(cfg.digs) ↪KT[γadtr.(cfg.vrf_pk), start_epγ γadtr, ep, uid] opt_pk.
Proof.
  iIntros "@@%". rewrite /kt_ptsto.
  eremember (ep - _)%nat as ep_t.
  list_elem digs ep_t as dig'. subst.
  iDestruct (mono_list_idx_own_get with "Hcli_digs") as "Hlook"; [done|].
  iDestruct (mono_list_idx_agree with "Hidx_dig Hlook") as %<-.
  iClear "Hlook".
  iDestruct (mono_list_idx_own_get with "Hadtr_digs") as "Hlook"; [done|].
  rewrite Heq_vrf Heq_start.
  by iFrame "#".
Qed.

Lemma commit_staged γcli uid keys γadtr audit_ep :
  let keys_start_ep := (start_epγ γcli + audit_offsetγ γcli)%nat in
  is_staged_keys γcli uid keys -∗
  is_audit γcli γadtr audit_ep -∗
  ⌜audit_offsetγ γadtr ≤ audit_offsetγ γcli⌝ -∗
  ⌜keys_start_ep + length keys ≤ S audit_ep⌝ -∗
  (∀ i opt_pk,
    let ep := (keys_start_ep + i)%nat in
    ⌜keys !! i = Some opt_pk⌝ -∗
    γadtr.(cfg.digs) ↪KT[γadtr.(cfg.vrf_pk), start_epγ γadtr, ep, uid] opt_pk).
Proof.
  simpl. iIntros "@ #Haudit %% * %Hlook_keys".
  apply lookup_lt_Some in Hlook_keys as ?.
  iPoseProof "Haudit" as "@".
  iApply kt_ptsto_txfer; [|done|word].
  iClear "Haudit". rewrite /kt_ptsto.
  destruct Hstaged as (?&Hlast_digs&_&?&Hstaged).
  rewrite last_lookup in Hlast_digs.
  apply lookup_lt_Some in Hlast_digs.
  autorewrite with len in *.
  iAssert (⌜digs `prefix_of` digs0⌝)%I as %(adtr_digs&->).
  { iDestruct (mono_list_lb_valid with "Hlb_digs Hcli_digs")
      as %[?|Hpref]; [done|].
    by apply prefix_length_eq in Hpref as ->; [|lia]. }
  iClear "Hcli_digs Hadtr_digs".
  autorewrite with len in *.

  odestruct (Hstaged _) as (_&->).
  { rewrite drop_app_le in Hmono_plain; [|word].
    rewrite -(take_drop (audit_offsetγ γcli - audit_offsetγ γadtr) (drop _ _))
      drop_drop in Hmono_plain.
    replace (_ + _)%nat with (audit_offsetγ γcli) in Hmono_plain; [|lia].
    list_simplifier.
    rewrite /mono_plain !fmap_app in Hmono_plain |-*.
    apply list_reln_app in Hmono_plain as [_ Hmono].
    apply list_reln_app in Hmono as [Hmono _].
    by rewrite Heq_vrf. }
  clear Hstaged.

  apply list_lookup_fmap_Some in Hlook_keys as (dig&->&Hlook_digs).
  iExists _. iSplit; [|done].
  iApply mono_list_idx_own_get; [|done].
  rewrite lookup_drop in Hlook_digs.
  exact_eq Hlook_digs. f_equal. lia.
Qed.

(* this lemma expects adtr0 to come before adtr1.
return new γadtr bc we need audit_offset of γadtr0 and digs of γadtr1.
NOTE: for two clients to agree, they need the same γdigs.
therefore, their combine sequences need to end with same auditor.
without hashchain inversion, not sure how to do multi-auditor agreement.
there's no final Auditor with all the digs. *)
Lemma combine_audits γcli γadtr0 γadtr1 audit_ep0 audit_ep1 :
  is_audit γcli γadtr0 audit_ep0 -∗
  is_audit γcli γadtr1 audit_ep1 -∗
  ⌜audit_offsetγ γadtr0 ≤ audit_offsetγ γadtr1⌝ -∗
  ⌜start_epγ γadtr1 + audit_offsetγ γadtr1 ≤ audit_ep0⌝ -∗
  ⌜audit_ep0 ≤ audit_ep1⌝ -∗
  let new_γadtr :=
    γadtr1 <| cfg.info; digs_info.audit_offset := audit_offsetγ γadtr0 |> in
  is_audit γcli new_γadtr audit_ep1.
Proof.
  iNamedSuffix 1 "0". iNamedSuffix 1 "1". iIntros "%%%".
  rewrite /is_audit /=. iFrame "Hadtr_digs1 #%".
  iAssert (⌜digs `prefix_of` digs0⌝)%I as %(new_digs&->).
  { iDestruct (mono_list_lb_valid with "Hcli_digs0 Hcli_digs1")
      as %[?|Hpref]; [done|].
    by apply prefix_length_eq in Hpref as ->; [|lia]. }
  iPureIntro.
  autorewrite with len in *.
  rewrite !drop_app_le in Hmono_plain1 |-*; [|word..].
  rewrite /mono_plain !fmap_app in Hmono_plain0 Hmono_plain1 |-*.
  rewrite -Heq_vrf0 Heq_vrf1 in Hmono_plain0.
  pose proof Hmono_plain1 as Ht.
  apply list_reln_app in Ht as [_ Hmono].
  apply list_reln_app'; [done..|].

  intros * Hlook0 Hlook1.
  apply (last_drop_Some _ _ (audit_offsetγ γadtr1 - audit_offsetγ γadtr0))
    in Hlook0; [|len].
  rewrite -!fmap_drop drop_drop in Hlook0.
  replace (_ + _)%nat with (audit_offsetγ γadtr1) in Hlook0 by word.
  rewrite last_lookup in Hlook0.
  rewrite head_lookup in Hlook1.
  eapply list_reln_trans.
  - apply _.
  - exact Hmono_plain1.
  - by apply lookup_app_l_Some.
  - by erewrite lookup_app_r' in Hlook1.
  - len.
Qed.

End proof.
End ktcore.
