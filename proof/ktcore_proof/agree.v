From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.
From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi hashchain merkle safemarshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  key_map sigpred staged_keys.

Module ktcore.
Import key_map.ktcore sigpred.sigpred staged_keys.ktcore.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Definition kt_ptsto γdigs vrf_pk digs_start_ep ep uid opt_pk : iProp Σ :=
  ∃ dig,
  "#Hidx_dig" ∷ mono_list_idx_own γdigs (ep - digs_start_ep) dig ∗
  "%Heq_pk" ∷ ⌜last $ ktcore.to_pks vrf_pk uid dig = opt_pk⌝.

(* [start_ep] of [keys]. *)
Definition is_staged_keys γcli uid start_ep keys : iProp Σ :=
  ∃ digs next_ver,
  let n_drop := (start_ep - start_epγ γcli)%nat in
  "#Hlb_digs" ∷ mono_list_lb_own γcli.(cfg.digs) digs ∗
  "%Hstaged" ∷ ⌜staged_keys γcli.(cfg.vrf_pk) (drop n_drop digs)
    uid keys next_ver⌝ ∗

  "%Hlt_start" ∷ ⌜start_epγ γcli ≤ start_ep⌝.

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

Lemma commit_staged γcli uid keys_start_ep keys γadtr audit_ep :
  is_staged_keys γcli uid keys_start_ep keys -∗
  is_audit γcli γadtr audit_ep -∗
  ⌜start_epγ γadtr + audit_offsetγ γadtr ≤ keys_start_ep⌝ -∗
  ⌜keys_start_ep + length keys ≤ S audit_ep⌝ -∗
  (∀ i opt_pk,
    let ep := (keys_start_ep + i)%nat in
    ⌜keys !! i = Some opt_pk⌝ -∗
    γadtr.(cfg.digs) ↪KT[γadtr.(cfg.vrf_pk), start_epγ γadtr, ep, uid] opt_pk).
Proof.
  iIntros "@ #Haudit %% * %Hlook_keys".
  apply lookup_lt_Some in Hlook_keys as ?.
  iApply kt_ptsto_txfer; [|done|word].
  iNamed "Haudit". rewrite /kt_ptsto.
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
    eremember (keys_start_ep - _)%nat as n_drop.
    rewrite -(take_drop (n_drop - audit_offsetγ γadtr) (drop _ _))
      drop_drop in Hmono_plain.
    replace (_ + _)%nat with n_drop in Hmono_plain; [|lia].
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

(* this lemma needs to return a new γadtr:
- need to use γdigs of γadtr1, for the mlist_lb.
- but to get the expanded range, need audit_offset of γadtr0.

with new γadtr, need to weaken kt_ptsto_agree:
- suppose alice and bob both trust A0, A1, A2.
- alice uses A0 + A2. bob uses A1 + A2.
A0 and A1 have different audit_offset's.
- then they'll end up with different audit_offset's.
and won't be able to use curr kt_ptsto_agree. *)
Lemma combine_audits γcli γadtr0 γadtr1 audit_ep0 audit_ep1 :
  is_audit γcli γadtr0 audit_ep0 -∗
  is_audit γcli γadtr1 audit_ep1 -∗
  ⌜start_epγ γadtr0 + audit_offsetγ γadtr0 ≤
    start_epγ γadtr1 + audit_offsetγ γadtr1 ≤ audit_ep0⌝ -∗
  ⌜audit_ep0 ≤ audit_ep1⌝ -∗
  let new_γadtr := set cfg.info (set digs_info.audit_offset
    (λ _, audit_offsetγ γadtr0)) γadtr1 in
  is_audit γcli new_γadtr audit_ep1.
Proof. Admitted.

End proof.
End ktcore.
