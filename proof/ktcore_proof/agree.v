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

Definition kt_ptsto γ ep uid opt_pk : iProp Σ :=
  ∃ dig,
  "#Hidx_dig" ∷ mono_list_idx_own γ.(cfg.digs)
    (ep - γ.(cfg.info).(digs_info.start_ep)) dig ∗
  "%Heq_pk" ∷ ⌜last $ ktcore.to_pks γ.(cfg.vrf_pk) uid dig = opt_pk⌝.

(* [start_ep] of [keys]. *)
Definition is_staged_keys γcli uid start_ep keys : iProp Σ :=
  ∃ digs next_ver,
  let n_drop := (start_ep - γcli.(cfg.info).(digs_info.start_ep))%nat in
  "#Hlb_digs" ∷ mono_list_lb_own γcli.(cfg.digs) digs ∗
  "%Hstaged" ∷ ⌜staged_keys γcli.(cfg.vrf_pk) (drop n_drop digs)
    uid keys next_ver⌝ ∗

  "%Hlt_start" ∷ ⌜γcli.(cfg.info).(digs_info.start_ep) ≤ start_ep⌝.

Definition is_audit γcli γadtr ep : iProp Σ :=
  ∃ (digs : list $ list w8),
  "#Hcli_digs" ∷ mono_list_lb_own γcli.(cfg.digs) digs ∗
  "#Hadtr_digs" ∷ mono_list_lb_own γadtr.(cfg.digs) digs ∗
  "%Hlen_digs" ∷ ⌜Z.of_nat $ length digs =
    S ep - γcli.(cfg.info).(digs_info.start_ep)⌝ ∗
  "%Hmono_plain" ∷ ⌜mono_plain γadtr.(cfg.vrf_pk)
    (drop γadtr.(cfg.info).(digs_info.audit_offset) digs)⌝ ∗

  "%Heq_vrf" ∷ ⌜γcli.(cfg.vrf_pk) = γadtr.(cfg.vrf_pk)⌝ ∗
  "%Heq_start" ∷ ⌜γcli.(cfg.info).(digs_info.start_ep) =
    γadtr.(cfg.info).(digs_info.start_ep)⌝ ∗
  "%Heq_cut" ∷ ⌜γcli.(cfg.info).(digs_info.cut) =
    γadtr.(cfg.info).(digs_info.cut)⌝.

End proof.

Global Notation "γ ↪KT[ ep , uid ] opt_pk" := (kt_ptsto γ ep uid opt_pk)
  (at level 20, format "γ  ↪KT[ ep ,  uid ]  opt_pk").

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Lemma kt_ptsto_agree γ ep uid opt_pk0 opt_pk1 :
  γ ↪KT[ep, uid] opt_pk0 -∗
  γ ↪KT[ep, uid] opt_pk1 -∗
  ⌜opt_pk0 = opt_pk1⌝.
Proof.
  iNamedSuffix 1 "0". iNamedSuffix 1 "1".
  iDestruct (mono_list_idx_agree with "Hidx_dig0 Hidx_dig1") as %->.
  by subst.
Qed.

Lemma kt_ptsto_txfer γcli γadtr ep uid opt_pk audit_ep :
  γcli ↪KT[ep, uid] opt_pk -∗
  is_audit γcli γadtr audit_ep -∗
  ⌜γadtr.(cfg.info).(digs_info.start_ep) +
    γadtr.(cfg.info).(digs_info.audit_offset) ≤ ep ≤ audit_ep⌝ -∗
  γadtr ↪KT[ep, uid] opt_pk.
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
  ⌜γadtr.(cfg.info).(digs_info.start_ep) +
    γadtr.(cfg.info).(digs_info.audit_offset) ≤ keys_start_ep⌝ -∗
  ⌜keys_start_ep + length keys ≤ S audit_ep⌝ -∗
  (∀ i opt_pk,
    let ep := (keys_start_ep + i)%nat in
    ⌜keys !! i = Some opt_pk⌝ -∗
    γadtr ↪KT[ep, uid] opt_pk).
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
    rewrite -(take_drop
      (n_drop - γadtr.(cfg.info).(digs_info.audit_offset))
      (drop _ _)) drop_drop in Hmono_plain.
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

End proof.
End ktcore.
