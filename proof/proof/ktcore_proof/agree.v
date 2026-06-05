From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.
From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi hashchain merkle safemarshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  key_map staged_keys.

Module ktcore.
Import key_map.ktcore staged_keys.ktcore.

Module Agree.
Record t :=
  mk {
    (* core params needed for two parties to agree on the latest key
    at some (epoch, uid). *)
    vrf_pk : list w8;
    (* ptr to mono_list of digs. *)
    digs : gname;
    (* epoch of first dig. *)
    digs_start : nat;

    (* hashchain cut prior to digs. *)
    cut : option $ list w8;
    (* offset into digs when a party started its functionality.
    for Auditors, when they started checking map mono.
    for Clients, when they started checking their own key history. *)
    func_start : nat;
  }.
End Agree.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Definition kt_ptsto γ ep uid opt_pk : iProp Σ :=
  ∃ dig,
  "#Hidx_dig" ∷ mono_list_idx_own γ.(Agree.digs) (ep - γ.(Agree.digs_start)) dig ∗
  "%Heq_pk" ∷ ⌜last $ ktcore.to_pks γ.(Agree.vrf_pk) uid dig = opt_pk⌝.

Definition is_staged_keys γcli uid keys : iProp Σ :=
  ∃ digs next_ver,
  "#Hlb_digs" ∷ mono_list_lb_own γcli.(Agree.digs) digs ∗
  "%Hstaged" ∷ ⌜staged_keys γcli.(Agree.vrf_pk) (drop γcli.(Agree.func_start) digs)
    uid keys next_ver⌝.

(* is_audit is an audit thru epoch [ep]. *)
Definition is_audit γcli γadtr ep : iProp Σ :=
  ∃ (digs : list $ list w8),
  "#Hcli_digs" ∷ mono_list_lb_own γcli.(Agree.digs) digs ∗
  "#Hadtr_digs" ∷ mono_list_lb_own γadtr.(Agree.digs) digs ∗
  "%Hlen_digs" ∷ ⌜Z.of_nat $ length digs = S ep - γcli.(Agree.digs_start)⌝ ∗
  "%Hmono_plain" ∷ ⌜mono_plain γadtr.(Agree.vrf_pk)
    (drop γadtr.(Agree.func_start) digs)⌝ ∗

  "%Heq_vrf" ∷ ⌜γcli.(Agree.vrf_pk) = γadtr.(Agree.vrf_pk)⌝ ∗
  "%Heq_start" ∷ ⌜γcli.(Agree.digs_start) = γadtr.(Agree.digs_start)⌝ ∗
  "%Heq_cut" ∷ ⌜γcli.(Agree.cut) = γadtr.(Agree.cut)⌝.

End proof.

Local Notation "γ ↪KT[ ep , uid ] opt_pk" :=
  (kt_ptsto γ ep uid opt_pk)
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
  intros. iNamedSuffix 1 "0". iNamedSuffix 1 "1".
  iDestruct (mono_list_idx_agree with "Hidx_dig0 Hidx_dig1") as %->.
  by subst.
Qed.

Lemma kt_ptsto_txfer γcli γadtr ep uid opt_pk audit_ep :
  γcli ↪KT[ep, uid] opt_pk -∗
  is_audit γcli γadtr audit_ep -∗
  ⌜γadtr.(Agree.digs_start) + γadtr.(Agree.func_start) ≤ ep ≤ audit_ep⌝ -∗
  γadtr ↪KT[ep, uid] opt_pk.
Proof.
  simpl. iIntros "@@%". rewrite /kt_ptsto.
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
  let keys_start_ep := (γcli.(Agree.digs_start) + γcli.(Agree.func_start))%nat in
  γadtr.(Agree.func_start) ≤ γcli.(Agree.func_start) →
  keys_start_ep + length keys ≤ S audit_ep →
  is_staged_keys γcli uid keys -∗
  is_audit γcli γadtr audit_ep -∗
  (∀ i opt_pk,
    let ep := (keys_start_ep + i)%nat in
    ⌜keys !! i = Some opt_pk⌝ -∗
    γadtr ↪KT[ep, uid] opt_pk).
Proof.
  simpl. iIntros "%% @ #Haudit * %Hlook_keys".
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
    rewrite -(take_drop (γcli.(Agree.func_start) - γadtr.(Agree.func_start)) (drop _ _))
      drop_drop in Hmono_plain.
    replace (_ + _)%nat with (γcli.(Agree.func_start)) in Hmono_plain; [|lia].
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

(* combine_audits takes in adtr0 that started before adtr1,
but still overlaps in auditing range.
it returns new adtr with audit_start of adtr0 and digs of adtr1.
NOTE: for two clients to agree, they need the same γdigs.
therefore, their combine sequences need to end with same auditor.
NOTE: without hashchain inversion, not sure how to do multi-auditor agreement.
there's no final Auditor with all the digs. *)
Lemma combine_audits γcli γadtr0 γadtr1 audit_ep0 audit_ep1 :
  γadtr0.(Agree.func_start) ≤ γadtr1.(Agree.func_start) →
  (γadtr1.(Agree.digs_start) + γadtr1.(Agree.func_start) ≤ audit_ep0)%nat →
  (audit_ep0 ≤ audit_ep1)%nat →
  is_audit γcli γadtr0 audit_ep0 -∗
  is_audit γcli γadtr1 audit_ep1 -∗
  let new_γadtr :=
    γadtr1 <| Agree.func_start := γadtr0.(Agree.func_start) |> in
  is_audit γcli new_γadtr audit_ep1.
Proof.
  simpl. iIntros "%%%". iNamedSuffix 1 "0". iNamedSuffix 1 "1".
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
  apply (last_drop_Some _ _
    (γadtr1.(Agree.func_start) - γadtr0.(Agree.func_start)))
    in Hlook0; [|len].
  rewrite -!fmap_drop drop_drop in Hlook0.
  replace (_ + _)%nat with (γadtr1.(Agree.func_start)) in Hlook0 by word.
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

Global Notation "γ ↪KT[ ep , uid ] opt_pk" :=
  (ktcore.kt_ptsto γ ep uid opt_pk)
  (at level 20, format "γ  ↪KT[ ep ,  uid ]  opt_pk").
