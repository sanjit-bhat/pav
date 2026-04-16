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

Local Definition kt_ptsto γ ep uid opt_pk : iProp Σ :=
  ∃ dig,
  "#Hlook_dig" ∷ mono_list_idx_own γ.(cfg.digs) ep dig ∗
  "%Heq_pk" ∷ ⌜last $ ktcore.to_pks γ.(cfg.vrf_pk) uid dig = opt_pk⌝.

Definition is_staged γcli uid keys_start_ep keys : iProp Σ :=
  ∃ digs next_ver,
  let n_drop := (keys_start_ep - γcli.(cfg.info).(digs_info.start_ep))%nat in
  "#Hlb_digs" ∷ mono_list_lb_own γcli.(cfg.digs) digs ∗
  "%Hstaged" ∷ ⌜is_staged_keys γcli.(cfg.vrf_pk) (drop n_drop digs)
    uid keys next_ver⌝ ∗

  "%Hlt_start" ∷ ⌜γcli.(cfg.info).(digs_info.start_ep) ≤ keys_start_ep⌝.

Definition is_audit γcli γadtr end_ep : iProp Σ :=
  ∃ (digs : list $ list w8),
  "#Hcli_digs" ∷ mono_list_lb_own γcli.(cfg.digs) digs ∗
  "#Hadtr_digs" ∷ mono_list_lb_own γadtr.(cfg.digs) digs ∗
  "%Hlen_digs" ∷ ⌜length digs =
    (S end_ep - γcli.(cfg.info).(digs_info.start_ep))%nat⌝ ∗
  "%Hmono_plain" ∷ ⌜mono_plain γadtr.(cfg.vrf_pk)
    (drop γadtr.(cfg.info).(digs_info.audit_offset) digs)⌝ ∗

  "%Heq_vrf" ∷ ⌜γcli.(cfg.vrf_pk) = γadtr.(cfg.vrf_pk)⌝ ∗
  "%Heq_start" ∷ ⌜γcli.(cfg.info).(digs_info.start_ep) =
    γadtr.(cfg.info).(digs_info.start_ep)⌝ ∗
  "%Heq_cut" ∷ ⌜γcli.(cfg.info).(digs_info.cut) =
    γadtr.(cfg.info).(digs_info.cut)⌝.

End proof.

Global Notation "γ ↪KT[ ep , uid ] opt_pk" :=
  (kt_ptsto γ ep uid opt_pk) (at level 20).

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
  iDestruct (mono_list_idx_agree with "Hlook_dig0 Hlook_dig1") as %->.
  by subst.
Qed.

Lemma kt_ptsto_txfer γcli γadtr ep uid opt_pk end_ep :
  γcli ↪KT[ep, uid] opt_pk -∗
  is_audit γcli γadtr end_ep -∗
  ⌜(γadtr.(cfg.info).(digs_info.start_ep) +
    γadtr.(cfg.info).(digs_info.audit_offset) ≤ ep ≤ end_ep)%nat⌝ -∗
  γadtr ↪KT[ep, uid] opt_pk.
Proof. Admitted.

End proof.
End ktcore.
