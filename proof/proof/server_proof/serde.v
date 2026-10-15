From New.generatedproof.github_com.sanjit_bhat.pav Require Import server.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import
  ktcore safemarshal.
From New.proof.github_com.tchajed Require Import marshal.

From New.proof.github_com.sanjit_bhat.pav.server_proof Require Import base.

(** serde spec form: see [safemarshal.v]. *)

Module server.

Module StartChain.
Record t :=
  mk' {
    PrevEpochLen: w64;
    PrevLink: list w8;
    ChainProof: list w8;
    LinkSig: list w8;
  }.

Definition enc_fn_def obj :=
  safemarshal.w64.enc_fn obj.(PrevEpochLen) ++
  safemarshal.Slice1D.enc_fn obj.(PrevLink) ++
  safemarshal.Slice1D.enc_fn obj.(ChainProof) ++
  safemarshal.Slice1D.enc_fn obj.(LinkSig).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def obj :=
  safemarshal.Slice1D.valid obj.(PrevLink) ∧
  safemarshal.Slice1D.valid obj.(ChainProof) ∧
  safemarshal.Slice1D.valid obj.(LinkSig).
Program Definition valid := sealed @valid_def.
#[local] Definition valid_unseal : valid = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal valid_unseal /enc_fn_def /valid_def. intros Heq (?&?&?) (?&?&?). repeat rewrite <- app_assoc in Heq.
  apply safemarshal.w64.enc_inj in Heq as [? Heq].
  apply safemarshal.Slice1D.enc_inj in Heq as [? Heq]; [|done..].
  apply safemarshal.Slice1D.enc_inj in Heq as [? Heq]; [|done..].
  apply safemarshal.Slice1D.enc_inj in Heq as [? ->]; [|done..].
  destruct obj, obj'. by simplify_eq/=.
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ sl_PrevLink sl_ChainProof sl_LinkSig,
  "#Hstr_StartChain" ∷ ptr ↦□ (server.StartChain.mk obj.(PrevEpochLen) sl_PrevLink sl_ChainProof sl_LinkSig) ∗

  "#Hsl_PrevLink" ∷ sl_PrevLink ↦*□ obj.(PrevLink) ∗
  "#Hsl_ChainProof" ∷ sl_ChainProof ↦*□ obj.(ChainProof) ∗
  "#Hsl_LinkSig" ∷ sl_LinkSig ↦*□ obj.(LinkSig).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iNamed 1.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_PrevLink") as %?.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_ChainProof") as %?.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_LinkSig") as %?.
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! server.StartChainEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_PrevLink sl_ChainProof sl_LinkSig) "(Hstr_StartChain & Hsl_PrevLink & Hsl_ChainProof & Hsl_LinkSig)".
  wp_auto.
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_PrevLink]") as "* (Hsl_b & Hcap_b & Hsl_PrevLink & %)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_ChainProof]") as "* (Hsl_b & Hcap_b & Hsl_ChainProof & %)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_LinkSig]") as "* (Hsl_b & Hcap_b & Hsl_LinkSig & %)".
  iApply "HΦ". iFrame "Hcap_b".
  iSplitL "Hsl_b". { iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc. }
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init server ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! server.StartChainDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ⌜¬ ∃ obj tail, b = enc_fn obj ++ tail ∧ valid obj⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj ∗
      sl_tail ↦*□ tail ∗
      ⌜b = enc_fn obj ++ tail⌝
    end
  }}}.
Proof.
  wp_start as "#Hsl_b". wp_auto.
  wp_apply (safemarshal.w64.wp_dec with "[$Hsl_b]").
  iIntros (a1 b1 err1) "Hpost". destruct err1.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply Hfail. eexists _, _. exact Henc. }
  iDestruct "Hpost" as (rem1) "(Hb1 & %Hrem1)".
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb1]").
  iIntros (a2 b2 err2) "Hpost". destruct err2.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite Hrem1 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.w64.enc_inj in Henc as [_ Henc].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v2 rem2) "(Hv2 & Hb2 & %Hrem2)".
  iDestruct (safemarshal.Slice1D.own_valid with "Hv2") as %?.
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb2]").
  iIntros (a3 b3 err3) "Hpost". destruct err3.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite Hrem1 Hrem2 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.w64.enc_inj in Henc as [_ Henc].
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v3 rem3) "(Hv3 & Hb3 & %Hrem3)".
  iDestruct (safemarshal.Slice1D.own_valid with "Hv3") as %?.
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb3]").
  iIntros (a4 b4 err4) "Hpost". destruct err4.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite Hrem1 Hrem2 Hrem3 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.w64.enc_inj in Henc as [_ Henc].
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v4 rem4) "(Hv4 & Hb4 & %Hrem4)".
  iDestruct (safemarshal.Slice1D.own_valid with "Hv4") as %?.
  wp_auto.
  wp_alloc l as "Hptr".
  iPersist "Hptr".
  wp_auto.
  iApply "HΦ". iExists (mk' a1 v2 v3 v4), rem4.
  iFrame "Hb4". iSplit; [iExists a2, a3, a4; by iFrame "∗#"|].
  iPureIntro. rewrite Hrem1 Hrem2 Hrem3 Hrem4 enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

End proof.
End StartChain.

Module StartVrf.
Record t :=
  mk' {
    VrfPk: list w8;
    VrfSig: list w8;
  }.

Definition enc_fn_def obj :=
  safemarshal.Slice1D.enc_fn obj.(VrfPk) ++
  safemarshal.Slice1D.enc_fn obj.(VrfSig).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def obj :=
  safemarshal.Slice1D.valid obj.(VrfPk) ∧
  safemarshal.Slice1D.valid obj.(VrfSig).
Program Definition valid := sealed @valid_def.
#[local] Definition valid_unseal : valid = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal valid_unseal /enc_fn_def /valid_def. intros Heq (?&?) (?&?). repeat rewrite <- app_assoc in Heq.
  apply safemarshal.Slice1D.enc_inj in Heq as [? Heq]; [|done..].
  apply safemarshal.Slice1D.enc_inj in Heq as [? ->]; [|done..].
  destruct obj, obj'. by simplify_eq/=.
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ sl_VrfPk sl_VrfSig,
  "#Hstr_StartVrf" ∷ ptr ↦□ (server.StartVrf.mk sl_VrfPk sl_VrfSig) ∗

  "#Hsl_VrfPk" ∷ sl_VrfPk ↦*□ obj.(VrfPk) ∗
  "#Hsl_VrfSig" ∷ sl_VrfSig ↦*□ obj.(VrfSig).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iNamed 1.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_VrfPk") as %?.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_VrfSig") as %?.
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! server.StartVrfEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_VrfPk sl_VrfSig) "(Hstr_StartVrf & Hsl_VrfPk & Hsl_VrfSig)".
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_VrfPk]") as "* (Hsl_b & Hcap_b & Hsl_VrfPk & %)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_VrfSig]") as "* (Hsl_b & Hcap_b & Hsl_VrfSig & %)".
  iApply "HΦ". iFrame "Hcap_b".
  iSplitL "Hsl_b". { iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc. }
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init server ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! server.StartVrfDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ⌜¬ ∃ obj tail, b = enc_fn obj ++ tail ∧ valid obj⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj ∗
      sl_tail ↦*□ tail ∗
      ⌜b = enc_fn obj ++ tail⌝
    end
  }}}.
Proof.
  wp_start as "#Hsl_b". wp_auto.
  wp_apply (safemarshal.Slice1D.wp_dec with "[$Hsl_b]").
  iIntros (a1 b1 err1) "Hpost". destruct err1.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?).
    rewrite enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v1 rem1) "(Hv1 & Hb1 & %Hrem1)".
  iDestruct (safemarshal.Slice1D.own_valid with "Hv1") as %?.
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb1]").
  iIntros (a2 b2 err2) "Hpost". destruct err2.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?).
    rewrite Hrem1 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v2 rem2) "(Hv2 & Hb2 & %Hrem2)".
  iDestruct (safemarshal.Slice1D.own_valid with "Hv2") as %?.
  wp_auto.
  wp_alloc l as "Hptr".
  iPersist "Hptr".
  wp_auto.
  iApply "HΦ". iExists (mk' v1 v2), rem2.
  iFrame "Hb2". iSplit; [iExists a1, a2; by iFrame "∗#"|].
  iPureIntro. rewrite Hrem1 Hrem2 enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

End proof.
End StartVrf.

Module StartReply.
Record t :=
  mk' {
    Chain: StartChain.t;
    Vrf: StartVrf.t;
  }.

Definition enc_fn_def obj :=
  StartChain.enc_fn obj.(Chain) ++
  StartVrf.enc_fn obj.(Vrf).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def obj :=
  StartChain.valid obj.(Chain) ∧
  StartVrf.valid obj.(Vrf).
Program Definition valid := sealed @valid_def.
#[local] Definition valid_unseal : valid = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal valid_unseal /enc_fn_def /valid_def. intros Heq (?&?) (?&?). repeat rewrite <- app_assoc in Heq.
  apply StartChain.enc_inj in Heq as [? Heq]; [|done..].
  apply StartVrf.enc_inj in Heq as [? ->]; [|done..].
  destruct obj, obj'. by simplify_eq/=.
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ ptr_Chain ptr_Vrf,
  "#Hstr_StartReply" ∷ ptr ↦□ (server.StartReply.mk ptr_Chain ptr_Vrf) ∗

  "#Hown_Chain" ∷ StartChain.own ptr_Chain obj.(Chain) ∗
  "#Hown_Vrf" ∷ StartVrf.own ptr_Vrf obj.(Vrf).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iNamed 1.
  iDestruct (StartChain.own_valid with "Hown_Chain") as %?.
  iDestruct (StartVrf.own_valid with "Hown_Vrf") as %?.
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! server.StartReplyEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (ptr_Chain ptr_Vrf) "(Hstr_StartReply & Hown_Chain & Hown_Vrf)".
  wp_auto.
  wp_apply (StartChain.wp_enc with "[$Hsl_b $Hcap_b $Hown_Chain]") as "* (Hsl_b & Hcap_b & %)".
  wp_apply (StartVrf.wp_enc with "[$Hsl_b $Hcap_b $Hown_Vrf]") as "* (Hsl_b & Hcap_b & %)".
  iApply "HΦ". iFrame "Hcap_b".
  iSplitL "Hsl_b". { iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc. }
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init server ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! server.StartReplyDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ⌜¬ ∃ obj tail, b = enc_fn obj ++ tail ∧ valid obj⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj ∗
      sl_tail ↦*□ tail ∗
      ⌜b = enc_fn obj ++ tail⌝
    end
  }}}.
Proof.
  wp_start as "#Hsl_b". wp_auto.
  wp_apply (StartChain.wp_dec with "[$Hsl_b]").
  iIntros (a1 b1 err1) "Hpost". destruct err1.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?).
    rewrite enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v1 rem1) "(Hv1 & Hb1 & %Hrem1)".
  iDestruct (StartChain.own_valid with "Hv1") as %?.
  wp_auto.
  wp_apply (StartVrf.wp_dec with "[$Hb1]").
  iIntros (a2 b2 err2) "Hpost". destruct err2.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?).
    rewrite Hrem1 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply StartChain.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v2 rem2) "(Hv2 & Hb2 & %Hrem2)".
  iDestruct (StartVrf.own_valid with "Hv2") as %?.
  wp_auto.
  wp_alloc l as "Hptr".
  iPersist "Hptr".
  wp_auto.
  iApply "HΦ". iExists (mk' v1 v2), rem2.
  iFrame "Hb2". iSplit; [iExists a1, a2; by iFrame "∗#"|].
  iPureIntro. rewrite Hrem1 Hrem2 enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

End proof.
End StartReply.

Module PutArg.
Record t :=
  mk' {
    Uid: w64;
    Pk: list w8;
    Ver: w64;
  }.

Definition enc_fn_def obj :=
  safemarshal.w64.enc_fn obj.(Uid) ++
  safemarshal.Slice1D.enc_fn obj.(Pk) ++
  safemarshal.w64.enc_fn obj.(Ver).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def obj :=
  safemarshal.Slice1D.valid obj.(Pk).
Program Definition valid := sealed @valid_def.
#[local] Definition valid_unseal : valid = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal valid_unseal /enc_fn_def /valid_def. intros Heq ? ?. repeat rewrite <- app_assoc in Heq.
  apply safemarshal.w64.enc_inj in Heq as [? Heq].
  apply safemarshal.Slice1D.enc_inj in Heq as [? Heq]; [|done..].
  apply safemarshal.w64.enc_inj in Heq as [? ->].
  destruct obj, obj'. by simplify_eq/=.
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ sl_Pk,
  "#Hstr_PutArg" ∷ ptr ↦□ (server.PutArg.mk obj.(Uid) sl_Pk obj.(Ver)) ∗

  "#Hsl_Pk" ∷ sl_Pk ↦*□ obj.(Pk).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iNamed 1.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_Pk") as %?.
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! server.PutArgEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_Pk) "(Hstr_PutArg & Hsl_Pk)".
  wp_auto.
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_Pk]") as "* (Hsl_b & Hcap_b & Hsl_Pk & %)".
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iApply "HΦ". iFrame "Hcap_b".
  iSplitL "Hsl_b". { iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc. }
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init server ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! server.PutArgDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ⌜¬ ∃ obj tail, b = enc_fn obj ++ tail ∧ valid obj⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj ∗
      sl_tail ↦*□ tail ∗
      ⌜b = enc_fn obj ++ tail⌝
    end
  }}}.
Proof.
  wp_start as "#Hsl_b". wp_auto.
  wp_apply (safemarshal.w64.wp_dec with "[$Hsl_b]").
  iIntros (a1 b1 err1) "Hpost". destruct err1.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv.
    rewrite enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply Hfail. eexists _, _. exact Henc. }
  iDestruct "Hpost" as (rem1) "(Hb1 & %Hrem1)".
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb1]").
  iIntros (a2 b2 err2) "Hpost". destruct err2.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv.
    rewrite Hrem1 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.w64.enc_inj in Henc as [_ Henc].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v2 rem2) "(Hv2 & Hb2 & %Hrem2)".
  iDestruct (safemarshal.Slice1D.own_valid with "Hv2") as %?.
  wp_auto.
  wp_apply (safemarshal.w64.wp_dec with "[$Hb2]").
  iIntros (a3 b3 err3) "Hpost". destruct err3.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv.
    rewrite Hrem1 Hrem2 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.w64.enc_inj in Henc as [_ Henc].
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. exact Henc. }
  iDestruct "Hpost" as (rem3) "(Hb3 & %Hrem3)".
  wp_auto.
  wp_alloc l as "Hptr".
  iPersist "Hptr".
  wp_auto.
  iApply "HΦ". iExists (mk' a1 v2 a3), rem3.
  iFrame "Hb3". iSplit; [iExists a2; by iFrame "∗#"|].
  iPureIntro. rewrite Hrem1 Hrem2 Hrem3 enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

End proof.
End PutArg.

Module HistoryArg.
Record t :=
  mk' {
    Uid: w64;
    PrevEpoch: w64;
    PrevVerLen: w64;
  }.

Definition enc_fn_def obj :=
  safemarshal.w64.enc_fn obj.(Uid) ++
  safemarshal.w64.enc_fn obj.(PrevEpoch) ++
  safemarshal.w64.enc_fn obj.(PrevVerLen).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal /enc_fn_def. intros Heq. repeat rewrite <- app_assoc in Heq.
  apply safemarshal.w64.enc_inj in Heq as [? Heq].
  apply safemarshal.w64.enc_inj in Heq as [? Heq].
  apply safemarshal.w64.enc_inj in Heq as [? ->].
  destruct obj, obj'. by simplify_eq/=.
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  "#Hstr_HistoryArg" ∷ ptr ↦□ (server.HistoryArg.mk obj.(Uid) obj.(PrevEpoch) obj.(PrevVerLen)).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! server.HistoryArgEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as "Hstr_HistoryArg".
  wp_auto.
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iApply "HΦ". iFrame "Hcap_b".
  iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init server ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! server.HistoryArgDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ⌜¬ ∃ obj tail, b = enc_fn obj ++ tail⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj ∗
      sl_tail ↦*□ tail ∗
      ⌜b = enc_fn obj ++ tail⌝
    end
  }}}.
Proof.
  wp_start as "#Hsl_b". wp_auto.
  wp_apply (safemarshal.w64.wp_dec with "[$Hsl_b]").
  iIntros (a1 b1 err1) "Hpost". destruct err1.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc).
    rewrite enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply Hfail. eexists _, _. exact Henc. }
  iDestruct "Hpost" as (rem1) "(Hb1 & %Hrem1)".
  wp_auto.
  wp_apply (safemarshal.w64.wp_dec with "[$Hb1]").
  iIntros (a2 b2 err2) "Hpost". destruct err2.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc).
    rewrite Hrem1 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.w64.enc_inj in Henc as [_ Henc].
    apply Hfail. eexists _, _. exact Henc. }
  iDestruct "Hpost" as (rem2) "(Hb2 & %Hrem2)".
  wp_auto.
  wp_apply (safemarshal.w64.wp_dec with "[$Hb2]").
  iIntros (a3 b3 err3) "Hpost". destruct err3.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc).
    rewrite Hrem1 Hrem2 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.w64.enc_inj in Henc as [_ Henc].
    apply safemarshal.w64.enc_inj in Henc as [_ Henc].
    apply Hfail. eexists _, _. exact Henc. }
  iDestruct "Hpost" as (rem3) "(Hb3 & %Hrem3)".
  wp_auto.
  wp_alloc l as "Hptr".
  iPersist "Hptr".
  wp_auto.
  iApply "HΦ". iExists (mk' a1 a2 a3), rem3.
  iFrame "Hb3". iSplit; [by iFrame "#"|].
  iPureIntro. rewrite Hrem1 Hrem2 Hrem3 enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

End proof.
End HistoryArg.

Module HistoryReply.
Record t :=
  mk' {
    ChainProof: list w8;
    LinkSig: list w8;
    Hist: ktcore.MembSlice1D.t;
    Bound: ktcore.NonMemb.t;
    Err: bool;
  }.

Definition enc_fn_def obj :=
  safemarshal.Slice1D.enc_fn obj.(ChainProof) ++
  safemarshal.Slice1D.enc_fn obj.(LinkSig) ++
  ktcore.MembSlice1D.enc_fn obj.(Hist) ++
  ktcore.NonMemb.enc_fn obj.(Bound) ++
  safemarshal.bool.enc_fn obj.(Err).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def obj :=
  safemarshal.Slice1D.valid obj.(ChainProof) ∧
  safemarshal.Slice1D.valid obj.(LinkSig) ∧
  ktcore.MembSlice1D.valid obj.(Hist) ∧
  ktcore.NonMemb.valid obj.(Bound).
Program Definition valid := sealed @valid_def.
#[local] Definition valid_unseal : valid = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal valid_unseal /enc_fn_def /valid_def. intros Heq (?&?&?&?) (?&?&?&?). repeat rewrite <- app_assoc in Heq.
  apply safemarshal.Slice1D.enc_inj in Heq as [? Heq]; [|done..].
  apply safemarshal.Slice1D.enc_inj in Heq as [? Heq]; [|done..].
  apply ktcore.MembSlice1D.enc_inj in Heq as [? Heq]; [|done..].
  apply ktcore.NonMemb.enc_inj in Heq as [? Heq]; [|done..].
  apply safemarshal.bool.enc_inj in Heq as [? ->].
  destruct obj, obj'. by simplify_eq/=.
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ sl_ChainProof sl_LinkSig ptr_Hist ptr_Bound,
  "#Hstr_HistoryReply" ∷ ptr ↦□ (server.HistoryReply.mk sl_ChainProof sl_LinkSig ptr_Hist ptr_Bound obj.(Err)) ∗

  "#Hsl_ChainProof" ∷ sl_ChainProof ↦*□ obj.(ChainProof) ∗
  "#Hsl_LinkSig" ∷ sl_LinkSig ↦*□ obj.(LinkSig) ∗
  "#Hown_Hist" ∷ ktcore.MembSlice1D.own ptr_Hist obj.(Hist) ∗
  "#Hown_Bound" ∷ ktcore.NonMemb.own ptr_Bound obj.(Bound).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iNamed 1.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_ChainProof") as %?.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_LinkSig") as %?.
  iDestruct (ktcore.MembSlice1D.own_valid with "Hown_Hist") as %?.
  iDestruct (ktcore.NonMemb.own_valid with "Hown_Bound") as %?.
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! server.HistoryReplyEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_ChainProof sl_LinkSig ptr_Hist ptr_Bound) "(Hstr_HistoryReply & Hsl_ChainProof & Hsl_LinkSig & Hown_Hist & Hown_Bound)".
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_ChainProof]") as "* (Hsl_b & Hcap_b & Hsl_ChainProof & %)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_LinkSig]") as "* (Hsl_b & Hcap_b & Hsl_LinkSig & %)".
  wp_apply (ktcore.MembSlice1D.wp_enc with "[$Hsl_b $Hcap_b $Hown_Hist]") as "* (Hsl_b & Hcap_b & %)".
  wp_apply (ktcore.NonMemb.wp_enc with "[$Hsl_b $Hcap_b $Hown_Bound]") as "* (Hsl_b & Hcap_b & %)".
  wp_apply (safemarshal.bool.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iApply "HΦ". iFrame "Hcap_b".
  iSplitL "Hsl_b". { iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc. }
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init server ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! server.HistoryReplyDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ⌜¬ ∃ obj tail, b = enc_fn obj ++ tail ∧ valid obj⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj ∗
      sl_tail ↦*□ tail ∗
      ⌜b = enc_fn obj ++ tail⌝
    end
  }}}.
Proof.
  wp_start as "#Hsl_b". wp_auto.
  wp_apply (safemarshal.Slice1D.wp_dec with "[$Hsl_b]").
  iIntros (a1 b1 err1) "Hpost". destruct err1.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?&?).
    rewrite enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v1 rem1) "(Hv1 & Hb1 & %Hrem1)".
  iDestruct (safemarshal.Slice1D.own_valid with "Hv1") as %?.
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb1]").
  iIntros (a2 b2 err2) "Hpost". destruct err2.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?&?).
    rewrite Hrem1 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v2 rem2) "(Hv2 & Hb2 & %Hrem2)".
  iDestruct (safemarshal.Slice1D.own_valid with "Hv2") as %?.
  wp_auto.
  wp_apply (ktcore.MembSlice1D.wp_dec with "[$Hb2]").
  iIntros (a3 b3 err3) "Hpost". destruct err3.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?&?).
    rewrite Hrem1 Hrem2 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v3 rem3) "(Hv3 & Hb3 & %Hrem3)".
  iDestruct (ktcore.MembSlice1D.own_valid with "Hv3") as %?.
  wp_auto.
  wp_apply (ktcore.NonMemb.wp_dec with "[$Hb3]").
  iIntros (a4 b4 err4) "Hpost". destruct err4.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?&?).
    rewrite Hrem1 Hrem2 Hrem3 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply ktcore.MembSlice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v4 rem4) "(Hv4 & Hb4 & %Hrem4)".
  iDestruct (ktcore.NonMemb.own_valid with "Hv4") as %?.
  wp_auto.
  wp_apply (safemarshal.bool.wp_dec with "[$Hb4]").
  iIntros (a5 b5 err5) "Hpost". destruct err5.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?&?).
    rewrite Hrem1 Hrem2 Hrem3 Hrem4 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply ktcore.MembSlice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply ktcore.NonMemb.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. exact Henc. }
  iDestruct "Hpost" as (rem5) "(Hb5 & %Hrem5)".
  wp_auto.
  wp_alloc l as "Hptr".
  iPersist "Hptr".
  wp_auto.
  iApply "HΦ". iExists (mk' v1 v2 v3 v4 a5), rem5.
  iFrame "Hb5". iSplit; [iExists a1, a2, a3, a4; by iFrame "∗#"|].
  iPureIntro. rewrite Hrem1 Hrem2 Hrem3 Hrem4 Hrem5 enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

End proof.
End HistoryReply.

Module AuditArg.
Record t :=
  mk' {
    PrevEpoch: w64;
  }.

Definition enc_fn_def obj :=
  safemarshal.w64.enc_fn obj.(PrevEpoch).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal /enc_fn_def. intros Heq. repeat rewrite <- app_assoc in Heq.
  apply safemarshal.w64.enc_inj in Heq as [? ->].
  destruct obj, obj'. by simplify_eq/=.
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  "#Hstr_AuditArg" ∷ ptr ↦□ (server.AuditArg.mk obj.(PrevEpoch)).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! server.AuditArgEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as "Hstr_AuditArg".
  wp_auto.
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iApply "HΦ". iFrame "Hcap_b".
  iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init server ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! server.AuditArgDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ⌜¬ ∃ obj tail, b = enc_fn obj ++ tail⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj ∗
      sl_tail ↦*□ tail ∗
      ⌜b = enc_fn obj ++ tail⌝
    end
  }}}.
Proof.
  wp_start as "#Hsl_b". wp_auto.
  wp_apply (safemarshal.w64.wp_dec with "[$Hsl_b]").
  iIntros (a1 b1 err1) "Hpost". destruct err1.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc).
    rewrite enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply Hfail. eexists _, _. exact Henc. }
  iDestruct "Hpost" as (rem1) "(Hb1 & %Hrem1)".
  wp_auto.
  wp_alloc l as "Hptr".
  iPersist "Hptr".
  wp_auto.
  iApply "HΦ". iExists (mk' a1), rem1.
  iFrame "Hb1". iSplit; [by iFrame "#"|].
  iPureIntro. rewrite Hrem1 enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

End proof.
End AuditArg.

Module AuditReply.
Record t :=
  mk' {
    P: ktcore.AuditProofSlice1D.t;
    Err: bool;
  }.

Definition enc_fn_def obj :=
  ktcore.AuditProofSlice1D.enc_fn obj.(P) ++
  safemarshal.bool.enc_fn obj.(Err).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def obj :=
  ktcore.AuditProofSlice1D.valid obj.(P).
Program Definition valid := sealed @valid_def.
#[local] Definition valid_unseal : valid = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal valid_unseal /enc_fn_def /valid_def. intros Heq ? ?. repeat rewrite <- app_assoc in Heq.
  apply ktcore.AuditProofSlice1D.enc_inj in Heq as [? Heq]; [|done..].
  apply safemarshal.bool.enc_inj in Heq as [? ->].
  destruct obj, obj'. by simplify_eq/=.
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ ptr_P,
  "#Hstr_AuditReply" ∷ ptr ↦□ (server.AuditReply.mk ptr_P obj.(Err)) ∗

  "#Hown_P" ∷ ktcore.AuditProofSlice1D.own ptr_P obj.(P).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iNamed 1.
  iDestruct (ktcore.AuditProofSlice1D.own_valid with "Hown_P") as %?.
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! server.AuditReplyEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (ptr_P) "(Hstr_AuditReply & Hown_P)".
  wp_auto.
  wp_apply (ktcore.AuditProofSlice1D.wp_enc with "[$Hsl_b $Hcap_b $Hown_P]") as "* (Hsl_b & Hcap_b & %)".
  wp_apply (safemarshal.bool.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iApply "HΦ". iFrame "Hcap_b".
  iSplitL "Hsl_b". { iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc. }
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init server ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! server.AuditReplyDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ⌜¬ ∃ obj tail, b = enc_fn obj ++ tail ∧ valid obj⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj ∗
      sl_tail ↦*□ tail ∗
      ⌜b = enc_fn obj ++ tail⌝
    end
  }}}.
Proof.
  wp_start as "#Hsl_b". wp_auto.
  wp_apply (ktcore.AuditProofSlice1D.wp_dec with "[$Hsl_b]").
  iIntros (a1 b1 err1) "Hpost". destruct err1.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv.
    rewrite enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v1 rem1) "(Hv1 & Hb1 & %Hrem1)".
  iDestruct (ktcore.AuditProofSlice1D.own_valid with "Hv1") as %?.
  wp_auto.
  wp_apply (safemarshal.bool.wp_dec with "[$Hb1]").
  iIntros (a2 b2 err2) "Hpost". destruct err2.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv.
    rewrite Hrem1 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply ktcore.AuditProofSlice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. exact Henc. }
  iDestruct "Hpost" as (rem2) "(Hb2 & %Hrem2)".
  wp_auto.
  wp_alloc l as "Hptr".
  iPersist "Hptr".
  wp_auto.
  iApply "HΦ". iExists (mk' v1 a2), rem2.
  iFrame "Hb2". iSplit; [iExists a1; by iFrame "∗#"|].
  iPureIntro. rewrite Hrem1 Hrem2 enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

End proof.
End AuditReply.

End server.
