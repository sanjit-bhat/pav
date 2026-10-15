From New.generatedproof.github_com.sanjit_bhat.pav Require Import auditor.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import safemarshal.
From New.proof.github_com.tchajed Require Import marshal.

From New.proof.github_com.sanjit_bhat.pav.auditor_proof Require Import base.

(** serde spec form: see [safemarshal.v]. *)

Module auditor.

Module GetArg.
Record t :=
  mk' {
    Epoch: w64;
  }.

Definition enc_fn_def obj :=
  safemarshal.w64.enc_fn obj.(Epoch).
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
  "#Hstr_GetArg" ∷ ptr ↦□ (auditor.GetArg.mk obj.(Epoch)).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init auditor ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! auditor.GetArgEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as "Hstr_GetArg".
  wp_auto.
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iApply "HΦ". iFrame "Hcap_b".
  iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init auditor ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! auditor.GetArgDecode #sl_b
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
End GetArg.

Module SignedLink.
Record t :=
  mk' {
    Link: list w8;
    ServSig: list w8;
    AdtrSig: list w8;
  }.

Definition enc_fn_def obj :=
  safemarshal.Slice1D.enc_fn obj.(Link) ++
  safemarshal.Slice1D.enc_fn obj.(ServSig) ++
  safemarshal.Slice1D.enc_fn obj.(AdtrSig).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def obj :=
  safemarshal.Slice1D.valid obj.(Link) ∧
  safemarshal.Slice1D.valid obj.(ServSig) ∧
  safemarshal.Slice1D.valid obj.(AdtrSig).
Program Definition valid := sealed @valid_def.
#[local] Definition valid_unseal : valid = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal valid_unseal /enc_fn_def /valid_def. intros Heq (?&?&?) (?&?&?). repeat rewrite <- app_assoc in Heq.
  apply safemarshal.Slice1D.enc_inj in Heq as [? Heq]; [|done..].
  apply safemarshal.Slice1D.enc_inj in Heq as [? Heq]; [|done..].
  apply safemarshal.Slice1D.enc_inj in Heq as [? ->]; [|done..].
  destruct obj, obj'. by simplify_eq/=.
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ sl_Link sl_ServSig sl_AdtrSig,
  "#Hstr_SignedLink" ∷ ptr ↦□ (auditor.SignedLink.mk sl_Link sl_ServSig sl_AdtrSig) ∗

  "#Hsl_Link" ∷ sl_Link ↦*□ obj.(Link) ∗
  "#Hsl_ServSig" ∷ sl_ServSig ↦*□ obj.(ServSig) ∗
  "#Hsl_AdtrSig" ∷ sl_AdtrSig ↦*□ obj.(AdtrSig).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iNamed 1.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_Link") as %?.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_ServSig") as %?.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_AdtrSig") as %?.
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init auditor ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! auditor.SignedLinkEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_Link sl_ServSig sl_AdtrSig) "(Hstr_SignedLink & Hsl_Link & Hsl_ServSig & Hsl_AdtrSig)".
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_Link]") as "* (Hsl_b & Hcap_b & Hsl_Link & %)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_ServSig]") as "* (Hsl_b & Hcap_b & Hsl_ServSig & %)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_AdtrSig]") as "* (Hsl_b & Hcap_b & Hsl_AdtrSig & %)".
  iApply "HΦ". iFrame "Hcap_b".
  iSplitL "Hsl_b". { iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc. }
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init auditor ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! auditor.SignedLinkDecode #sl_b
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
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v1 rem1) "(Hv1 & Hb1 & %Hrem1)".
  iDestruct (safemarshal.Slice1D.own_valid with "Hv1") as %?.
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb1]").
  iIntros (a2 b2 err2) "Hpost". destruct err2.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite Hrem1 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
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
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v3 rem3) "(Hv3 & Hb3 & %Hrem3)".
  iDestruct (safemarshal.Slice1D.own_valid with "Hv3") as %?.
  wp_auto.
  wp_alloc l as "Hptr".
  iPersist "Hptr".
  wp_auto.
  iApply "HΦ". iExists (mk' v1 v2 v3), rem3.
  iFrame "Hb3". iSplit; [iExists a1, a2, a3; by iFrame "∗#"|].
  iPureIntro. rewrite Hrem1 Hrem2 Hrem3 enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

End proof.
End SignedLink.

Module SignedVrf.
Record t :=
  mk' {
    VrfPk: list w8;
    ServSig: list w8;
    AdtrSig: list w8;
  }.

Definition enc_fn_def obj :=
  safemarshal.Slice1D.enc_fn obj.(VrfPk) ++
  safemarshal.Slice1D.enc_fn obj.(ServSig) ++
  safemarshal.Slice1D.enc_fn obj.(AdtrSig).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def obj :=
  safemarshal.Slice1D.valid obj.(VrfPk) ∧
  safemarshal.Slice1D.valid obj.(ServSig) ∧
  safemarshal.Slice1D.valid obj.(AdtrSig).
Program Definition valid := sealed @valid_def.
#[local] Definition valid_unseal : valid = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal valid_unseal /enc_fn_def /valid_def. intros Heq (?&?&?) (?&?&?). repeat rewrite <- app_assoc in Heq.
  apply safemarshal.Slice1D.enc_inj in Heq as [? Heq]; [|done..].
  apply safemarshal.Slice1D.enc_inj in Heq as [? Heq]; [|done..].
  apply safemarshal.Slice1D.enc_inj in Heq as [? ->]; [|done..].
  destruct obj, obj'. by simplify_eq/=.
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ sl_VrfPk sl_ServSig sl_AdtrSig,
  "#Hstr_SignedVrf" ∷ ptr ↦□ (auditor.SignedVrf.mk sl_VrfPk sl_ServSig sl_AdtrSig) ∗

  "#Hsl_VrfPk" ∷ sl_VrfPk ↦*□ obj.(VrfPk) ∗
  "#Hsl_ServSig" ∷ sl_ServSig ↦*□ obj.(ServSig) ∗
  "#Hsl_AdtrSig" ∷ sl_AdtrSig ↦*□ obj.(AdtrSig).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iNamed 1.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_VrfPk") as %?.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_ServSig") as %?.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_AdtrSig") as %?.
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init auditor ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! auditor.SignedVrfEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_VrfPk sl_ServSig sl_AdtrSig) "(Hstr_SignedVrf & Hsl_VrfPk & Hsl_ServSig & Hsl_AdtrSig)".
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_VrfPk]") as "* (Hsl_b & Hcap_b & Hsl_VrfPk & %)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_ServSig]") as "* (Hsl_b & Hcap_b & Hsl_ServSig & %)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_AdtrSig]") as "* (Hsl_b & Hcap_b & Hsl_AdtrSig & %)".
  iApply "HΦ". iFrame "Hcap_b".
  iSplitL "Hsl_b". { iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc. }
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init auditor ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! auditor.SignedVrfDecode #sl_b
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
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v1 rem1) "(Hv1 & Hb1 & %Hrem1)".
  iDestruct (safemarshal.Slice1D.own_valid with "Hv1") as %?.
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb1]").
  iIntros (a2 b2 err2) "Hpost". destruct err2.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite Hrem1 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
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
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v3 rem3) "(Hv3 & Hb3 & %Hrem3)".
  iDestruct (safemarshal.Slice1D.own_valid with "Hv3") as %?.
  wp_auto.
  wp_alloc l as "Hptr".
  iPersist "Hptr".
  wp_auto.
  iApply "HΦ". iExists (mk' v1 v2 v3), rem3.
  iFrame "Hb3". iSplit; [iExists a1, a2, a3; by iFrame "∗#"|].
  iPureIntro. rewrite Hrem1 Hrem2 Hrem3 enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

End proof.
End SignedVrf.

Module GetReply.
Record t :=
  mk' {
    StartEp: w64;
    StartLink: SignedLink.t;
    CurrLink: SignedLink.t;
    Vrf: SignedVrf.t;
    Err: bool;
  }.

Definition enc_fn_def obj :=
  safemarshal.w64.enc_fn obj.(StartEp) ++
  SignedLink.enc_fn obj.(StartLink) ++
  SignedLink.enc_fn obj.(CurrLink) ++
  SignedVrf.enc_fn obj.(Vrf) ++
  safemarshal.bool.enc_fn obj.(Err).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def obj :=
  SignedLink.valid obj.(StartLink) ∧
  SignedLink.valid obj.(CurrLink) ∧
  SignedVrf.valid obj.(Vrf).
Program Definition valid := sealed @valid_def.
#[local] Definition valid_unseal : valid = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal valid_unseal /enc_fn_def /valid_def. intros Heq (?&?&?) (?&?&?). repeat rewrite <- app_assoc in Heq.
  apply safemarshal.w64.enc_inj in Heq as [? Heq].
  apply SignedLink.enc_inj in Heq as [? Heq]; [|done..].
  apply SignedLink.enc_inj in Heq as [? Heq]; [|done..].
  apply SignedVrf.enc_inj in Heq as [? Heq]; [|done..].
  apply safemarshal.bool.enc_inj in Heq as [? ->].
  destruct obj, obj'. by simplify_eq/=.
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ ptr_StartLink ptr_CurrLink ptr_Vrf,
  "#Hstr_GetReply" ∷ ptr ↦□ (auditor.GetReply.mk obj.(StartEp) ptr_StartLink ptr_CurrLink ptr_Vrf obj.(Err)) ∗

  "#Hown_StartLink" ∷ SignedLink.own ptr_StartLink obj.(StartLink) ∗
  "#Hown_CurrLink" ∷ SignedLink.own ptr_CurrLink obj.(CurrLink) ∗
  "#Hown_Vrf" ∷ SignedVrf.own ptr_Vrf obj.(Vrf).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iNamed 1.
  iDestruct (SignedLink.own_valid with "Hown_StartLink") as %?.
  iDestruct (SignedLink.own_valid with "Hown_CurrLink") as %?.
  iDestruct (SignedVrf.own_valid with "Hown_Vrf") as %?.
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : auditor.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init auditor ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! auditor.GetReplyEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (ptr_StartLink ptr_CurrLink ptr_Vrf) "(Hstr_GetReply & Hown_StartLink & Hown_CurrLink & Hown_Vrf)".
  wp_auto.
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (SignedLink.wp_enc with "[$Hsl_b $Hcap_b $Hown_StartLink]") as "* (Hsl_b & Hcap_b & %)".
  wp_apply (SignedLink.wp_enc with "[$Hsl_b $Hcap_b $Hown_CurrLink]") as "* (Hsl_b & Hcap_b & %)".
  wp_apply (SignedVrf.wp_enc with "[$Hsl_b $Hcap_b $Hown_Vrf]") as "* (Hsl_b & Hcap_b & %)".
  wp_apply (safemarshal.bool.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iApply "HΦ". iFrame "Hcap_b".
  iSplitL "Hsl_b". { iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc. }
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init auditor ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! auditor.GetReplyDecode #sl_b
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
  wp_apply (SignedLink.wp_dec with "[$Hb1]").
  iIntros (a2 b2 err2) "Hpost". destruct err2.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite Hrem1 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.w64.enc_inj in Henc as [_ Henc].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v2 rem2) "(Hv2 & Hb2 & %Hrem2)".
  iDestruct (SignedLink.own_valid with "Hv2") as %?.
  wp_auto.
  wp_apply (SignedLink.wp_dec with "[$Hb2]").
  iIntros (a3 b3 err3) "Hpost". destruct err3.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite Hrem1 Hrem2 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.w64.enc_inj in Henc as [_ Henc].
    apply SignedLink.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v3 rem3) "(Hv3 & Hb3 & %Hrem3)".
  iDestruct (SignedLink.own_valid with "Hv3") as %?.
  wp_auto.
  wp_apply (SignedVrf.wp_dec with "[$Hb3]").
  iIntros (a4 b4 err4) "Hpost". destruct err4.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite Hrem1 Hrem2 Hrem3 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.w64.enc_inj in Henc as [_ Henc].
    apply SignedLink.enc_inj in Henc as [_ Henc]; [|done..].
    apply SignedLink.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v4 rem4) "(Hv4 & Hb4 & %Hrem4)".
  iDestruct (SignedVrf.own_valid with "Hv4") as %?.
  wp_auto.
  wp_apply (safemarshal.bool.wp_dec with "[$Hb4]").
  iIntros (a5 b5 err5) "Hpost". destruct err5.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite Hrem1 Hrem2 Hrem3 Hrem4 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.w64.enc_inj in Henc as [_ Henc].
    apply SignedLink.enc_inj in Henc as [_ Henc]; [|done..].
    apply SignedLink.enc_inj in Henc as [_ Henc]; [|done..].
    apply SignedVrf.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. exact Henc. }
  iDestruct "Hpost" as (rem5) "(Hb5 & %Hrem5)".
  wp_auto.
  wp_alloc l as "Hptr".
  iPersist "Hptr".
  wp_auto.
  iApply "HΦ". iExists (mk' a1 v2 v3 v4 a5), rem5.
  iFrame "Hb5". iSplit; [iExists a2, a3, a4; by iFrame "∗#"|].
  iPureIntro. rewrite Hrem1 Hrem2 Hrem3 Hrem4 Hrem5 enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

End proof.
End GetReply.

End auditor.
