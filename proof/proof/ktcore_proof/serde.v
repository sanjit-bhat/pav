From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import safemarshal.
From New.proof.github_com.tchajed Require Import marshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import base.

(** serde spec form: see [safemarshal.v]. *)

Module ktcore.

Notation VrfSigTag := 0 (only parsing).
Notation LinkSigTag := 1 (only parsing).

Module VrfSig.
Record t :=
  mk' {
    SigTag: w8;
    VrfPk: list w8;
  }.

Definition enc_fn_def obj :=
  safemarshal.w8.enc_fn obj.(SigTag) ++
  safemarshal.Slice1D.enc_fn obj.(VrfPk).
Program Definition enc_fn := sealed @enc_fn_def.
(* public: [get_vrf_sigpred] and [get_link_sigpred] separate sig tags. *)
Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def obj :=
  safemarshal.Slice1D.valid obj.(VrfPk).
Program Definition valid := sealed @valid_def.
#[local] Definition valid_unseal : valid = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal valid_unseal /enc_fn_def /valid_def. intros Heq ? ?. repeat rewrite <- app_assoc in Heq.
  apply safemarshal.w8.enc_inj in Heq as [? Heq].
  apply safemarshal.Slice1D.enc_inj in Heq as [? ->]; [|done..].
  destruct obj, obj'. by simplify_eq/=.
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ sl_VrfPk,
  "#Hstr_VrfSig" ∷ ptr ↦□ (ktcore.VrfSig.mk obj.(SigTag) sl_VrfPk) ∗

  "#Hsl_VrfPk" ∷ sl_VrfPk ↦*□ obj.(VrfPk).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iNamed 1.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_VrfPk") as %?.
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! ktcore.VrfSigEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_VrfPk) "(Hstr_VrfSig & Hsl_VrfPk)".
  wp_auto.
  wp_apply (safemarshal.w8.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_VrfPk]") as "* (Hsl_b & Hcap_b & Hsl_VrfPk & %)".
  iApply "HΦ". iFrame "Hcap_b".
  iSplitL "Hsl_b". { iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc. }
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init ktcore ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! ktcore.VrfSigDecode #sl_b
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
  wp_apply (safemarshal.w8.wp_dec with "[$Hsl_b]").
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
    apply safemarshal.w8.enc_inj in Henc as [_ Henc].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v2 rem2) "(Hv2 & Hb2 & %Hrem2)".
  iDestruct (safemarshal.Slice1D.own_valid with "Hv2") as %?.
  wp_auto.
  wp_alloc l as "Hptr".
  iPersist "Hptr".
  wp_auto.
  iApply "HΦ". iExists (mk' a1 v2), rem2.
  iFrame "Hb2". iSplit; [iExists a2; by iFrame "∗#"|].
  iPureIntro. rewrite Hrem1 Hrem2 enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

End proof.
End VrfSig.

Module LinkSig.
Record t :=
  mk' {
    SigTag: w8;
    Epoch: w64;
    Link: list w8;
  }.

Definition enc_fn_def obj :=
  safemarshal.w8.enc_fn obj.(SigTag) ++
  safemarshal.w64.enc_fn obj.(Epoch) ++
  safemarshal.Slice1D.enc_fn obj.(Link).
Program Definition enc_fn := sealed @enc_fn_def.
(* public: [get_vrf_sigpred] and [get_link_sigpred] separate sig tags. *)
Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def obj :=
  safemarshal.Slice1D.valid obj.(Link).
Program Definition valid := sealed @valid_def.
#[local] Definition valid_unseal : valid = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal valid_unseal /enc_fn_def /valid_def. intros Heq ? ?. repeat rewrite <- app_assoc in Heq.
  apply safemarshal.w8.enc_inj in Heq as [? Heq].
  apply safemarshal.w64.enc_inj in Heq as [? Heq].
  apply safemarshal.Slice1D.enc_inj in Heq as [? ->]; [|done..].
  destruct obj, obj'. by simplify_eq/=.
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ sl_Link,
  "#Hstr_LinkSig" ∷ ptr ↦□ (ktcore.LinkSig.mk obj.(SigTag) obj.(Epoch) sl_Link) ∗

  "#Hsl_Link" ∷ sl_Link ↦*□ obj.(Link).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iNamed 1.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_Link") as %?.
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! ktcore.LinkSigEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_Link) "(Hstr_LinkSig & Hsl_Link)".
  wp_auto.
  wp_apply (safemarshal.w8.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_Link]") as "* (Hsl_b & Hcap_b & Hsl_Link & %)".
  iApply "HΦ". iFrame "Hcap_b".
  iSplitL "Hsl_b". { iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc. }
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init ktcore ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! ktcore.LinkSigDecode #sl_b
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
  wp_apply (safemarshal.w8.wp_dec with "[$Hsl_b]").
  iIntros (a1 b1 err1) "Hpost". destruct err1.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv.
    rewrite enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply Hfail. eexists _, _. exact Henc. }
  iDestruct "Hpost" as (rem1) "(Hb1 & %Hrem1)".
  wp_auto.
  wp_apply (safemarshal.w64.wp_dec with "[$Hb1]").
  iIntros (a2 b2 err2) "Hpost". destruct err2.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv.
    rewrite Hrem1 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.w8.enc_inj in Henc as [_ Henc].
    apply Hfail. eexists _, _. exact Henc. }
  iDestruct "Hpost" as (rem2) "(Hb2 & %Hrem2)".
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb2]").
  iIntros (a3 b3 err3) "Hpost". destruct err3.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv.
    rewrite Hrem1 Hrem2 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.w8.enc_inj in Henc as [_ Henc].
    apply safemarshal.w64.enc_inj in Henc as [_ Henc].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v3 rem3) "(Hv3 & Hb3 & %Hrem3)".
  iDestruct (safemarshal.Slice1D.own_valid with "Hv3") as %?.
  wp_auto.
  wp_alloc l as "Hptr".
  iPersist "Hptr".
  wp_auto.
  iApply "HΦ". iExists (mk' a1 a2 v3), rem3.
  iFrame "Hb3". iSplit; [iExists a3; by iFrame "∗#"|].
  iPureIntro. rewrite Hrem1 Hrem2 Hrem3 enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

End proof.
End LinkSig.

Module MapLabel.
Record t :=
  mk' {
    Uid: w64;
    Ver: w64;
  }.

Definition enc_fn_def obj :=
  safemarshal.w64.enc_fn obj.(Uid) ++
  safemarshal.w64.enc_fn obj.(Ver).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal /enc_fn_def. intros Heq. repeat rewrite <- app_assoc in Heq.
  apply safemarshal.w64.enc_inj in Heq as [? Heq].
  apply safemarshal.w64.enc_inj in Heq as [? ->].
  destruct obj, obj'. by simplify_eq/=.
Qed.

Definition dec_fn_def (b0 : list w8) : option (t * list w8) :=
  '(a1, b1) ← safemarshal.w64.dec_fn b0;
  '(a2, b2) ← safemarshal.w64.dec_fn b1;
  Some (mk' a1 a2, b2).
Program Definition dec_fn := sealed @dec_fn_def.
#[local] Definition dec_fn_unseal : dec_fn = _ := seal_eq _.

Lemma dec_fn_iff b obj tail :
  dec_fn b = Some (obj, tail) ↔ b = enc_fn obj ++ tail.
Proof.
  rewrite dec_fn_unseal enc_fn_unseal /dec_fn_def /enc_fn_def. split.
  - destruct (safemarshal.w64.dec_fn b) as [[a1 b1]|] eqn:H1; [|done]; simpl.
    destruct (safemarshal.w64.dec_fn b1) as [[a2 b2]|] eqn:H2; [|done]; simpl.
    intros [= <- <-].
    apply safemarshal.w64.dec_fn_iff in H1 as ->.
    apply safemarshal.w64.dec_fn_iff in H2 as ->.
    simpl. by repeat rewrite <- app_assoc.
  - intros ->. repeat rewrite <- app_assoc.
    rewrite safemarshal.w64.dec_fn_enc //= safemarshal.w64.dec_fn_enc //=. by destruct obj.
Qed.

Lemma dec_fn_enc obj tail :
  dec_fn (enc_fn obj ++ tail) = Some (obj, tail).
Proof. by apply dec_fn_iff. Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  "#Hstr_MapLabel" ∷ ptr ↦□ (ktcore.MapLabel.mk obj.(Uid) obj.(Ver)).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! ktcore.MapLabelEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as "Hstr_MapLabel".
  wp_auto.
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iApply "HΦ". iFrame "Hcap_b".
  iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init ktcore ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! ktcore.MapLabelDecode #sl_b
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
  wp_alloc l as "Hptr".
  iPersist "Hptr".
  wp_auto.
  iApply "HΦ". iExists (mk' a1 a2), rem2.
  iFrame "Hb2". iSplit; [by iFrame "#"|].
  iPureIntro. rewrite Hrem1 Hrem2 enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc.
Qed.

End proof.
End MapLabel.

Module CommitOpen.
Record t :=
  mk' {
    Val: list w8;
    Rand: list w8;
  }.

Definition enc_fn_def obj :=
  safemarshal.Slice1D.enc_fn obj.(Val) ++
  safemarshal.Slice1D.enc_fn obj.(Rand).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def obj :=
  safemarshal.Slice1D.valid obj.(Val) ∧
  safemarshal.Slice1D.valid obj.(Rand).
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

Definition dec_fn_def (b0 : list w8) : option (t * list w8) :=
  '(a1, b1) ← safemarshal.Slice1D.dec_fn b0;
  '(a2, b2) ← safemarshal.Slice1D.dec_fn b1;
  Some (mk' a1 a2, b2).
Program Definition dec_fn := sealed @dec_fn_def.
#[local] Definition dec_fn_unseal : dec_fn = _ := seal_eq _.

Lemma dec_fn_iff b obj tail :
  dec_fn b = Some (obj, tail) ↔ b = enc_fn obj ++ tail ∧ valid obj.
Proof.
  rewrite dec_fn_unseal enc_fn_unseal valid_unseal /dec_fn_def /enc_fn_def /valid_def. split.
  - destruct (safemarshal.Slice1D.dec_fn b) as [[a1 b1]|] eqn:H1; [|done]; simpl.
    destruct (safemarshal.Slice1D.dec_fn b1) as [[a2 b2]|] eqn:H2; [|done]; simpl.
    intros [= <- <-].
    apply safemarshal.Slice1D.dec_fn_iff in H1 as [-> ?].
    apply safemarshal.Slice1D.dec_fn_iff in H2 as [-> ?].
    simpl. split; [by repeat rewrite <- app_assoc|naive_solver].
  - intros [-> (?&?)]. repeat rewrite <- app_assoc.
    rewrite safemarshal.Slice1D.dec_fn_enc //= safemarshal.Slice1D.dec_fn_enc //=. by destruct obj.
Qed.

Lemma dec_fn_enc obj tail :
  valid obj →
  dec_fn (enc_fn obj ++ tail) = Some (obj, tail).
Proof. intros. by apply dec_fn_iff. Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ sl_Val sl_Rand,
  "#Hstr_CommitOpen" ∷ ptr ↦□ (ktcore.CommitOpen.mk sl_Val sl_Rand) ∗

  "#Hsl_Val" ∷ sl_Val ↦*□ obj.(Val) ∗
  "#Hsl_Rand" ∷ sl_Rand ↦*□ obj.(Rand).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iNamed 1.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_Val") as %?.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_Rand") as %?.
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! ktcore.CommitOpenEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_Val sl_Rand) "(Hstr_CommitOpen & Hsl_Val & Hsl_Rand)".
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_Val]") as "* (Hsl_b & Hcap_b & Hsl_Val & %)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_Rand]") as "* (Hsl_b & Hcap_b & Hsl_Rand & %)".
  iApply "HΦ". iFrame "Hcap_b".
  iSplitL "Hsl_b". { iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc. }
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init ktcore ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! ktcore.CommitOpenDecode #sl_b
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
End CommitOpen.

Module Memb.
Record t :=
  mk' {
    LabelProof: list w8;
    PkOpen: CommitOpen.t;
    MerkleProof: list w8;
  }.

Definition enc_fn_def obj :=
  safemarshal.Slice1D.enc_fn obj.(LabelProof) ++
  CommitOpen.enc_fn obj.(PkOpen) ++
  safemarshal.Slice1D.enc_fn obj.(MerkleProof).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def obj :=
  safemarshal.Slice1D.valid obj.(LabelProof) ∧
  CommitOpen.valid obj.(PkOpen) ∧
  safemarshal.Slice1D.valid obj.(MerkleProof).
Program Definition valid := sealed @valid_def.
#[local] Definition valid_unseal : valid = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal valid_unseal /enc_fn_def /valid_def. intros Heq (?&?&?) (?&?&?). repeat rewrite <- app_assoc in Heq.
  apply safemarshal.Slice1D.enc_inj in Heq as [? Heq]; [|done..].
  apply CommitOpen.enc_inj in Heq as [? Heq]; [|done..].
  apply safemarshal.Slice1D.enc_inj in Heq as [? ->]; [|done..].
  destruct obj, obj'. by simplify_eq/=.
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ sl_LabelProof ptr_PkOpen sl_MerkleProof,
  "#Hstr_Memb" ∷ ptr ↦□ (ktcore.Memb.mk sl_LabelProof ptr_PkOpen sl_MerkleProof) ∗

  "#Hsl_LabelProof" ∷ sl_LabelProof ↦*□ obj.(LabelProof) ∗
  "#Hown_PkOpen" ∷ CommitOpen.own ptr_PkOpen obj.(PkOpen) ∗
  "#Hsl_MerkleProof" ∷ sl_MerkleProof ↦*□ obj.(MerkleProof).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iNamed 1.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_LabelProof") as %?.
  iDestruct (CommitOpen.own_valid with "Hown_PkOpen") as %?.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_MerkleProof") as %?.
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! ktcore.MembEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_LabelProof ptr_PkOpen sl_MerkleProof) "(Hstr_Memb & Hsl_LabelProof & Hown_PkOpen & Hsl_MerkleProof)".
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_LabelProof]") as "* (Hsl_b & Hcap_b & Hsl_LabelProof & %)".
  wp_apply (CommitOpen.wp_enc with "[$Hsl_b $Hcap_b $Hown_PkOpen]") as "* (Hsl_b & Hcap_b & %)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_MerkleProof]") as "* (Hsl_b & Hcap_b & Hsl_MerkleProof & %)".
  iApply "HΦ". iFrame "Hcap_b".
  iSplitL "Hsl_b". { iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc. }
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init ktcore ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! ktcore.MembDecode #sl_b
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
  wp_apply (CommitOpen.wp_dec with "[$Hb1]").
  iIntros (a2 b2 err2) "Hpost". destruct err2.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite Hrem1 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v2 rem2) "(Hv2 & Hb2 & %Hrem2)".
  iDestruct (CommitOpen.own_valid with "Hv2") as %?.
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb2]").
  iIntros (a3 b3 err3) "Hpost". destruct err3.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?&?).
    rewrite Hrem1 Hrem2 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply safemarshal.Slice1D.enc_inj in Henc as [_ Henc]; [|done..].
    apply CommitOpen.enc_inj in Henc as [_ Henc]; [|done..].
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
End Memb.

Module MembSlice1D.
Definition t := list Memb.t.

Definition enc_fn_def (obj : t) :=
  safemarshal.w64.enc_fn (W64 $ length obj) ++ mjoin (Memb.enc_fn <$> obj).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def (obj : t) :=
  sint.Z (W64 (length obj)) = length obj ∧
  Forall Memb.valid obj.
Program Definition valid := sealed @valid_def.
#[local] Definition valid_unseal : valid = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal valid_unseal /enc_fn_def /valid_def -!app_assoc.
  intros Heq [??] [??].
  apply safemarshal.w64.enc_inj in Heq as [? Heq].
  apply (mjoin_enc_inj _ _ _ _ _ _ Memb.enc_inj) in Heq; [done|word|done..].
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ ptrs,
  "#Hsl" ∷ ptr ↦*□ ptrs ∗
  "#Hown_elems" ∷ ([∗ list] p;o ∈ ptrs;obj, Memb.own p o).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iDestruct 1 as (ptrs) "[Hsl Hbig]".
  iDestruct (own_slice_len with "Hsl") as %[??].
  iDestruct (big_sepL2_length with "Hbig") as %?.
  iDestruct (big_sepL2_impl _ (λ _ _ o, ⌜Memb.valid o⌝)%I with "Hbig []") as "Hv".
  { iIntros "!> * _ _ H". iApply (Memb.own_valid with "H"). }
  rewrite big_sepL2_const_sepL_r big_sepL_pure.
  iDestruct "Hv" as "[_ %Hv]".
  iPureIntro. rewrite valid_unseal /valid_def.
  split; [word|]. apply Forall_lookup. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! ktcore.MembSlice1DEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & #Hown)".
  iDestruct (own_valid with "Hown") as %Hvalid.
  iDestruct "Hown" as (ptrs) "[#Hsl #Hown_elems]".
  iDestruct (own_slice_len with "Hsl") as %[Hlen0 ?].
  iDestruct (big_sepL2_length with "Hown_elems") as %Hlen_eq.
  wp_auto.
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iAssert (∃ (j : w64) (sl_cur : slice.t) (ev : loc),
    "i" ∷ i_ptr ↦ j ∗
    "%Hj" ∷ ⌜0 ≤ sint.Z j ≤ length obj⌝ ∗
    "e" ∷ e_ptr ↦ ev ∗
    "b" ∷ b_ptr ↦ sl_cur ∗
    "Hsl_b" ∷ sl_cur ↦* (b ++ safemarshal.w64.enc_fn ptr_obj.(slice.len)
                          ++ mjoin (Memb.enc_fn <$> take (sint.nat j) obj)) ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_cur 1)%I
    with "[-HΦ]" as "IH".
  { iExists (W64 0), _, null. rewrite take_0 /= app_nil_r. iFrame. iPureIntro. word. }
  wp_for "IH".
  case_bool_decide.
  2: { wp_auto.
       iApply "HΦ".
       iFrame "Hcap_b %".
       iExactEq "Hsl_b".
       replace (sint.nat j) with (length obj) by word.
       rewrite take_ge; [|lia].
       rewrite enc_fn_unseal /enc_fn_def.
       replace (W64 (length obj)) with ptr_obj.(slice.len) by word.
       done. }
  list_elem ptrs (sint.Z j) as pj.
  list_elem obj (sint.Z j) as oj.
  wp_auto.
  rewrite decide_True; last word.
  wp_apply (wp_load_slice_index with "[$Hsl]") as "_".
  { word. }
  { eauto. }
  iDestruct (big_sepL2_lookup with "Hown_elems") as "Hown_j";
    [exact Hpj_lookup | exact Hoj_lookup |].
  wp_apply (Memb.wp_enc with "[$Hsl_b $Hcap_b $Hown_j]") as "* (Hsl_b & Hcap_b & _)".
  wp_for_post.
  iFrame.
  iSplitR; [iPureIntro; word|].
  iExactEq "Hsl_b".
  replace (sint.nat (word.add j (W64 1))) with (S (sint.nat j)) by word.
  rewrite (take_S_r _ _ oj); [|exact Hoj_lookup].
  rewrite fmap_app join_app /= app_nil_r.
  by rewrite -!app_assoc.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init ktcore ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! ktcore.MembSlice1DDecode #sl_b
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
  iIntros (length0 b1 err1) "Hpost". destruct err1.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & _).
    apply Hfail. eexists _, _. rewrite Henc enc_fn_unseal /enc_fn_def. by rewrite -app_assoc. }
  iDestruct "Hpost" as (tail1) "(Hb1 & %Hb)". subst b.
  wp_auto.
  wp_if_destruct.
  { iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (Hvlen & _).
    rewrite enc_fn_unseal /enc_fn_def -app_assoc in Henc.
    apply safemarshal.w64.enc_inj in Henc as [-> _]. word. }
  wp_apply wp_slice_make3; first word.
  iIntros (lo_sl) "(Hlo & Hcap & %Hlocap)".
  wp_auto.
  iAssert (∃ (j : w64) (decoded : list Memb.t) (ptrs : list loc)
             (cur_lo cur_lb : slice.t) (rest : list w8),
    "i" ∷ i_ptr ↦ j ∗
    "%Hj" ∷ ⌜uint.Z j ≤ uint.Z length0⌝ ∗
    "%Hdeclen" ∷ ⌜Z.of_nat (length decoded) = uint.Z j⌝ ∗
    "loopO" ∷ loopO_ptr ↦ cur_lo ∗
    "Hlo" ∷ cur_lo ↦* ptrs ∗
    "Hcap" ∷ own_slice_cap loc cur_lo (DfracOwn 1) ∗
    "#Hbig" ∷ ([∗ list] p;o ∈ ptrs;decoded, Memb.own p o) ∗
    "loopErr" ∷ loopErr_ptr ↦ false ∗
    "loopB" ∷ loopB_ptr ↦ cur_lb ∗
    "#Hlb" ∷ cur_lb ↦*□ rest ∗
    "%Hcons" ∷ ⌜tail1 = mjoin (Memb.enc_fn <$> decoded) ++ rest⌝ ∗
    "%Hvf" ∷ ⌜Forall Memb.valid decoded⌝)%I
    with "[i loopO Hlo Hcap loopErr loopB Hb1]" as "IH".
  { iEval (replace (sint.nat (W64 0)) with 0%nat by word) in "Hlo".
    iExists (W64 0), [], [], lo_sl, b1, tail1.
    iFrame. simpl. iSplit; [iPureIntro; word|].
    iSplit; [iPureIntro; word|]. iSplit; [done|]. iPureIntro. done. }
  wp_for "IH".
  case_bool_decide as Hcond.
  2: {
    iPersist "Hlo".
    wp_auto.
    iApply "HΦ".
    iExists decoded, rest.
    iFrame "Hlb". iSplit; [iExists ptrs; by iFrame "#"|].
    iPureIntro. rewrite Hcons enc_fn_unseal /enc_fn_def -!app_assoc. repeat f_equal. word. }
  wp_auto.
  wp_apply (Memb.wp_dec with "[$Hlb]").
  iIntros (a2 lb1 err2) "Hpost".
  wp_auto.
  destruct err2.
  - iDestruct "Hpost" as %Hfail.
    wp_auto.
    wp_for_post.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (Hvlen & Hvobj).
    rewrite enc_fn_unseal /enc_fn_def -app_assoc in Henc.
    apply safemarshal.w64.enc_inj in Henc as [-> Hrest].
    assert (Hjlt : (uint.nat j < length obj)%nat) by word.
    destruct (lookup_lt_is_Some_2 obj (uint.nat j) Hjlt) as [oj Hoj].
    rewrite Hcons -(take_drop_middle obj (uint.nat j) oj Hoj)
      fmap_app fmap_cons join_app join_cons -!app_assoc in Hrest.
    apply (mjoin_enc_inj _ _ _ _ _ _ Memb.enc_inj) in Hrest as [_ ->].
    2: { rewrite length_take. word. }
    2: done.
    2: by apply Forall_take.
    apply Hfail. eexists oj, _. split; [done|].
    rewrite Forall_lookup in Hvobj. naive_solver.
  - iDestruct "Hpost" as (m t) "(Hown_m & Hlb1 & %Hrest_eq)".
    iDestruct (Memb.own_valid with "Hown_m") as %Hvm.
    wp_auto.
    wp_apply wp_slice_literal. iSplitR; first done. iIntros "* [Hlit _]". wp_auto.
    wp_apply (wp_slice_append with "[$Hlo $Hcap $Hlit]").
    iIntros (lo2) "(Hlo & Hcap & _)".
    wp_auto.
    wp_for_post.
    iFrame "HΦ length".
    iDestruct (big_sepL2_snoc with "[$Hbig $Hown_m]") as "Hbig'".
    iExists (word.add j (W64 1)), (decoded ++ [m]), (ptrs ++ [a2]), lo2, lb1, t.
    iFrame.
    iPureIntro. rewrite length_app /=. split_and!; [word|word| |].
    + rewrite fmap_app join_app /= app_nil_r Hcons Hrest_eq. by rewrite -!app_assoc.
    + apply Forall_app. split; [done|]. by apply Forall_singleton.
Qed.

End proof.
End MembSlice1D.

Module NonMemb.
Record t :=
  mk' {
    LabelProof: list w8;
    MerkleProof: list w8;
  }.

Definition enc_fn_def obj :=
  safemarshal.Slice1D.enc_fn obj.(LabelProof) ++
  safemarshal.Slice1D.enc_fn obj.(MerkleProof).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def obj :=
  safemarshal.Slice1D.valid obj.(LabelProof) ∧
  safemarshal.Slice1D.valid obj.(MerkleProof).
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
  ∃ sl_LabelProof sl_MerkleProof,
  "#Hstr_NonMemb" ∷ ptr ↦□ (ktcore.NonMemb.mk sl_LabelProof sl_MerkleProof) ∗

  "#Hsl_LabelProof" ∷ sl_LabelProof ↦*□ obj.(LabelProof) ∗
  "#Hsl_MerkleProof" ∷ sl_MerkleProof ↦*□ obj.(MerkleProof).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iNamed 1.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_LabelProof") as %?.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_MerkleProof") as %?.
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! ktcore.NonMembEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_LabelProof sl_MerkleProof) "(Hstr_NonMemb & Hsl_LabelProof & Hsl_MerkleProof)".
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_LabelProof]") as "* (Hsl_b & Hcap_b & Hsl_LabelProof & %)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_MerkleProof]") as "* (Hsl_b & Hcap_b & Hsl_MerkleProof & %)".
  iApply "HΦ". iFrame "Hcap_b".
  iSplitL "Hsl_b". { iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc. }
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init ktcore ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! ktcore.NonMembDecode #sl_b
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
End NonMemb.

Module UpdateProof.
Record t :=
  mk' {
    MapLabel: list w8;
    MapVal: list w8;
    NonMembProof: list w8;
  }.

Definition enc_fn_def obj :=
  safemarshal.Slice1D.enc_fn obj.(MapLabel) ++
  safemarshal.Slice1D.enc_fn obj.(MapVal) ++
  safemarshal.Slice1D.enc_fn obj.(NonMembProof).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def obj :=
  safemarshal.Slice1D.valid obj.(MapLabel) ∧
  safemarshal.Slice1D.valid obj.(MapVal) ∧
  safemarshal.Slice1D.valid obj.(NonMembProof).
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
  ∃ sl_MapLabel sl_MapVal sl_NonMembProof,
  "#Hstr_UpdateProof" ∷ ptr ↦□ (ktcore.UpdateProof.mk sl_MapLabel sl_MapVal sl_NonMembProof) ∗

  "#Hsl_MapLabel" ∷ sl_MapLabel ↦*□ obj.(MapLabel) ∗
  "#Hsl_MapVal" ∷ sl_MapVal ↦*□ obj.(MapVal) ∗
  "#Hsl_NonMembProof" ∷ sl_NonMembProof ↦*□ obj.(NonMembProof).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iNamed 1.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_MapLabel") as %?.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_MapVal") as %?.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_NonMembProof") as %?.
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! ktcore.UpdateProofEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (sl_MapLabel sl_MapVal sl_NonMembProof) "(Hstr_UpdateProof & Hsl_MapLabel & Hsl_MapVal & Hsl_NonMembProof)".
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_MapLabel]") as "* (Hsl_b & Hcap_b & Hsl_MapLabel & %)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_MapVal]") as "* (Hsl_b & Hcap_b & Hsl_MapVal & %)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_NonMembProof]") as "* (Hsl_b & Hcap_b & Hsl_NonMembProof & %)".
  iApply "HΦ". iFrame "Hcap_b".
  iSplitL "Hsl_b". { iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc. }
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init ktcore ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! ktcore.UpdateProofDecode #sl_b
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
End UpdateProof.

Module UpdateProofSlice1D.
Definition t := list UpdateProof.t.

Definition enc_fn_def (obj : t) :=
  safemarshal.w64.enc_fn (W64 $ length obj) ++ mjoin (UpdateProof.enc_fn <$> obj).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def (obj : t) :=
  sint.Z (W64 (length obj)) = length obj ∧
  Forall UpdateProof.valid obj.
Program Definition valid := sealed @valid_def.
#[local] Definition valid_unseal : valid = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal valid_unseal /enc_fn_def /valid_def -!app_assoc.
  intros Heq [??] [??].
  apply safemarshal.w64.enc_inj in Heq as [? Heq].
  apply (mjoin_enc_inj _ _ _ _ _ _ UpdateProof.enc_inj) in Heq; [done|word|done..].
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ ptrs,
  "#Hsl" ∷ ptr ↦*□ ptrs ∗
  "#Hown_elems" ∷ ([∗ list] p;o ∈ ptrs;obj, UpdateProof.own p o).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iDestruct 1 as (ptrs) "[Hsl Hbig]".
  iDestruct (own_slice_len with "Hsl") as %[??].
  iDestruct (big_sepL2_length with "Hbig") as %?.
  iDestruct (big_sepL2_impl _ (λ _ _ o, ⌜UpdateProof.valid o⌝)%I with "Hbig []") as "Hv".
  { iIntros "!> * _ _ H". iApply (UpdateProof.own_valid with "H"). }
  rewrite big_sepL2_const_sepL_r big_sepL_pure.
  iDestruct "Hv" as "[_ %Hv]".
  iPureIntro. rewrite valid_unseal /valid_def.
  split; [word|]. apply Forall_lookup. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! ktcore.UpdateProofSlice1DEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & #Hown)".
  iDestruct (own_valid with "Hown") as %Hvalid.
  iDestruct "Hown" as (ptrs) "[#Hsl #Hown_elems]".
  iDestruct (own_slice_len with "Hsl") as %[Hlen0 ?].
  iDestruct (big_sepL2_length with "Hown_elems") as %Hlen_eq.
  wp_auto.
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iAssert (∃ (j : w64) (sl_cur : slice.t) (ev : loc),
    "i" ∷ i_ptr ↦ j ∗
    "%Hj" ∷ ⌜0 ≤ sint.Z j ≤ length obj⌝ ∗
    "e" ∷ e_ptr ↦ ev ∗
    "b" ∷ b_ptr ↦ sl_cur ∗
    "Hsl_b" ∷ sl_cur ↦* (b ++ safemarshal.w64.enc_fn ptr_obj.(slice.len)
                          ++ mjoin (UpdateProof.enc_fn <$> take (sint.nat j) obj)) ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_cur 1)%I
    with "[-HΦ]" as "IH".
  { iExists (W64 0), _, null. rewrite take_0 /= app_nil_r. iFrame. iPureIntro. word. }
  wp_for "IH".
  case_bool_decide.
  2: { wp_auto.
       iApply "HΦ".
       iFrame "Hcap_b %".
       iExactEq "Hsl_b".
       replace (sint.nat j) with (length obj) by word.
       rewrite take_ge; [|lia].
       rewrite enc_fn_unseal /enc_fn_def.
       replace (W64 (length obj)) with ptr_obj.(slice.len) by word.
       done. }
  list_elem ptrs (sint.Z j) as pj.
  list_elem obj (sint.Z j) as oj.
  wp_auto.
  rewrite decide_True; last word.
  wp_apply (wp_load_slice_index with "[$Hsl]") as "_".
  { word. }
  { eauto. }
  iDestruct (big_sepL2_lookup with "Hown_elems") as "Hown_j";
    [exact Hpj_lookup | exact Hoj_lookup |].
  wp_apply (UpdateProof.wp_enc with "[$Hsl_b $Hcap_b $Hown_j]") as "* (Hsl_b & Hcap_b & _)".
  wp_for_post.
  iFrame.
  iSplitR; [iPureIntro; word|].
  iExactEq "Hsl_b".
  replace (sint.nat (word.add j (W64 1))) with (S (sint.nat j)) by word.
  rewrite (take_S_r _ _ oj); [|exact Hoj_lookup].
  rewrite fmap_app join_app /= app_nil_r.
  by rewrite -!app_assoc.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init ktcore ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! ktcore.UpdateProofSlice1DDecode #sl_b
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
  iIntros (length0 b1 err1) "Hpost". destruct err1.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & _).
    apply Hfail. eexists _, _. rewrite Henc enc_fn_unseal /enc_fn_def. by rewrite -app_assoc. }
  iDestruct "Hpost" as (tail1) "(Hb1 & %Hb)". subst b.
  wp_auto.
  wp_if_destruct.
  { iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (Hvlen & _).
    rewrite enc_fn_unseal /enc_fn_def -app_assoc in Henc.
    apply safemarshal.w64.enc_inj in Henc as [-> _]. word. }
  wp_apply wp_slice_make3; first word.
  iIntros (lo_sl) "(Hlo & Hcap & %Hlocap)".
  wp_auto.
  iAssert (∃ (j : w64) (decoded : list UpdateProof.t) (ptrs : list loc)
             (cur_lo cur_lb : slice.t) (rest : list w8),
    "i" ∷ i_ptr ↦ j ∗
    "%Hj" ∷ ⌜uint.Z j ≤ uint.Z length0⌝ ∗
    "%Hdeclen" ∷ ⌜Z.of_nat (length decoded) = uint.Z j⌝ ∗
    "loopO" ∷ loopO_ptr ↦ cur_lo ∗
    "Hlo" ∷ cur_lo ↦* ptrs ∗
    "Hcap" ∷ own_slice_cap loc cur_lo (DfracOwn 1) ∗
    "#Hbig" ∷ ([∗ list] p;o ∈ ptrs;decoded, UpdateProof.own p o) ∗
    "loopErr" ∷ loopErr_ptr ↦ false ∗
    "loopB" ∷ loopB_ptr ↦ cur_lb ∗
    "#Hlb" ∷ cur_lb ↦*□ rest ∗
    "%Hcons" ∷ ⌜tail1 = mjoin (UpdateProof.enc_fn <$> decoded) ++ rest⌝ ∗
    "%Hvf" ∷ ⌜Forall UpdateProof.valid decoded⌝)%I
    with "[i loopO Hlo Hcap loopErr loopB Hb1]" as "IH".
  { iEval (replace (sint.nat (W64 0)) with 0%nat by word) in "Hlo".
    iExists (W64 0), [], [], lo_sl, b1, tail1.
    iFrame. simpl. iSplit; [iPureIntro; word|].
    iSplit; [iPureIntro; word|]. iSplit; [done|]. iPureIntro. done. }
  wp_for "IH".
  case_bool_decide as Hcond.
  2: {
    iPersist "Hlo".
    wp_auto.
    iApply "HΦ".
    iExists decoded, rest.
    iFrame "Hlb". iSplit; [iExists ptrs; by iFrame "#"|].
    iPureIntro. rewrite Hcons enc_fn_unseal /enc_fn_def -!app_assoc. repeat f_equal. word. }
  wp_auto.
  wp_apply (UpdateProof.wp_dec with "[$Hlb]").
  iIntros (a2 lb1 err2) "Hpost".
  wp_auto.
  destruct err2.
  - iDestruct "Hpost" as %Hfail.
    wp_auto.
    wp_for_post.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (Hvlen & Hvobj).
    rewrite enc_fn_unseal /enc_fn_def -app_assoc in Henc.
    apply safemarshal.w64.enc_inj in Henc as [-> Hrest].
    assert (Hjlt : (uint.nat j < length obj)%nat) by word.
    destruct (lookup_lt_is_Some_2 obj (uint.nat j) Hjlt) as [oj Hoj].
    rewrite Hcons -(take_drop_middle obj (uint.nat j) oj Hoj)
      fmap_app fmap_cons join_app join_cons -!app_assoc in Hrest.
    apply (mjoin_enc_inj _ _ _ _ _ _ UpdateProof.enc_inj) in Hrest as [_ ->].
    2: { rewrite length_take. word. }
    2: done.
    2: by apply Forall_take.
    apply Hfail. eexists oj, _. split; [done|].
    rewrite Forall_lookup in Hvobj. naive_solver.
  - iDestruct "Hpost" as (m t) "(Hown_m & Hlb1 & %Hrest_eq)".
    iDestruct (UpdateProof.own_valid with "Hown_m") as %Hvm.
    wp_auto.
    wp_apply wp_slice_literal. iSplitR; first done. iIntros "* [Hlit _]". wp_auto.
    wp_apply (wp_slice_append with "[$Hlo $Hcap $Hlit]").
    iIntros (lo2) "(Hlo & Hcap & _)".
    wp_auto.
    wp_for_post.
    iFrame "HΦ length".
    iDestruct (big_sepL2_snoc with "[$Hbig $Hown_m]") as "Hbig'".
    iExists (word.add j (W64 1)), (decoded ++ [m]), (ptrs ++ [a2]), lo2, lb1, t.
    iFrame.
    iPureIntro. rewrite length_app /=. split_and!; [word|word| |].
    + rewrite fmap_app join_app /= app_nil_r Hcons Hrest_eq. by rewrite -!app_assoc.
    + apply Forall_app. split; [done|]. by apply Forall_singleton.
Qed.

End proof.
End UpdateProofSlice1D.

Module AuditProof.
Record t :=
  mk' {
    Updates: UpdateProofSlice1D.t;
    LinkSig: list w8;
  }.

Definition enc_fn_def obj :=
  UpdateProofSlice1D.enc_fn obj.(Updates) ++
  safemarshal.Slice1D.enc_fn obj.(LinkSig).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def obj :=
  UpdateProofSlice1D.valid obj.(Updates) ∧
  safemarshal.Slice1D.valid obj.(LinkSig).
Program Definition valid := sealed @valid_def.
#[local] Definition valid_unseal : valid = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal valid_unseal /enc_fn_def /valid_def. intros Heq (?&?) (?&?). repeat rewrite <- app_assoc in Heq.
  apply UpdateProofSlice1D.enc_inj in Heq as [? Heq]; [|done..].
  apply safemarshal.Slice1D.enc_inj in Heq as [? ->]; [|done..].
  destruct obj, obj'. by simplify_eq/=.
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ ptr_Updates sl_LinkSig,
  "#Hstr_AuditProof" ∷ ptr ↦□ (ktcore.AuditProof.mk ptr_Updates sl_LinkSig) ∗

  "#Hown_Updates" ∷ UpdateProofSlice1D.own ptr_Updates obj.(Updates) ∗
  "#Hsl_LinkSig" ∷ sl_LinkSig ↦*□ obj.(LinkSig).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iNamed 1.
  iDestruct (UpdateProofSlice1D.own_valid with "Hown_Updates") as %?.
  iDestruct (safemarshal.Slice1D.own_valid with "Hsl_LinkSig") as %?.
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! ktcore.AuditProofEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & Hown)".
  iDestruct "Hown" as (ptr_Updates sl_LinkSig) "(Hstr_AuditProof & Hown_Updates & Hsl_LinkSig)".
  wp_auto.
  wp_apply (UpdateProofSlice1D.wp_enc with "[$Hsl_b $Hcap_b $Hown_Updates]") as "* (Hsl_b & Hcap_b & %)".
  wp_apply (safemarshal.Slice1D.wp_enc with "[$Hsl_b $Hcap_b $Hsl_LinkSig]") as "* (Hsl_b & Hcap_b & Hsl_LinkSig & %)".
  iApply "HΦ". iFrame "Hcap_b".
  iSplitL "Hsl_b". { iExactEq "Hsl_b". rewrite enc_fn_unseal /enc_fn_def. by repeat rewrite <- app_assoc. }
  iPureIntro. rewrite valid_unseal /valid_def. naive_solver.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init ktcore ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! ktcore.AuditProofDecode #sl_b
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
  wp_apply (UpdateProofSlice1D.wp_dec with "[$Hsl_b]").
  iIntros (a1 b1 err1) "Hpost". destruct err1.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?).
    rewrite enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply Hfail. eexists _, _. split; [exact Henc|done]. }
  iDestruct "Hpost" as (v1 rem1) "(Hv1 & Hb1 & %Hrem1)".
  iDestruct (UpdateProofSlice1D.own_valid with "Hv1") as %?.
  wp_auto.
  wp_apply (safemarshal.Slice1D.wp_dec with "[$Hb1]").
  iIntros (a2 b2 err2) "Hpost". destruct err2.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (?&?).
    rewrite Hrem1 enc_fn_unseal /enc_fn_def in Henc. repeat rewrite <- app_assoc in Henc.
    apply UpdateProofSlice1D.enc_inj in Henc as [_ Henc]; [|done..].
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
End AuditProof.

Module AuditProofSlice1D.
Definition t := list AuditProof.t.

Definition enc_fn_def (obj : t) :=
  safemarshal.w64.enc_fn (W64 $ length obj) ++ mjoin (AuditProof.enc_fn <$> obj).
Program Definition enc_fn := sealed @enc_fn_def.
#[local] Definition enc_fn_unseal : enc_fn = _ := seal_eq _.

Definition valid_def (obj : t) :=
  sint.Z (W64 (length obj)) = length obj ∧
  Forall AuditProof.valid obj.
Program Definition valid := sealed @valid_def.
#[local] Definition valid_unseal : valid = _ := seal_eq _.

Lemma enc_inj obj obj' tail tail' :
  enc_fn obj ++ tail = enc_fn obj' ++ tail' →
  valid obj → valid obj' →
  obj = obj' ∧ tail = tail'.
Proof.
  rewrite enc_fn_unseal valid_unseal /enc_fn_def /valid_def -!app_assoc.
  intros Heq [??] [??].
  apply safemarshal.w64.enc_inj in Heq as [? Heq].
  apply (mjoin_enc_inj _ _ _ _ _ _ AuditProof.enc_inj) in Heq; [done|word|done..].
Qed.

Section defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.

Definition own ptr obj : iProp Σ :=
  ∃ ptrs,
  "#Hsl" ∷ ptr ↦*□ ptrs ∗
  "#Hown_elems" ∷ ([∗ list] p;o ∈ ptrs;obj, AuditProof.own p o).
#[global] Instance own_pers ptr obj : Persistent (own ptr obj) := _.

Lemma own_valid ptr obj :
  own ptr obj ⊢ ⌜valid obj⌝.
Proof.
  iDestruct 1 as (ptrs) "[Hsl Hbig]".
  iDestruct (own_slice_len with "Hsl") as %[??].
  iDestruct (big_sepL2_length with "Hbig") as %?.
  iDestruct (big_sepL2_impl _ (λ _ _ o, ⌜AuditProof.valid o⌝)%I with "Hbig []") as "Hv".
  { iIntros "!> * _ _ H". iApply (AuditProof.own_valid with "H"). }
  rewrite big_sepL2_const_sepL_r big_sepL_pure.
  iDestruct "Hv" as "[_ %Hv]".
  iPureIntro. rewrite valid_unseal /valid_def.
  split; [word|]. apply Forall_lookup. naive_solver.
Qed.

End defs.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_enc obj sl_b b ptr_obj :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "#Hown_obj" ∷ own ptr_obj obj
  }}}
  @! ktcore.AuditProofSlice1DEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    sl_b' ↦* (b ++ enc_fn obj) ∗
    own_slice_cap w8 sl_b' 1 ∗
    ⌜valid obj⌝
  }}}.
Proof.
  wp_start as "(Hsl_b & Hcap_b & #Hown)".
  iDestruct (own_valid with "Hown") as %Hvalid.
  iDestruct "Hown" as (ptrs) "[#Hsl #Hown_elems]".
  iDestruct (own_slice_len with "Hsl") as %[Hlen0 ?].
  iDestruct (big_sepL2_length with "Hown_elems") as %Hlen_eq.
  wp_auto.
  wp_apply (safemarshal.w64.wp_enc with "[$Hsl_b $Hcap_b]") as "* [Hsl_b Hcap_b]".
  iAssert (∃ (j : w64) (sl_cur : slice.t) (ev : loc),
    "i" ∷ i_ptr ↦ j ∗
    "%Hj" ∷ ⌜0 ≤ sint.Z j ≤ length obj⌝ ∗
    "e" ∷ e_ptr ↦ ev ∗
    "b" ∷ b_ptr ↦ sl_cur ∗
    "Hsl_b" ∷ sl_cur ↦* (b ++ safemarshal.w64.enc_fn ptr_obj.(slice.len)
                          ++ mjoin (AuditProof.enc_fn <$> take (sint.nat j) obj)) ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_cur 1)%I
    with "[-HΦ]" as "IH".
  { iExists (W64 0), _, null. rewrite take_0 /= app_nil_r. iFrame. iPureIntro. word. }
  wp_for "IH".
  case_bool_decide.
  2: { wp_auto.
       iApply "HΦ".
       iFrame "Hcap_b %".
       iExactEq "Hsl_b".
       replace (sint.nat j) with (length obj) by word.
       rewrite take_ge; [|lia].
       rewrite enc_fn_unseal /enc_fn_def.
       replace (W64 (length obj)) with ptr_obj.(slice.len) by word.
       done. }
  list_elem ptrs (sint.Z j) as pj.
  list_elem obj (sint.Z j) as oj.
  wp_auto.
  rewrite decide_True; last word.
  wp_apply (wp_load_slice_index with "[$Hsl]") as "_".
  { word. }
  { eauto. }
  iDestruct (big_sepL2_lookup with "Hown_elems") as "Hown_j";
    [exact Hpj_lookup | exact Hoj_lookup |].
  wp_apply (AuditProof.wp_enc with "[$Hsl_b $Hcap_b $Hown_j]") as "* (Hsl_b & Hcap_b & _)".
  wp_for_post.
  iFrame.
  iSplitR; [iPureIntro; word|].
  iExactEq "Hsl_b".
  replace (sint.nat (word.add j (W64 1))) with (S (sint.nat j)) by word.
  rewrite (take_S_r _ _ oj); [|exact Hoj_lookup].
  rewrite fmap_app join_app /= app_nil_r.
  by rewrite -!app_assoc.
Qed.

Lemma wp_dec sl_b b :
  {{{
    is_pkg_init ktcore ∗
    "#Hsl_b" ∷ sl_b ↦*□ b
  }}}
  @! ktcore.AuditProofSlice1DDecode #sl_b
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
  iIntros (length0 b1 err1) "Hpost". destruct err1.
  { iDestruct "Hpost" as %Hfail. wp_auto.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & _).
    apply Hfail. eexists _, _. rewrite Henc enc_fn_unseal /enc_fn_def. by rewrite -app_assoc. }
  iDestruct "Hpost" as (tail1) "(Hb1 & %Hb)". subst b.
  wp_auto.
  wp_if_destruct.
  { iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (Hvlen & _).
    rewrite enc_fn_unseal /enc_fn_def -app_assoc in Henc.
    apply safemarshal.w64.enc_inj in Henc as [-> _]. word. }
  wp_apply wp_slice_make3; first word.
  iIntros (lo_sl) "(Hlo & Hcap & %Hlocap)".
  wp_auto.
  iAssert (∃ (j : w64) (decoded : list AuditProof.t) (ptrs : list loc)
             (cur_lo cur_lb : slice.t) (rest : list w8),
    "i" ∷ i_ptr ↦ j ∗
    "%Hj" ∷ ⌜uint.Z j ≤ uint.Z length0⌝ ∗
    "%Hdeclen" ∷ ⌜Z.of_nat (length decoded) = uint.Z j⌝ ∗
    "loopO" ∷ loopO_ptr ↦ cur_lo ∗
    "Hlo" ∷ cur_lo ↦* ptrs ∗
    "Hcap" ∷ own_slice_cap loc cur_lo (DfracOwn 1) ∗
    "#Hbig" ∷ ([∗ list] p;o ∈ ptrs;decoded, AuditProof.own p o) ∗
    "loopErr" ∷ loopErr_ptr ↦ false ∗
    "loopB" ∷ loopB_ptr ↦ cur_lb ∗
    "#Hlb" ∷ cur_lb ↦*□ rest ∗
    "%Hcons" ∷ ⌜tail1 = mjoin (AuditProof.enc_fn <$> decoded) ++ rest⌝ ∗
    "%Hvf" ∷ ⌜Forall AuditProof.valid decoded⌝)%I
    with "[i loopO Hlo Hcap loopErr loopB Hb1]" as "IH".
  { iEval (replace (sint.nat (W64 0)) with 0%nat by word) in "Hlo".
    iExists (W64 0), [], [], lo_sl, b1, tail1.
    iFrame. simpl. iSplit; [iPureIntro; word|].
    iSplit; [iPureIntro; word|]. iSplit; [done|]. iPureIntro. done. }
  wp_for "IH".
  case_bool_decide as Hcond.
  2: {
    iPersist "Hlo".
    wp_auto.
    iApply "HΦ".
    iExists decoded, rest.
    iFrame "Hlb". iSplit; [iExists ptrs; by iFrame "#"|].
    iPureIntro. rewrite Hcons enc_fn_unseal /enc_fn_def -!app_assoc. repeat f_equal. word. }
  wp_auto.
  wp_apply (AuditProof.wp_dec with "[$Hlb]").
  iIntros (a2 lb1 err2) "Hpost".
  wp_auto.
  destruct err2.
  - iDestruct "Hpost" as %Hfail.
    wp_auto.
    wp_for_post.
    iApply "HΦ". iPureIntro. intros (obj & tail & Henc & Hv).
    rewrite valid_unseal /valid_def in Hv. destruct Hv as (Hvlen & Hvobj).
    rewrite enc_fn_unseal /enc_fn_def -app_assoc in Henc.
    apply safemarshal.w64.enc_inj in Henc as [-> Hrest].
    assert (Hjlt : (uint.nat j < length obj)%nat) by word.
    destruct (lookup_lt_is_Some_2 obj (uint.nat j) Hjlt) as [oj Hoj].
    rewrite Hcons -(take_drop_middle obj (uint.nat j) oj Hoj)
      fmap_app fmap_cons join_app join_cons -!app_assoc in Hrest.
    apply (mjoin_enc_inj _ _ _ _ _ _ AuditProof.enc_inj) in Hrest as [_ ->].
    2: { rewrite length_take. word. }
    2: done.
    2: by apply Forall_take.
    apply Hfail. eexists oj, _. split; [done|].
    rewrite Forall_lookup in Hvobj. naive_solver.
  - iDestruct "Hpost" as (m t) "(Hown_m & Hlb1 & %Hrest_eq)".
    iDestruct (AuditProof.own_valid with "Hown_m") as %Hvm.
    wp_auto.
    wp_apply wp_slice_literal. iSplitR; first done. iIntros "* [Hlit _]". wp_auto.
    wp_apply (wp_slice_append with "[$Hlo $Hcap $Hlit]").
    iIntros (lo2) "(Hlo & Hcap & _)".
    wp_auto.
    wp_for_post.
    iFrame "HΦ length".
    iDestruct (big_sepL2_snoc with "[$Hbig $Hown_m]") as "Hbig'".
    iExists (word.add j (W64 1)), (decoded ++ [m]), (ptrs ++ [a2]), lo2, lb1, t.
    iFrame.
    iPureIntro. rewrite length_app /=. split_and!; [word|word| |].
    + rewrite fmap_app join_app /= app_nil_r Hcons Hrest_eq. by rewrite -!app_assoc.
    + apply Forall_app. split; [done|]. by apply Forall_singleton.
Qed.

End proof.
End AuditProofSlice1D.

End ktcore.
