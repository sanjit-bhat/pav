From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof Require Import bytes.
From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi safemarshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  base ktcore serde sigpred.

Module ktcore.
Import ktcore.ktcore serde.ktcore sigpred.ktcore.

Module EvidVrf.
Record t :=
  mk' {
    VrfPk0: list w8;
    Sig0: list w8;
    VrfPk1: list w8;
    Sig1: list w8;
  }.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_VrfPk0 sl_Sig0 sl_VrfPk1 sl_Sig1,
  "Hstruct" ∷ ptr ↦{d} (ktcore.EvidVrf.mk sl_VrfPk0 sl_Sig0 sl_VrfPk1 sl_Sig1) ∗

  "Hsl_VrfPk0" ∷ sl_VrfPk0 ↦*{d} obj.(VrfPk0) ∗
  "Hsl_Sig0" ∷ sl_Sig0 ↦*{d} obj.(Sig0) ∗
  "Hsl_VrfPk1" ∷ sl_VrfPk1 ↦*{d} obj.(VrfPk1) ∗
  "Hsl_Sig1" ∷ sl_Sig1 ↦*{d} obj.(Sig1).

End proof.
End EvidVrf.

Module EvidLink.
Record t :=
  mk' {
    Epoch: w64;
    Link0: list w8;
    Sig0: list w8;
    Link1: list w8;
    Sig1: list w8;
  }.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_Link0 sl_Sig0 sl_Link1 sl_Sig1,
  "Hstruct" ∷ ptr ↦{d} (ktcore.EvidLink.mk obj.(Epoch) sl_Link0 sl_Sig0 sl_Link1 sl_Sig1) ∗

  "Hsl_Link0" ∷ sl_Link0 ↦*{d} obj.(Link0) ∗
  "Hsl_Sig0" ∷ sl_Sig0 ↦*{d} obj.(Sig0) ∗
  "Hsl_Link1" ∷ sl_Link1 ↦*{d} obj.(Link1) ∗
  "Hsl_Sig1" ∷ sl_Sig1 ↦*{d} obj.(Sig1).

End proof.
End EvidLink.

Module Evid.
Record t :=
  mk' {
    Vrf: option EvidVrf.t;
    Link: option EvidLink.t;
  }.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ ptr_Vrf ptr_Link,
  "Hstruct" ∷ ptr ↦{d} (ktcore.Evid.mk ptr_Vrf ptr_Link) ∗

  "Hown_Vrf" ∷
    match obj.(Vrf) with
    | Some Vrf => EvidVrf.own ptr_Vrf Vrf d
    | None => ⌜ptr_Vrf = null⌝
    end ∗
  "Hown_Link" ∷
    match obj.(Link) with
    | Some Link => EvidLink.own ptr_Link Link d
    | None => ⌜ptr_Link = null⌝
    end.

End proof.
End Evid.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition wish_EvidVrf e pk : iProp Σ :=
  "#Hwish0" ∷ wish_VrfSig pk e.(EvidVrf.VrfPk0) e.(EvidVrf.Sig0) ∗
  "#Hwish1" ∷ wish_VrfSig pk e.(EvidVrf.VrfPk1) e.(EvidVrf.Sig1) ∗
  "%Heq" ∷ ⌜e.(EvidVrf.VrfPk0) ≠ e.(EvidVrf.VrfPk1)⌝.

Lemma wish_EvidVrf_sigpred e pk γ :
  wish_EvidVrf e pk -∗
  ¬ cryptoffi.is_sig_pk pk (sigpred.P γ).
Proof.
  iIntros "@ #His_pk".
  iNamedSuffix "Hwish0" "0".
  iNamedSuffix "Hwish1" "1".
  iDestruct (cryptoffi.is_sig_to_pred with "His_pk His_sig0") as "#HP0".
  iDestruct (cryptoffi.is_sig_to_pred with "His_pk His_sig1") as "#HP1".
  iDestruct "HP0" as "[H|H]"; [|by iNamed "H"].
  iNamedSuffix "H" "0".
  iDestruct "HP1" as "[H|H]"; [|by iNamed "H"].
  iNamedSuffix "H" "1".
  remember (VrfSig.mk' _ _) as o0 in Henc0.
  remember (VrfSig.mk' _ _) as o1 in Henc0.
  opose proof (VrfSig.wish_det [] [] o0 o1 _ _) as [? _].
  { by list_simplifier. }
  { rewrite /VrfSig.wish.
    list_simplifier.
    intuition.
    by f_equal. }
  remember (VrfSig.mk' _ _) as o2 in Henc1.
  remember (VrfSig.mk' _ _) as o3 in Henc1.
  opose proof (VrfSig.wish_det [] [] o2 o3 _ _) as [? _].
  { by list_simplifier. }
  { rewrite /VrfSig.wish.
    list_simplifier.
    intuition.
    by f_equal. }
  iDestruct (sigpred.vrfP_evid with "Hsigpred0 Hsigpred1") as %->.
  simplify_eq/=.
Qed.

Lemma wp_EvidVrf_check ptr_e e sl_pk pk :
  {{{
    is_pkg_init ktcore ∗
    "#Hown_evid" ∷ EvidVrf.own ptr_e e (□) ∗
    "#Hsl_pk" ∷ sl_pk ↦*□ pk
  }}}
  ptr_e @! (go.PointerType ktcore.EvidVrf) @! "check" #sl_pk
  {{{
    (err : bool), RET #err;
    "Hgenie" ∷
      match err with
      | true => ¬ wish_EvidVrf e pk
      | false =>
        "#Hwish_EvidVrf" ∷ wish_EvidVrf e pk
      end
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hown_evid".
  wp_auto.
  wp_apply wp_VerifyVrfSig as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iIntros "@". by iApply "Hgenie". }
  iNamedSuffix "Hgenie" "0".
  wp_apply wp_VerifyVrfSig as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iIntros "@". by iApply "Hgenie". }
  iNamedSuffix "Hgenie" "1".
  wp_apply bytes.wp_Equal as "_".
  { iFrame "#". }
  iApply "HΦ".
  case_bool_decide.
  - by iIntros "@".
  - by iFrame "#".
Qed.

Definition wish_EvidLink e pk : iProp Σ :=
  "#Hwish0" ∷ wish_LinkSig pk e.(EvidLink.Epoch) e.(EvidLink.Link0) e.(EvidLink.Sig0) ∗
  "#Hwish1" ∷ wish_LinkSig pk e.(EvidLink.Epoch) e.(EvidLink.Link1) e.(EvidLink.Sig1) ∗
  "%Heq" ∷ ⌜e.(EvidLink.Link0) ≠ e.(EvidLink.Link1)⌝.

Lemma wish_EvidLink_sigpred e pk γ :
  wish_EvidLink e pk -∗
  ¬ cryptoffi.is_sig_pk pk (sigpred.P γ).
Proof.
  iIntros "@ #His_pk".
  destruct e. simpl in *.
  iNamedSuffix "Hwish0" "0".
  iNamedSuffix "Hwish1" "1".
  iDestruct (cryptoffi.is_sig_to_pred with "His_pk His_sig0") as "#HP0".
  iDestruct (cryptoffi.is_sig_to_pred with "His_pk His_sig1") as "#HP1".
  iDestruct "HP0" as "[H|H]"; [by iNamed "H"|].
  iNamedSuffix "H" "0".
  iDestruct "HP1" as "[H|H]"; [by iNamed "H"|].
  iNamedSuffix "H" "1".
  remember (LinkSig.mk' _ _ _) as o0 in Henc0.
  remember (LinkSig.mk' _ _ _) as o1 in Henc0.
  opose proof (LinkSig.wish_det [] [] o0 o1 _ _) as [? _].
  { by list_simplifier. }
  { rewrite /LinkSig.wish.
    list_simplifier.
    intuition.
    by f_equal. }
  remember (LinkSig.mk' _ _ _) as o2 in Henc1.
  remember (LinkSig.mk' _ _ _) as o3 in Henc1.
  opose proof (LinkSig.wish_det [] [] o2 o3 _ _) as [? _].
  { by list_simplifier. }
  { rewrite /LinkSig.wish.
    list_simplifier.
    intuition.
    by f_equal. }
  simplify_eq/=.
  iDestruct (sigpred.linkP_evid with "Hsigpred0 Hsigpred1") as %->.
  simplify_eq/=.
Qed.

Lemma wp_EvidLink_check ptr_e e sl_pk pk :
  {{{
    is_pkg_init ktcore ∗
    "#Hown_evid" ∷ EvidLink.own ptr_e e (□) ∗
    "#Hsl_pk" ∷ sl_pk ↦*□ pk
  }}}
  ptr_e @! (go.PointerType ktcore.EvidLink) @! "check" #sl_pk
  {{{
    (err : bool), RET #err;
    "Hgenie" ∷
      match err with
      | true => ¬ wish_EvidLink e pk
      | false =>
        "#Hwish_EvidLink" ∷ wish_EvidLink e pk
      end
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hown_evid".
  wp_auto.
  wp_apply wp_VerifyLinkSig as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iIntros "@". by iApply "Hgenie". }
  iNamedSuffix "Hgenie" "0".
  wp_apply wp_VerifyLinkSig as "* @".
  { iFrame "#". }
  wp_if_destruct.
  { iApply "HΦ". iIntros "@". by iApply "Hgenie". }
  iNamedSuffix "Hgenie" "1".
  wp_apply bytes.wp_Equal as "_".
  { iFrame "#". }
  iApply "HΦ".
  case_bool_decide.
  - by iIntros "@".
  - by iFrame "#".
Qed.

Definition wish_Evid e pk : iProp Σ :=
  match e.(Evid.Vrf), e.(Evid.Link) with
  | Some e', None => wish_EvidVrf e' pk
  | None, Some e' => wish_EvidLink e' pk
  | _, _ => False
  end.

Lemma wish_Evid_sigpred e pk γ :
  wish_Evid e pk -∗
  ¬ cryptoffi.is_sig_pk pk (sigpred.P γ).
Proof.
  iIntros "#Hwish #His_pk".
  destruct e.
  destruct Vrf as [Vrf|], Link as [Link|]; try done.
  - iNamed "Hwish".
    iApply (wish_EvidVrf_sigpred Vrf); [|done].
    by iFrame "#".
  - iNamed "Hwish".
    iApply (wish_EvidLink_sigpred Link); [|done].
    by iFrame "#".
Qed.

Lemma wp_Evid_Check ptr_e e sl_pk pk :
  {{{
    is_pkg_init ktcore ∗
    "#Hown_evid" ∷ Evid.own ptr_e e (□) ∗
    "#Hsl_pk" ∷ sl_pk ↦*□ pk
  }}}
  ptr_e @! (go.PointerType ktcore.Evid) @! "Check" #sl_pk
  {{{
    (err : bool), RET #err;
    "Hgenie" ∷
      match err with
      | true => ¬ wish_Evid e pk
      | false =>
        "#Hwish_Evid" ∷ wish_Evid e pk
      end
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hown_evid".
  wp_auto.
  destruct e. simpl.

  wp_if_destruct.
  2: {
    destruct Vrf.
    2: { by iDestruct "Hown_Vrf" as %?. }
    wp_if_destruct.
    2: {
      destruct Link.
      2: { by iDestruct "Hown_Link" as %?. }
      by iApply "HΦ". }
    destruct Link.
    { iNamedSuffix "Hown_Link" "'".
      by iDestruct (typed_pointsto_not_null with "Hstruct'") as %?. }
    wp_apply wp_EvidVrf_check as "* @".
    { iFrame "#". }
    by iApply "HΦ". }

  destruct Vrf.
  { iNamedSuffix "Hown_Vrf" "'".
    by iDestruct (typed_pointsto_not_null with "Hstruct'") as %?. }
  wp_if_destruct.
  { destruct Link.
    { iNamedSuffix "Hown_Link" "'".
      by iDestruct (typed_pointsto_not_null with "Hstruct'") as %?. }
    by iApply "HΦ". }
  destruct Link.
  2: { by iDestruct "Hown_Link" as %?. }
  wp_apply wp_EvidLink_check as "* @".
  { iFrame "#". }
  by iApply "HΦ".
Qed.

End proof.
End ktcore.
