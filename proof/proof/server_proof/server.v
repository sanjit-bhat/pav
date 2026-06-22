From New.generatedproof.github_com.sanjit_bhat.pav Require Import server.

From New.proof Require Import sync time.
From New.golang.theory.chan.idioms Require Import bag.
From New.proof.github_com.goose_lang Require Import std.
From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi hashchain ktcore merkle.

From New.proof.github_com.sanjit_bhat.pav.server_proof Require Import
  serde.

From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

Module server.
Import serde.server.

(** top-level server state and inv. *)

Module cfg.
Record t :=
  mk {
    sig_pk : list w8;
    pendγ : gname;
    (* map from uid to gname. *)
    uidγ : gmap w64 gname;
    agreeγ : ktcore.Agree.t;
  }.
End cfg.

Module state.
Record t :=
  mk {
    (* pending map of all keys.
    client gives server permission to add to this.
    all writable post-conds only reference pending. *)
    pending : ktcore.plain_ty;
    (* digs of digs.
    server can update this by adding dig that corresponds to curr pending.
    all read-only post-conds only reference digs. *)
    digs : list (list w8);
  }.
End state.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

(* TODO: [iDestruct own_aux as "[H0 H1]"] uses [into_sep_sep] (high priority)
instead of [into_sep_fractional_half] (priority 100).
not sure if this is a bug in instance priority. *)
Definition own_aux γ obj q : iProp Σ :=
  let agreeγ := γ.(cfg.agreeγ) in
  "Hown_pend" ∷ dghost_var γ.(cfg.pendγ) (DfracOwn q) obj.(state.pending) ∗
  (* client remembers lb's of this. *)
  "Hown_digs" ∷ mono_list_auth_own agreeγ.(ktcore.Agree.digs) q obj.(state.digs).

(* other 1/2 in server lock inv. *)
Definition own γ obj : iProp Σ := own_aux γ obj (1/2).

#[global] Instance own_aux_frac γ obj :
  fractional.Fractional (λ q, own_aux γ obj q).
Proof.
  intros ??. iSplit.
  - iIntros "@".
    iDestruct "Hown_pend" as "[? ?]".
    iDestruct "Hown_digs" as "[? ?]".
    iFrame.
  - iIntros "[H0 H1]".
    iNamedSuffix "H0" "0".
    iNamedSuffix "H1" "1".
    iCombine "Hown_pend0 Hown_pend1" as "?".
    iCombine "Hown_digs0 Hown_digs1" as "?".
    iFrame.
Qed.

#[global] Instance own_aux_as_frac γ obj q :
  fractional.AsFractional (own_aux γ obj q) (λ q, own_aux γ obj q) q.
Proof. auto. Qed.

#[global] Instance own_aux_combine_sep_gives γ obj0 obj1 q0 q1 :
  CombineSepGives (own_aux γ obj0 q0) (own_aux γ obj1 q1) (⌜obj0 = obj1⌝).
Proof.
  rewrite /CombineSepGives.
  iIntros "[H0 H1]".
  iNamedSuffix "H0" "0".
  iNamedSuffix "H1" "1".
  iCombine "Hown_pend0 Hown_pend1" gives %[? ?].
  iDestruct (mono_list_auth_own_agree with "Hown_digs0 Hown_digs1") as %[? ?].
  iModIntro.
  destruct obj0, obj1. by simplify_eq/=.
Qed.

#[global] Instance own_aux_combine_sep_as γ obj0 obj1 q0 q1 :
  CombineSepAs (own_aux γ obj0 q0) (own_aux γ obj1 q1) (own_aux γ obj0 (q0 + q1)) | 60.
Proof.
  rewrite /CombineSepAs.
  iIntros "[H0 H1]".
  iCombine "H0 H1" gives %->.
  by iCombine "H0 H1" as "H".
Qed.

Definition valid γ obj : iProp Σ :=
  let agreeγ := γ.(cfg.agreeγ) in
  "#Hperm_uids" ∷ ([∗ map] uid ↦ pks ∈ obj.(state.pending),
    ∃ uidγ,
    "%Hlook_uidγ" ∷ ⌜γ.(cfg.uidγ) !! uid = Some uidγ⌝ ∗
    "#Hpks" ∷ ([∗ list] ver ↦ pk ∈ pks,
      ∃ i,
      (* client owns mlist_auth for their uid.
      for adversarial uid, auth in inv. *)
      mono_list_idx_own uidγ i (ver, pk))) ∗
  "%Hsub_pend" ∷ ⌜∀ last_dig,
    last obj.(state.digs) = Some last_dig →
    ktcore.plain_sub (ktcore.to_plain agreeγ.(ktcore.Agree.vrf_pk) last_dig) obj.(state.pending)⌝ ∗
  "%Hsub_digs" ∷ ⌜ktcore.mono_plain agreeγ.(ktcore.Agree.vrf_pk) obj.(state.digs)⌝.

Definition inv_aux γ obj : iProp Σ :=
  "Hown_serv" ∷ own γ obj ∗
  "#His_serv" ∷ valid γ obj.

#[global] Instance inv_aux_timeless γ obj : Timeless (inv_aux γ obj).
Proof. apply _. Qed.

Definition is_inv γ := inv nroot (∃ obj, inv_aux γ obj).

(** helpers for inv. *)

Lemma digs_pks_prefix uid γ (i j : nat) (x y : list w8) :
  let agreeγ := γ.(cfg.agreeγ) in
  (i ≤ j)%nat →
  is_inv γ -∗
  mono_list_idx_own agreeγ.(ktcore.Agree.digs) i x -∗
  mono_list_idx_own agreeγ.(ktcore.Agree.digs) j y ={⊤}=∗
  ⌜ktcore.to_pks agreeγ.(ktcore.Agree.vrf_pk) uid x `prefix_of` ktcore.to_pks agreeγ.(ktcore.Agree.vrf_pk) uid y⌝.
Proof.
  simpl. iIntros (?) "#Hinv #Hidx0 #Hidx1".
  rewrite /is_inv.
  iInv "Hinv" as ">@" "Hclose".
  iNamed "Hown_serv".
  iDestruct (mono_list_auth_idx_lookup with "Hown_digs Hidx0") as %Hlook0.
  iDestruct (mono_list_auth_idx_lookup with "Hown_digs Hidx1") as %Hlook1.
  iMod ("Hclose" with "[-]") as "_"; [iFrame "∗#"|].
  iNamed "His_serv".
  iIntros "!> !%".
  by eapply ktcore.mono_plain_lookup.
Qed.

Lemma digs_to_put_perms γ i x :
  let agreeγ := γ.(cfg.agreeγ) in
  is_inv γ -∗
  mono_list_idx_own agreeγ.(ktcore.Agree.digs) i x ={⊤}=∗
  ∀ uid pks,
    ⌜ktcore.to_plain agreeγ.(ktcore.Agree.vrf_pk) x !! uid = Some pks⌝ -∗
    (* if empty pks, might not have uidγ. *)
    ⌜length pks > 0%nat⌝ -∗
    ∃ uidγ,
      ⌜γ.(cfg.uidγ) !! uid = Some uidγ⌝ ∗
      ([∗ list] ver ↦ pk ∈ pks,
        ∃ i,
        mono_list_idx_own uidγ i (ver, pk)).
Proof.
  simpl. iIntros "#Hinv #Hidx".
  rewrite /is_inv.
  iInv "Hinv" as ">@" "Hclose".
  iNamed "Hown_serv".
  iDestruct (mono_list_auth_idx_lookup with "Hown_digs Hidx") as %Hlook_digs.
  iMod ("Hclose" with "[-]") as "_"; [by iFrame "∗#"|].
  iNamed "His_serv".
  iModIntro.

  iIntros "* %Hlook_uid %Hlen_pks".
  apply lookup_lt_Some in Hlook_digs as ?.
  list_elem (obj.(state.digs)) (pred (length obj.(state.digs))) as last_dig.
  opose proof (ktcore.mono_plain_lookup uid _
    Hlook_digs Hlast_dig_lookup _) as Hsub0; [done|lia|].
  rewrite -last_lookup in Hlast_dig_lookup.
  apply Hsub_pend in Hlast_dig_lookup as Hsub1.
  specialize (Hsub1 uid).
  rewrite !lookup_total_alt in Hsub0.
  rewrite Hlook_uid /= in Hsub0.
  destruct (ktcore.to_plain _ last_dig !! uid) eqn:?.
  2: { apply prefix_length in Hsub0. simpl in *. lia. }
  simpl in *.
  case_match; try done.

  iDestruct (big_sepM_lookup with "Hperm_uids") as "@"; [done|].
  iFrame "%".
  iApply big_sepL_intro.
  iIntros "!> **".
  iApply (big_sepL_lookup with "Hpks").
  eapply prefix_lookup_Some; [|done].
  by eapply prefix_lookup_Some.
Qed.

(** state transition ops. *)

Definition perm_read γ Q : iProp Σ :=
  (|={⊤,∅}=>
    ∃ obj, own γ obj ∗
      (own γ obj
        ={∅,⊤}=∗ Q obj)).

Definition Q_read_lb prev_lb γ obj : iProp Σ :=
  let agreeγ := γ.(cfg.agreeγ) in
  mono_list_lb_own agreeγ.(ktcore.Agree.digs) obj.(state.digs) ∗
  ⌜prev_lb `prefix_of` obj.(state.digs)⌝.

Lemma op_read_lb γ prev_lb :
  let agreeγ := γ.(cfg.agreeγ) in
  is_inv γ -∗
  mono_list_lb_own agreeγ.(ktcore.Agree.digs) prev_lb -∗
  perm_read γ (Q_read_lb prev_lb γ).
Proof.
  simpl. iIntros "#Hinv #Hlb".
  rewrite /is_inv.
  iInv "Hinv" as ">@" "Hclose".
  iApply fupd_mask_intro.
  { set_solver. }
  iIntros "Hmask".
  iFrame.
  iIntros "@".
  iMod "Hmask" as "_".
  iDestruct (mono_list_lb_own_get with "Hown_digs") as "#Hlb'".
  iDestruct (mono_list_auth_lb_valid with "Hown_digs Hlb") as %[_ ?].
  iMod ("Hclose" with "[-]") as "_".
  - iFrame "∗#".
  - by iFrame "#%".
Qed.

Definition Q_read_idx prev_idx γ obj : iProp Σ :=
  let agreeγ := γ.(cfg.agreeγ) in
  mono_list_lb_own agreeγ.(ktcore.Agree.digs) obj.(state.digs) ∗
  ⌜prev_idx < length obj.(state.digs)⌝.

(* op_read_idx necessary, even tho weaker than op_read_lb.
cli_call takes in curried Q_read, since it's used in both pre and post.
at currying time, not under good flag, so client doesn't have prev_lb.
but it does have have prev_idx!
that's an arg to, e.g., CallHistory, independent of good-ness. *)
Lemma op_read_idx γ prev_idx (a : list w8) :
  let agreeγ := γ.(cfg.agreeγ) in
  is_inv γ -∗
  mono_list_idx_own agreeγ.(ktcore.Agree.digs) prev_idx a -∗
  perm_read γ (Q_read_idx prev_idx γ).
Proof.
  simpl. iIntros "#Hinv #Hidx".
  iDestruct "Hidx" as "(%&%Hlook&Hlb)".
  iMod (op_read_lb with "Hinv Hlb") as "{Hlb} (%&Hown&Hfupd)".
  iModIntro.
  iFrame.
  iIntros "Hown".
  iMod ("Hfupd" with "Hown") as "(Hlb&%Hpref)".
  iModIntro.
  iFrame "Hlb".
  apply lookup_lt_Some in Hlook.
  apply prefix_length in Hpref.
  word.
Qed.

(* caller doesn't need anything from Put.
and in fact, Put might logically execute *after* Put returns. *)
Definition perm_put γ uid ver pk : iProp Σ :=
  □ (|={⊤,∅}=> ∃ obj, own γ obj ∗
      (let pks := obj.(state.pending) !!! uid in
      let obj' := set state.pending <[uid:=pks ++ [pk]]> obj in
      ⌜ver = length pks⌝ -∗
      own γ obj' ={∅,⊤}=∗ True)).

Lemma op_put γ uid uidγ i ver pk :
  is_inv γ -∗
  ⌜γ.(cfg.uidγ) !! uid = Some uidγ⌝ -∗
  mono_list_idx_own uidγ i (ver, pk) -∗
  perm_put γ uid ver pk.
Proof.
  iIntros "#Hinv %Hlook_uidγ #Hmono_idx".
  iModIntro.
  rewrite /is_inv.
  iInv "Hinv" as ">@" "Hclose".
  iApply fupd_mask_intro.
  { set_solver. }
  iIntros "Hmask".
  iFrame.
  iIntros (->) "H".
  iMod "Hmask" as "_".
  iMod ("Hclose" with "[-]"); [|done].
  iModIntro.
  iFrame.

  destruct obj. simpl in *.
  iNamed "His_serv".
  iFrame "%". iSplit; try iPureIntro; simpl in *.
  - iApply big_sepM_insert_2; [|iFrame "#"].
    iFrame "%".
    iApply big_sepL_snoc.
    iFrame "#".
    rewrite lookup_total_alt.
    destruct (pending !! uid) eqn:Hlook;
      rewrite Hlook; simpl; [|done].
    iDestruct (big_sepM_lookup with "Hperm_uids") as "@"; [done|].
    by simplify_eq/=.
  - intros.
    trans pending; [naive_solver|].
    apply insert_included; [apply _|].
    intros.
    setoid_rewrite lookup_total_correct; [|done].
    by apply prefix_app_r.
Qed.

Definition perm_add_digs γ : iProp Σ :=
  let agreeγ := γ.(cfg.agreeγ) in
  □ (|={⊤,∅}=> ∃ obj, own γ obj ∗
    ∀ dig,
    ⌜ktcore.to_plain agreeγ.(ktcore.Agree.vrf_pk) dig = obj.(state.pending)⌝ -∗
    let obj' := set (state.digs) (.++ [dig]) obj in
    (own γ obj' ={∅,⊤}=∗ True)).

Lemma op_add_digs γ : is_inv γ -∗ perm_add_digs γ.
Proof.
  rewrite /perm_add_digs. iIntros "#Hinv".
  iModIntro.
  rewrite /is_inv.
  iInv "Hinv" as ">@" "Hclose".
  iApply fupd_mask_intro.
  { set_solver. }
  iIntros "Hmask".
  iFrame.
  iIntros "* %Hdig Hown_serv".
  iMod "Hmask" as "_".
  iMod ("Hclose" with "[-]"); [|done].
  iModIntro.
  iFrame.

  iNamed "His_serv".
  iFrame "#".
  destruct obj. simpl in *.
  iSplit; iPureIntro; simpl.
  - intros ? Hlast.
    rewrite last_snoc in Hlast.
    by simplify_eq/=.
  - unfold ktcore.mono_plain in *.
    rewrite !fmap_app /=.
    eapply list_reln_snoc; [done|].
    intros * Hlast.
    rewrite fmap_last in Hlast.
    apply fmap_Some in Hlast as (?&Hlast&?).
    rewrite fmap_last in Hlast.
    apply fmap_Some in Hlast as (?&Hlast&?).
    apply Hsub_pend in Hlast.
    by simplify_eq/=.
Qed.

End proof.

(** golang server state. *)

Module secrets.
Record t' := mk' {
  commit : list w8;
}.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Definition own γ ptr obj : iProp Σ :=
  let agreeγ := γ.(cfg.agreeγ) in
  ∃ ptr_sig ptr_vrf sl_commit,
  "#Hstr_secrets" ∷ ptr ↦□ (server.secrets.mk ptr_sig ptr_vrf sl_commit) ∗
  "#Hown_sig" ∷ cryptoffi.own_sig_sk ptr_sig γ.(cfg.sig_pk)
    (sigpred.P agreeγ) ∗
  "#Hown_vrf" ∷ cryptoffi.own_vrf_sk ptr_vrf agreeγ.(ktcore.Agree.vrf_pk) ∗
  "#Hsl_commit" ∷ sl_commit ↦*□ obj.(commit) ∗
  "%Hlen_commit" ∷ ⌜Z.of_nat (length obj.(commit)) = cryptoffi.hash_len⌝.

End proof.
End secrets.

Module keyStore.
Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Definition own_plain ptr0_plain (plain : ktcore.plain_ty) q : iProp Σ :=
  "Hptr0_plain" ∷ ([∗ map] uid ↦ sl_pks;pks ∈ ptr0_plain;plain,
    ∃ sl0_pks,
    "Hsl_pks" ∷ sl_pks ↦*{#q} sl0_pks ∗
    "Hcap_pks" ∷ own_slice_cap slice.t sl_pks (DfracOwn q) ∗
    "#Hsl0_pks" ∷ ([∗ list] sl_pk;pk ∈ sl0_pks;pks,
      "Hsl_pk" ∷ sl_pk ↦*□ pk)).

Definition is_commit commit_sec (hidden : gmap (list w8) (list w8)) :=
  map_Forall
    (λ map_label map_val,
      ∃ kt_pk rand,
      ktcore.map_val_inv_fn map_val = Some (kt_pk, rand) ∧
      ktcore.is_CommitRand commit_sec map_label rand)
    hidden.

Definition own γ ptr secs dig q : iProp Σ :=
  let agreeγ := γ.(cfg.agreeγ) in
  ∃ ptr_hidden hidden ptr_plain ptr0_plain,
  let plain := ktcore.to_plain agreeγ.(ktcore.Agree.vrf_pk) dig in
  "#Hstr_keyStore" ∷ ptr ↦□ (server.keyStore.mk ptr_hidden ptr_plain) ∗
  "Hown_hidden" ∷ merkle.own_Map ptr_hidden hidden dig (DfracOwn q) ∗
  "Hptr_plain" ∷ ptr_plain ↦${#q} ptr0_plain ∗
  "Hown_plain" ∷ own_plain ptr0_plain plain q ∗
  "%Hbij_maps" ∷ ⌜ktcore.is_plain agreeγ.(ktcore.Agree.vrf_pk) plain hidden⌝ ∗
  "%His_commit" ∷ ⌜is_commit secs.(secrets.commit) hidden⌝.

End proof.
End keyStore.

Module history.
Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Definition is_audits γ digs audits : iProp Σ :=
  "%Hlen_audits" ∷ ⌜length digs = length audits⌝ ∗
  (* epoch 0 UpdateProof is invalid. *)
  "#His_upds" ∷ ([∗ list] pred_ep ↦ aud ∈ drop 1 audits,
    ∃ dig0 dig1,
    "%Hlook0" ∷ ⌜digs !! pred_ep = Some dig0⌝ ∗
    "%Hlook1" ∷ ⌜digs !! (S pred_ep) = Some dig1⌝ ∗
    "#His_upd" ∷ ktcore.wish_ListUpdate dig0 aud.(ktcore.AuditProof.Updates) dig1) ∗
  "#His_sigs" ∷ ([∗ list] ep ↦ aud ∈ audits,
    ∃ link,
    "%His_link" ∷ ⌜hashchain.valid (take (S ep) digs) None link (S ep)⌝ ∗
    "#His_sig" ∷ ktcore.wish_LinkSig γ.(cfg.sig_pk) (W64 ep) link aud.(ktcore.AuditProof.LinkSig)).

Definition own γ ptr digs q : iProp Σ :=
  let agreeγ := γ.(cfg.agreeγ) in
  ∃ ptr_chain sl_audits sl0_audits audits sl_vrfSig vrfSig,
  "Hstr_history" ∷ ptr ↦{#q} (server.history.mk ptr_chain sl_audits sl_vrfSig) ∗
  "Hown_chain" ∷ hashchain.own ptr_chain digs (DfracOwn q) ∗

  "Hsl_audits" ∷ sl_audits ↦*{#q} sl0_audits ∗
  "Hcap_audits" ∷ own_slice_cap loc sl_audits (DfracOwn q) ∗
  "#Hown_audits" ∷ ([∗ list] idx ↦ p; aud ∈ sl0_audits; audits,
    ktcore.AuditProof.own p aud (□)) ∗
  "#His_audits" ∷ is_audits γ digs audits ∗
  "%Hmono_plain" ∷ ⌜ktcore.mono_plain agreeγ.(ktcore.Agree.vrf_pk) digs⌝ ∗

  "#Hsl_vrfSig" ∷ sl_vrfSig ↦*□ vrfSig ∗
  "#His_vrfSig" ∷ ktcore.wish_VrfSig γ.(cfg.sig_pk) agreeγ.(ktcore.Agree.vrf_pk) vrfSig.

Lemma is_audits_grow new_dig upd_proof sig link γ digs last_dig audits :
  let ep := length digs in
  last digs = Some last_dig →
  is_audits γ digs audits -∗
  ktcore.wish_ListUpdate last_dig upd_proof new_dig -∗
  ⌜hashchain.valid (digs ++ [new_dig]) None link (S ep)⌝ -∗
  ktcore.wish_LinkSig γ.(cfg.sig_pk) (W64 ep) link sig -∗
  is_audits γ (digs ++ [new_dig]) (audits ++ [ktcore.AuditProof.mk' upd_proof sig]).
Proof.
  simpl. iIntros (Hlast_dig) "#@ #Hupd %Hchain #Hsig".
  pose proof Hlast_dig as Hsome_eps.
  rewrite last_lookup in Hsome_eps.
  apply lookup_lt_Some in Hsome_eps.
  rewrite /is_audits.
  repeat iSplit; try done.
  - len.
  - rewrite drop_app_le; [|lia].
    iSplit.
    + iApply big_sepL_impl; [done|].
      iIntros "!>*%@".
      iFrame "#". iPureIntro.
      by eapply lookup_app_l_Some in Hlook0, Hlook1.
    + simpl. iSplit; [|done]. iFrame "#".
      iPureIntro. len.
      split.
      * rewrite last_lookup in Hlast_dig.
        eapply lookup_app_l_Some in Hlast_dig.
        exact_eq Hlast_dig. f_equal. lia.
      * replace (S _) with (pred $ length (digs ++ [new_dig])); [|len].
        by rewrite -last_lookup last_snoc.
  - simpl. iApply big_sepL_impl; [done|].
    iIntros "!>*%Hlook@".
    apply lookup_lt_Some in Hlook.
    autorewrite with len in *.
    iFrame "#". iPureIntro.
    by rewrite take_app_le; [|lia].
  - simpl.
    replace (length _ + 0)%nat with (length digs) by lia.
    iFrame "#". iPureIntro.
    by rewrite take_ge; [|len].
Qed.

End proof.
End history.

Module work.
Record t' := mk' {
  uid : w64;
  ver : w64;
  pk : list w8;
}.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Definition own γ secs ptr obj : iProp Σ :=
  let agreeγ := γ.(cfg.agreeγ) in
  ∃ sl_pk sl_mapLabel mapLabel sl_mapVal mapVal rand,
  "#Hstr_work" ∷ ptr ↦□ (server.work.mk obj.(uid) obj.(ver) sl_pk sl_mapLabel sl_mapVal) ∗
  "#Hsl_pk" ∷ sl_pk ↦*□ obj.(pk) ∗
  "#Hsl_mapLabel" ∷ sl_mapLabel ↦*□ mapLabel ∗
  "#Hsl_mapVal" ∷ sl_mapVal ↦*□ mapVal ∗

  "%His_mapLabel" ∷ ⌜ktcore.map_label_fn agreeγ.(ktcore.Agree.vrf_pk) obj.(uid)
    (uint.nat obj.(ver)) mapLabel⌝ ∗
  "%His_rand" ∷ ⌜ktcore.is_CommitRand secs.(secrets.commit) mapLabel rand⌝ ∗
  "%His_mapVal" ∷ ⌜ktcore.map_val_fn obj.(pk) rand mapVal⌝ ∗

  "#Hperm_put" ∷ perm_put γ obj.(uid) (uint.nat obj.(ver)) obj.(pk).

Definition own_aux γ secs (ptr : loc) : iProp Σ := ∃ obj, own γ secs ptr obj.

Definition own_sl γ secs sl_work work : iProp Σ :=
  ∃ sl0_work,
  "#Hsl_work" ∷ sl_work ↦*□ sl0_work ∗
  "#Hsl0_work" ∷ ([∗ list] ptr;obj ∈ sl0_work;work, own γ secs ptr obj).

End proof.
End work.

Module Server.
Record t' :=
  mk' {
    (* even tho secrets is static param, don't put it in global server γ.
    clients shouldn't depend on it being visible. *)
    secs : secrets.t';
  }.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Definition own_ro γ ptr obj : iProp Σ :=
  ∃ ptr_secs ptr_workQ workQγ,
  "#Hfld_secs" ∷ ptr.[server.Server.t, "secs"] ↦□ ptr_secs ∗
  "#Hfld_workQ" ∷ ptr.[server.Server.t, "workQ"] ↦□ ptr_workQ ∗

  "#Hown_secs" ∷ secrets.own γ ptr_secs obj.(secs) ∗
  "#His_workQ" ∷ bag.is_chan_bag workQγ ptr_workQ (work.own_aux γ obj.(secs)).

Definition own γ ptr σ obj q : iProp Σ :=
  let agreeγ := γ.(cfg.agreeγ) in
  ∃ ptr_keys ptr_hist last_dig,
  "#Hfld_keys" ∷ ptr.[server.Server.t, "keys"] ↦□ ptr_keys ∗
  "#Hfld_hist" ∷ ptr.[server.Server.t, "hist"] ↦□ ptr_hist ∗

  "Hown_keys" ∷ keyStore.own γ ptr_keys obj.(secs) last_dig q ∗
  "Hown_hist" ∷ history.own γ ptr_hist σ.(state.digs) q ∗

  (* other 1/2 in server inv. *)
  "Hown_gs" ∷ own_aux γ σ (q/2) ∗
  "%Hlast_dig" ∷ ⌜last σ.(state.digs) = Some last_dig⌝ ∗
  "%Heq_hist_pend" ∷ ⌜ktcore.to_plain agreeγ.(ktcore.Agree.vrf_pk) last_dig = σ.(state.pending)⌝ ∗
  "#Hperm_add_digs" ∷ perm_add_digs γ ∗
  "%Heq_digs_start" ∷ ⌜agreeγ.(ktcore.Agree.digs_start) = 0%nat⌝ ∗
  "%Heq_cut" ∷ ⌜agreeγ.(ktcore.Agree.cut) = None⌝ ∗
  "%Heq_func_start" ∷ ⌜agreeγ.(ktcore.Agree.func_start) = 0%nat⌝.

Definition own_aux γ ptr obj q : iProp Σ := ∃ σ, own γ ptr σ obj q.

Definition lock_perm γ ptr obj : iProp Σ :=
  ∃ ptr_mu,
  "#Hfld_mu" ∷ ptr.[server.Server.t, "mu"] ↦□ ptr_mu ∗

  "Hlock" ∷ own_RWMutex ptr_mu (own_aux γ ptr obj) ∗
  "#Hown_ro" ∷ own_ro γ ptr obj.

End proof.
End Server.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

(** fetch-side helper funcs. *)

Lemma wp_Server_getHist s γ σ obj (uid prefixLen : w64) q last_dig :
  let agreeγ := γ.(cfg.agreeγ) in
  let pks := ktcore.to_pks agreeγ.(ktcore.Agree.vrf_pk) uid last_dig in
  {{{
    is_pkg_init server ∗
    "Hown_serv" ∷ Server.own γ s σ obj q ∗
    "#Hown_serv_ro" ∷ Server.own_ro γ s obj ∗
    "%Hlast_dig" ∷ ⌜last σ.(state.digs) = Some last_dig⌝ ∗
    "%Heq_prefixLen" ∷ ⌜uint.nat prefixLen ≤ length pks⌝
  }}}
  s @! (go.PointerType server.Server) @! "getHist" #uid #prefixLen
  {{{
    sl_hist hist, RET #sl_hist;
    "Hown_serv" ∷ Server.own γ s σ obj q ∗
    "#Hsl_hist" ∷ ktcore.MembSlice1D.own sl_hist hist (□) ∗
    "#Hwish_hist" ∷ ktcore.wish_ListMemb agreeγ.(ktcore.Agree.vrf_pk) uid
      (uint.nat prefixLen) last_dig hist ∗
    "%Heq_hist" ∷ ⌜drop (uint.nat prefixLen) pks =
      ktcore.CommitOpen.Val <$> (ktcore.Memb.PkOpen <$> hist)⌝
  }}}.
Proof.
  simpl. wp_start as "@".
  iNamed "Hown_serv_ro". iNamed "Hown_secs".
  iNamed "Hown_serv". iNamed "Hown_keys".
  rewrite /keyStore.own_plain. iNamed "Hown_plain".
  simplify_eq/=. wp_auto.
  wp_apply (wp_map_lookup1 with "[$Hptr_plain]") as "Hptr_plain".
  (* destruct "uid existence" early to reduce complexity. *)
  destruct (ktcore.to_plain (γ.(cfg.agreeγ).(ktcore.Agree.vrf_pk)) last_dig !! uid) as [pks|] eqn:Hlook_uid.
  2: {
    rewrite lookup_total_alt Hlook_uid /= in Heq_prefixLen |-*.
    iDestruct (big_sepM2_lookup_r_none with "Hptr0_plain") as %->; [done|].
    assert (prefixLen = W64 0) as -> by word.
    replace (uint.nat (W64 0)) with 0%nat by word.
    simpl in *.
    wp_apply wp_slice_make3 as "* (Hsl_hist&_)"; [word|].
    iPersist "Hsl_hist".
    replace (sint.nat _) with 0%nat by word.
    wp_for.
    iApply ("HΦ" $! _ []).
    iFrame "∗#%".
    simpl. repeat iSplit; try done.
    rewrite /ktcore.wish_ListMemb. naive_solver. }

  rewrite lookup_total_alt Hlook_uid /= in Heq_prefixLen |-*.
  iDestruct (big_sepM2_lookup_r_some with "Hptr0_plain") as %[sl_pks Hlook_uid']; [done|].
  iDestruct (big_sepM2_lookup_acc with "Hptr0_plain") as "(@&Hclose)"; [done..|].
  iDestruct (own_slice_len with "Hsl_pks") as %?.
  iDestruct (big_sepL2_length with "Hsl0_pks") as %?.
  rewrite Hlook_uid' /=.
  wp_apply wp_slice_make3 as "* (Hsl_hist&Hcap_hist&_)"; [word|].
  replace (sint.nat _) with 0%nat by word.
  simpl.
  iPersist "s uid pks numVers".
  iAssert (
    ∃ (ver : w64) sl_hist sl0_hist hist,
    "ver" ∷ ver_ptr ↦ ver ∗
    "%Heq_ver" ∷ ⌜uint.nat ver = (uint.nat prefixLen + length hist)%nat⌝ ∗
    "%Hlt_ver" ∷ ⌜uint.nat ver ≤ length pks⌝ ∗
    "hist" ∷ hist_ptr ↦ sl_hist ∗
    "Hsl_hist" ∷ sl_hist ↦* sl0_hist ∗
    "Hcap_hist" ∷ own_slice_cap loc sl_hist 1 ∗
    "#Hsl0_hist" ∷ ([∗ list] ptr;obj ∈ sl0_hist;hist, ktcore.Memb.own ptr obj (□)) ∗

    "#Hwish_hist" ∷ ktcore.wish_ListMemb (γ.(cfg.agreeγ).(ktcore.Agree.vrf_pk)) uid
      (uint.nat prefixLen) last_dig hist ∗
    "%Heq_hist" ∷ ⌜subslice (uint.nat prefixLen) (uint.nat ver) pks =
      ktcore.CommitOpen.Val <$> (ktcore.Memb.PkOpen <$> hist)⌝
  )%I with "[hist Hsl_hist Hcap_hist ver]" as "IH".
  { iFrame "∗". iExists [].
    repeat iSplit; try done.
    - naive_solver.
    - rewrite /ktcore.wish_ListMemb. naive_solver.
    - by rewrite subslice_zero_length. }
  rewrite -wp_fupd.
  wp_for "IH".
  wp_if_destruct.
  2: {
    replace (uint.nat ver) with (length pks) in Heq_hist by word.
    rewrite subslice_to_end in Heq_hist; [|lia].
    iPersist "Hsl_hist".
    iDestruct ("Hclose" with "[$Hsl_pks $Hcap_pks //]") as "Hptr0_plain".
    iApply "HΦ".
    by iFrame "∗#%". }

  list_elem pks (uint.nat ver) as pk.
  iDestruct (big_sepL2_lookup_r with "Hsl0_pks") as (sl_pk) "(%Hpk_lookup'&@)"; [done|].
  wp_apply ktcore.wp_ProveMapLabel as "* @".
  { iFrame "#". }
  wp_apply (merkle.wp_Map_Prove with "[$Hown_hidden]") as "{Hsl_label} * @".
  { iFrame "#".
    by destruct His_Label as (?%cryptoffi.is_vrf_len&_). }
  iPersist "Hsl_label Hsl_entryProof".
  destruct (hidden !! label) as [map_val|] eqn:Hlook_hidden.
  2: {
    exfalso. subst.
    opose proof ((proj1 Hbij_maps) _ _ Hlook_uid) as [_ Ht].
    odestruct (Ht _ _ Hpk_lookup) as (?&Hlab&?&?&?&?).
    apply ktcore.map_label_iff in Hlab.
    opose proof (ktcore.map_label_det His_Label Hlab) as <-.
    simplify_eq/=. }
  destruct_and?. subst.
  wp_apply wp_Assert; [done|].
  wp_apply ktcore.wp_GetCommitRand as "* @".
  { iFrame "#". }
  case_decide; [|word].
  wp_apply (wp_load_slice_index with "[$Hsl_pks]") as "Hsl_pks"; [word|..].
  { iPureIntro. exact_eq Hpk_lookup'. f_equal. word. }
  wp_apply wp_alloc as "%ptr_open Hptr_open".
  wp_apply wp_alloc as "%ptr_memb Hptr_memb".
  wp_apply wp_slice_literal. iSplitR; first done. iIntros "* [Ht _]". wp_auto.
  replace (sint.nat _) with 0%nat by word. simpl.
  iPersist "Hptr_open Hptr_memb".
  wp_apply (wp_slice_append with "[$Hsl_hist $Hcap_hist $Ht]")
    as "%sl_hist' (Hsl_hist&Hcap_hist&_)".
  wp_for_post.
  iFrame.
  iExists (hist ++ [ktcore.Memb.mk' _ (ktcore.CommitOpen.mk' _ _) _]).
  iSplit; [len|].
  iSplit; [word|].
  iSplit. { iApply big_sepL2_snoc. iFrame "#". }
  iSplit.
  2: {
    iPureIntro.
    rewrite !fmap_snoc /=.
    replace (uint.nat (word.add _ _)) with (S $ uint.nat ver) by word.
    erewrite subslice_snoc; [|done|word].
    by rewrite Heq_hist. }
  rewrite /ktcore.wish_ListMemb.
  iApply big_sepL_snoc.
  rewrite -Heq_ver.
  iFrame "#%". simpl.
  replace (W64 _) with ver by word. iFrame "#".
  iPureIntro. rewrite /ktcore.map_val_fn.
  opose proof ((proj1 Hbij_maps) _ _ Hlook_uid) as [_ Ht].
  odestruct (Ht _ _ Hpk_lookup) as (?&Hlab%ktcore.map_label_iff&?&?&Hval&?).
  opose proof (ktcore.map_label_det His_Label Hlab) as <-.
  opose proof (His_commit _ _ Hlook_hidden) as (?&?&?&Hrand).
  opose proof (ktcore.is_CommitRand_det His_CommitRand Hrand) as <-.
  simplify_eq/=.
  by apply ktcore.map_val_iff in Hval.
Qed.

Lemma wp_Server_getBound s γ σ obj (uid numVers : w64) q last_dig :
  let agreeγ := γ.(cfg.agreeγ) in
  let pks := ktcore.to_pks agreeγ.(ktcore.Agree.vrf_pk) uid last_dig in
  {{{
    is_pkg_init server ∗
    "Hown_serv" ∷ Server.own γ s σ obj q ∗
    "#Hown_serv_ro" ∷ Server.own_ro γ s obj ∗
    "%Hlast_dig" ∷ ⌜last σ.(state.digs) = Some last_dig⌝ ∗
    "%Heq_numVers" ∷ ⌜uint.nat numVers = length pks⌝
  }}}
  s @! (go.PointerType server.Server) @! "getBound" #uid #numVers
  {{{
    ptr_bound bound, RET #ptr_bound;
    "Hown_serv" ∷ Server.own γ s σ obj q ∗
    "#Hptr_bound" ∷ ktcore.NonMemb.own ptr_bound bound (□) ∗
    "#Hwish_bound" ∷ ktcore.wish_NonMemb agreeγ.(ktcore.Agree.vrf_pk) uid
      (uint.nat numVers) last_dig bound
  }}}.
Proof.
  simpl. wp_start as "@".
  iNamed "Hown_serv_ro". iNamed "Hown_secs".
  iNamed "Hown_serv". iNamed "Hown_keys".
  simplify_eq/=. wp_auto.
  wp_apply ktcore.wp_ProveMapLabel as "* @".
  { iFrame "#". }
  wp_apply (merkle.wp_Map_Prove with "[$Hown_hidden]") as "{Hsl_label} * @".
  { iFrame "#".
    by destruct His_Label as (?%cryptoffi.is_vrf_len&_). }
  iPersist "Hsl_label Hsl_entryProof".
  destruct (hidden !! label) eqn:Hlook_hidden.
  { exfalso. destruct_and?. subst.
    opose proof ((proj2 Hbij_maps) _ _ Hlook_hidden) as Ht.
    rewrite /= /ktcore.in_plain in Ht.
    destruct_exis. destruct Ht as (?&?&?&?%lookup_lt_Some).
    apply ktcore.map_label_iff in His_Label.
    simplify_eq/=.
    erewrite lookup_total_correct in Heq_numVers; [|done].
    len. }
  subst.
  wp_apply wp_Assert; [done|].
  rewrite -wp_fupd.
  wp_apply wp_alloc as "* Hown_bound".
  iPersist "Hown_bound".
  iApply "HΦ".
  instantiate (1:=ktcore.NonMemb.mk' _ _).
  iFrame "∗#%". simpl.
  replace (W64 _) with numVers by word.
  by iFrame "#".
Qed.

(** update-side helper funcs. *)

Lemma wp_Server_getWork s γ obj :
  {{{
    is_pkg_init server ∗
    "#Hown_serv_ro" ∷ Server.own_ro γ s obj
  }}}
  s @! (go.PointerType server.Server) @! "getWork" #()
  {{{
    sl_work work, RET #sl_work;
    "#Hown_work_sl" ∷ work.own_sl γ obj.(Server.secs) sl_work work
  }}}.
Proof.
  wp_start as "@".
  iDestruct (is_pkg_init_access with "[$]") as "@".
  iNamed "Hown_serv_ro". wp_auto.
  (* TODO: translate/prove [Timer] and [NewTimer], assuming [newTimer]. *)
Admitted.

Lemma wp_Server_doWork s γ obj sl_work work :
  {{{
    is_pkg_init server ∗
    "Hown_serv_lock" ∷ Server.lock_perm γ s obj ∗
    "#Hown_work_sl" ∷ work.own_sl γ obj.(Server.secs) sl_work work
  }}}
  s @! (go.PointerType server.Server) @! "doWork" #sl_work
  {{{
    RET #();
    "Hown_serv_lock" ∷ Server.lock_perm γ s obj
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hown_serv_lock".
  iNamed "Hown_ro".
  wp_apply wp_with_defer as "* Hdefer". simpl.
  wp_auto.
  wp_apply (wp_RWMutex__Lock with "[$Hlock]") as "(Hlocked&H)".
  iNamed "H".
  iNamed "Hown_work_sl".
  iDestruct (own_slice_len with "Hsl_work") as %?.
  wp_apply wp_slice_make3 as "%sl_upd (Hsl_upd&Hcap_upd&_)"; [word|].
  replace (sint.nat _) with 0%nat by word. simpl.
  destruct σ. simpl in *.
  subst.

  iAssert (
    ∃ (i : w64) (t0 : loc) sl_upd sl0_upd upd new_dig,
    let agreeγ := γ.(cfg.agreeγ) in
    let new_pend := ktcore.to_plain agreeγ.(ktcore.Agree.vrf_pk) new_dig in
    "i" ∷ i_ptr ↦ i ∗
    "%Hlt_i" ∷ ⌜0 ≤ sint.Z i ≤ length work⌝ ∗
    "w" ∷ w_ptr ↦ t0 ∗
    "upd" ∷ upd_ptr ↦ sl_upd ∗
    "Hsl_upd" ∷ sl_upd ↦* sl0_upd ∗
    "Hcap_upd" ∷ own_slice_cap loc sl_upd 1 ∗
    "#Hsl0_upd" ∷ ([∗ list] ptr;obj ∈ sl0_upd;upd, ktcore.UpdateProof.own ptr obj (□)) ∗
    "#His_upd" ∷ ktcore.wish_ListUpdate last_dig upd new_dig ∗
    "%Hmono" ∷ ⌜ktcore.plain_sub (ktcore.to_plain agreeγ.(ktcore.Agree.vrf_pk) last_dig)
      (ktcore.to_plain agreeγ.(ktcore.Agree.vrf_pk) new_dig)⌝ ∗
    "Hown_keys" ∷ keyStore.own γ ptr_keys obj.(Server.secs) new_dig 1 ∗
    "Hown_gs" ∷ own_aux γ {| state.pending := new_pend; state.digs := digs |} (1/2)
  )%I with "[Hown_keys Hown_gs upd Hsl_upd Hcap_upd w i]" as "IH".
  { iFrame "∗". iExists []. simpl.
    iSplit; [word|].
    iSplit; [done|].
    iSplit. { by iApply ktcore.wish_ListUpdate_nil. }
    done. }
  wp_for "IH".
  case_bool_decide.
  { rename new_dig into old_dig.
    iNamed "Hown_keys".
    iDestruct (own_slice_len with "Hsl_work") as %?.
    iDestruct (big_sepL2_length with "Hsl0_work") as %?.
    list_elem work (sint.nat i) as w.
    iDestruct (big_sepL2_lookup_r with "Hsl0_work") as (ptr_w) "(%&@)"; [done|].
    (* TODO: code ordering display inside for-loop is screwed up. *)
    wp_auto.
    case_decide as Ht; [|word]. clear Ht.
    (* TODO: for some reason, [as "_"] is slow as hell here. *)
    wp_apply wp_load_slice_index; [word|by iFrame "#"|].
    iIntros "_".
    wp_auto. simpl.
    wp_apply (wp_map_lookup1 with "[$Hptr_plain]") as "Hptr_plain".
    case_bool_decide as Ht; wp_auto.
    2: { wp_for_post. iFrame "Hown_hist ∗#%". word. }

    (* unify cases of uid in or not in golang map. *)
    iAssert (
      ∃ sl0_pks,
      let agreeγ := γ.(cfg.agreeγ) in
      let sl_pks := default slice.nil (ptr0_plain !! w.(work.uid)) in
      "Hsl_pks" ∷ sl_pks ↦* sl0_pks ∗
      "Hcap_pks" ∷ own_slice_cap slice.t sl_pks 1 ∗
      "#Hsl0_pks" ∷ ([∗ list] sl_pk;pk ∈
        sl0_pks;ktcore.to_pks agreeγ.(ktcore.Agree.vrf_pk) w.(work.uid) old_dig,
        "Hsl_pk" ∷ sl_pk ↦*□ pk) ∗
      "Hown_plain" ∷ keyStore.own_plain (delete w.(work.uid) ptr0_plain)
        (delete w.(work.uid) (ktcore.to_plain agreeγ.(ktcore.Agree.vrf_pk) old_dig)) 1
    )%I with "[Hown_plain]" as "@".
    { destruct (ptr0_plain !! _) eqn:?; simpl in *.
      - iDestruct (big_sepM2_delete_l with "Hown_plain") as "(%&%&@&Hown_plain)"; [done|].
        erewrite lookup_total_correct; [|done].
        iFrame "∗#".
      - iDestruct (big_sepM2_lookup_l_none with "Hown_plain") as %Ht0; [done|].
        iDestruct own_slice_nil as "$".
        iDestruct own_slice_cap_nil as "$".
        rewrite lookup_total_alt Ht0 /=.
        iSplit; [done|].
        rewrite !delete_id; [|done..].
        iFrame. }
    iDestruct (own_slice_len with "Hsl_pks") as %?.
    iDestruct (big_sepL2_length with "Hsl0_pks") as %?.

    iAssert (let agreeγ := γ.(cfg.agreeγ) in
      ⌜uint.nat w.(work.ver) =
      length $ ktcore.to_pks agreeγ.(ktcore.Agree.vrf_pk) w.(work.uid) old_dig⌝)%I
      as %Heq_ver; [word|].
    clear Ht.
    destruct (hidden !! mapLabel) eqn:Hlook_hid.
    { exfalso.
      opose proof ((proj2 Hbij_maps) _ _ Hlook_hid) as Ht.
      rewrite /= /ktcore.in_plain in Ht.
      destruct_exis. destruct Ht as (?&?&?&?%lookup_lt_Some).
      apply ktcore.map_label_iff in His_mapLabel.
      simplify_eq/=.
      erewrite lookup_total_correct in Heq_ver; [|done].
      word. }

    iApply ncfupd_wp.
    rewrite /own.
    iMod "Hperm_put" as "(%obj'&Hown_gs'&Hperm)".
    destruct obj'.
    iCombine "Hown_gs Hown_gs'" as "Hown_gs" gives %?.
    (* TODO: 1/2 + 1/2 not getting reduced. *)
    rewrite Qp.half_half.
    simplify_eq/=.
    iSpecialize ("Hperm" with "[]"); [word|].
    iNamedSuffix "Hown_gs" "_gs".
    simpl.
    iMod (dghost_var_update with "Hown_pend_gs") as "[Hpend Hpend']".
    iDestruct "Hown_digs_gs" as "[Hdigs Hdigs']".
    iMod ("Hperm" with "[$Hpend' $Hdigs']") as "_".
    iAssert (own_aux _ _ (1/2))%I with "[$Hpend $Hdigs]" as "Hown_gs".
    iModIntro.

    wp_apply (merkle.wp_Map_Put with "[$Hown_hidden]") as "%%%new_dig @".
    { iFrame "#%".
      destruct His_mapLabel as (Ht&_).
      by apply cryptoffi.is_vrf_len in Ht. }
    iPersist "Hsl_updProof". simpl.
    wp_apply (wp_map_lookup1 with "[$Hptr_plain]") as "Hptr_plain".
    wp_apply wp_slice_literal. iSplitR; first done. iIntros "* [Ht _]". wp_auto.
    replace (sint.nat _) with 0%nat by word. simpl.
    wp_apply (wp_slice_append with "[$Hsl_pks $Hcap_pks $Ht]")
      as "%sl_pks (Hsl_pks&Hcap_pks&_)".
    simpl. wp_apply (wp_map_insert with "[$Hptr_plain]") as "Hptr_plain".
    wp_apply wp_alloc as "%ptr_info Hptr_info".
    iPersist "Hptr_info".
    wp_apply wp_slice_literal. iSplitR; first done. iIntros "* [Ht _]". wp_auto.
    replace (sint.nat _) with 0%nat by word. simpl.
    wp_apply (wp_slice_append with "[$Hsl_upd $Hcap_upd $Ht]")
      as "%sl_upd' (Hsl_upd&Hcap_upd&_)".

    wp_for_post.
    iDestruct (merkle.own_Map_to_is_map with "Hown_Map") as %[Hnew_dig _].
    iFrame "Hown_hist ∗#".
    eapply ktcore.plain_insert in Hbij_maps; cycle 1.
    { exact_eq His_mapLabel. word. }
    { done. }
    apply ktcore.is_plain_has_inv in Hbij_maps as Hnew_inv_plain.
    rewrite Hnew_dig Hnew_inv_plain.
    iDestruct (big_sepL2_snoc with "[$Hsl0_pks $Hsl_pk]") as "{Hsl0_pks} Hsl0_pks".
    iDestruct (big_sepM2_insert_delete with "[$Hown_plain $Hsl_pks $Hcap_pks //]") as "Hown_plain".
    iFrame "∗%".
    iExists (_ ++ [_]). repeat iSplit; try iPureIntro.
    - word.
    - word.
    - iFrame "#".
    - instantiate (1:=ktcore.UpdateProof.mk' _ _ _). iFrame "#".
    - done.
    - by iApply ktcore.wish_ListUpdate_grow.
    - trans (ktcore.to_plain (γ.(cfg.agreeγ).(ktcore.Agree.vrf_pk)) old_dig); [done|].
      apply insert_included; [apply _|].
      intros.
      setoid_rewrite lookup_total_correct; [|done].
      by apply prefix_app_r.
    - apply map_Forall_insert_2; [|done].
      apply ktcore.map_val_iff in His_mapVal.
      naive_solver. }

  iNamed "Hown_secs". iNamed "Hown_keys".
  iNamed "Hown_hist". iNamed "His_audits".
  wp_auto.
  iDestruct (merkle.own_Map_to_is_map with "Hown_hidden") as %[_ ?].
  wp_apply (merkle.wp_Map_Hash with "[$Hown_hidden]") as "* @".
  wp_apply (hashchain.wp_HashChain_Append with "[$Hown_chain]") as "* @ {Hsl_val}".
  { by iFrame "#". }

  iApply ncfupd_wp.
  rewrite /own.
  iPoseProof "Hperm_add_digs" as "Hperm".
  iMod "Hperm" as "(%obj'&Hown_gs'&Hperm)".
  destruct obj'.
  iCombine "Hown_gs Hown_gs'" as "Hown_gs" gives %?.
  (* TODO: 1/2 + 1/2 not getting reduced. *)
  rewrite Qp.half_half.
  simplify_eq/=.
  iSpecialize ("Hperm" with "[]"); [done|].
  iNamedSuffix "Hown_gs" "_gs".
  simpl.
  iMod (mono_list_auth_own_update_app [new_dig] with "Hown_digs_gs") as "[[Hdigs Hdigs'] #Hlb_digs]".
  iDestruct "Hown_pend_gs" as "[Hpend Hpend']".
  iMod ("Hperm" with "[$Hpend' $Hdigs']") as "_".
  iAssert (own_aux _ (state.mk _ _) (1/2))%I with "[$Hpend $Hdigs]" as "Hown_gs".
  iModIntro.

  iDestruct (own_slice_len with "Hsl_audits") as %?.
  iDestruct (big_sepL2_length with "Hown_audits") as %?.
  eassert (ktcore.mono_plain (γ.(cfg.agreeγ).(ktcore.Agree.vrf_pk)) (_ ++ [_])) as Hmono_plain'.
  { rewrite /ktcore.mono_plain in Hmono_plain |-*.
    rewrite !fmap_app.
    eapply list_reln_snoc; [done|].
    intros * Hlast_digs.
    rewrite !fmap_last Hlast_dig /= in Hlast_digs.
    by simplify_eq/=. }
  clear Hmono_plain.
  wp_apply ktcore.wp_SignLink as "* @".
  { iFrame "#". iPureIntro.
    rewrite Heq_cut Heq_digs_start Heq_func_start.
    split; [|repeat split].
    - exact_eq His_chain. word.
    - len.
    - lia.
    - by rewrite drop_0. }

  wp_apply wp_alloc as "%ptr_audit Hptr_audit".
  iPersist "Hptr_audit".
  wp_apply wp_slice_literal. iSplitR; first done. iIntros "* [Ht _]". wp_auto.
  replace (sint.nat _) with 0%nat by word. simpl.
  wp_apply (wp_slice_append with "[$Hsl_audits $Hcap_audits $Ht]")
    as "%sl_audits' (Hsl_audits&Hcap_audits&_)".
  iPersist "Hsl_upd". iClear "Hcap_upd".
  wp_apply (wp_RWMutex__Unlock with "[-HΦ $Hlocked]") as "Hlock".
  2: { iApply "HΦ". iFrame "∗#%". }
  iDestruct (history.is_audits_grow with "[][//][//][]") as "His_audits"; [done|..].
  { by iFrame "#". }
  { iExactEq "Hwish_LinkSig". f_equal. word. }
  iFrame "∗#%".
  simpl. repeat iSplit; try done.
  iPureIntro. by rewrite last_snoc.
Qed.

Lemma wp_Server_worker s γ obj :
  {{{
    is_pkg_init server ∗
    "Hown_serv_lock" ∷ Server.lock_perm γ s obj
  }}}
  s @! (go.PointerType server.Server) @! "worker" #()
  {{{ RET #(); True }}}.
Proof.
  wp_start as "@". wp_auto.
  wp_for "Hown_serv_lock".
  wp_apply wp_Server_getWork as "* @"; [done|].
  wp_if_destruct.
  { wp_for_post. iFrame "∗#". }
  wp_apply (wp_Server_doWork with "[$Hlock]") as "@".
  { iFrame "#". }
  wp_for_post.
  iFrame "∗#".
Qed.

(** top-level methods. *)

Lemma wp_Server_Put s γ obj uid sl_pk pk (ver : w64) :
  {{{
    is_pkg_init server ∗
    "#Hown_serv_ro" ∷ Server.own_ro γ s obj ∗
    "#Hsl_pk" ∷ sl_pk ↦*□ pk ∗
    "#Hperm_put" ∷ perm_put γ uid (uint.nat ver) pk
  }}}
  s @! (go.PointerType server.Server) @! "Put" #uid #ver #sl_pk
  {{{ RET #(); True }}}.
Proof.
  wp_start as "@".
  iNamed "Hown_serv_ro". iNamed "Hown_secs".
  wp_auto.
  wp_apply ktcore.wp_EvalMapLabel as "* @".
  { iFrame "#". }
  wp_apply ktcore.wp_GetCommitRand as "* @".
  { iFrame "#". }
  wp_apply ktcore.wp_GetMapVal as "* @".
  { iFrame "#". }
  wp_apply wp_alloc as "* Hptr_work".
  iPersist "Hptr_work".
  wp_apply wp_bag_send.
  { iFrame "His_workQ".
    rewrite /work.own_aux. iExists (work.mk' _ _ _).
    iFrame "Hptr_work #%". }
  wp_end.
Qed.

Lemma wp_Server_History s γ obj (uid prevEpoch prevVerLen : w64) Q :
  {{{
    is_pkg_init server ∗
    "Hown_serv_lock" ∷ Server.lock_perm γ s obj ∗
    "Hperm_read" ∷ perm_read γ Q
  }}}
  s @! (go.PointerType server.Server) @! "History" #uid #prevEpoch #prevVerLen
  {{{
    sl_chainProof sl_linkSig sl_hist ptr_bound err σ lastDig,
    RET (#sl_chainProof, #sl_linkSig, #sl_hist, #ptr_bound, #err);
    let agreeγ := γ.(cfg.agreeγ) in
    let numEps := length σ.(state.digs) in
    let pks := ktcore.to_pks agreeγ.(ktcore.Agree.vrf_pk) uid lastDig in
    "Hown_serv_lock" ∷ Server.lock_perm γ s obj ∗
    "HQ" ∷ Q σ ∗
    "%Hlast_digs" ∷ ⌜last σ.(state.digs) = Some lastDig⌝ ∗
    "#Herr" ∷
      match err with
      | true => ⌜uint.nat prevEpoch ≥ numEps ∨
        uint.nat prevVerLen > length pks⌝
      | false =>
        ∃ lastLink chainProof linkSig hist bound,
        "%Hnoof_eps" ∷ ⌜numEps = sint.nat (W64 $ numEps)⌝ ∗
        "%Hnoof_vers" ∷ ⌜length pks = sint.nat (W64 $ length pks)⌝ ∗
        "%His_lastLink" ∷ ⌜hashchain.valid (σ.(state.digs)) None lastLink numEps⌝ ∗

        "#Hsl_chainProof" ∷ sl_chainProof ↦*□ chainProof ∗
        "#Hsl_linkSig" ∷ sl_linkSig ↦*□ linkSig ∗
        "#Hsl_hist" ∷ ktcore.MembSlice1D.own sl_hist hist (□) ∗
        "#Hptr_bound" ∷ ktcore.NonMemb.own ptr_bound bound (□) ∗

        "%Hwish_chainProof" ∷ ⌜hashchain.wish_Proof chainProof
          (drop (S (uint.nat prevEpoch)) σ.(state.digs))⌝ ∗
        "#Hwish_linkSig" ∷ ktcore.wish_LinkSig γ.(cfg.sig_pk)
          (W64 $ (Z.of_nat numEps - 1)) lastLink linkSig ∗
        "#Hwish_hist" ∷ ktcore.wish_ListMemb agreeγ.(ktcore.Agree.vrf_pk) uid
          (uint.nat prevVerLen) lastDig hist ∗
        "%Heq_hist" ∷ ⌜drop (uint.nat prevVerLen) pks =
          ktcore.CommitOpen.Val <$> (ktcore.Memb.PkOpen <$> hist)⌝ ∗
        "#Hwish_bound" ∷ ktcore.wish_NonMemb agreeγ.(ktcore.Agree.vrf_pk) uid
          (length pks) lastDig bound
      end
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hown_serv_lock".
  wp_apply wp_with_defer as "* Hdefer". simpl.
  wp_auto.
  wp_apply (wp_RWMutex__RLock with "[$Hlock]") as "[Hlocked H]".
  iNamed "H".
  iApply ncfupd_wp.
  rewrite /perm_read /own.
  iMod "Hperm_read" as "(%&Hown_gs'&Hperm)".
  iCombine "Hown_gs Hown_gs'" gives %<-.
  iMod ("Hperm" with "[$Hown_gs']") as "HQ".
  iModIntro.

  iNamed "Hown_keys".
  iNamed "Hown_hist". iNamed "His_audits".
  iDestruct (own_slice_len with "Hsl_audits") as %?.
  iDestruct (own_slice_wf with "Hsl_audits") as %?.
  iDestruct (big_sepL2_length with "Hown_audits") as %?.
  wp_auto.
  pose proof Hlast_dig as Hsome_digs.
  rewrite last_lookup in Hsome_digs.
  apply lookup_lt_Some in Hsome_digs.
  wp_if_destruct.
  { wp_apply (wp_RWMutex__RUnlock with "[-HΦ HQ]") as "Hlock".
    { iFrame "∗∗#%". }
    wp_end. iFrame "∗#%". word. }
  simpl.
  wp_apply (wp_map_lookup1 with "[$Hptr_plain]") as "Hptr_plain".
  iAssert (let agreeγ := γ.(cfg.agreeγ) in
    ⌜sint.Z (default slice.nil (ptr0_plain !! uid)).(slice.len) =
    length $ ktcore.to_pks agreeγ.(ktcore.Agree.vrf_pk) uid last_dig⌝)%I as %?.
  { rewrite /keyStore.own_plain.
    iNamed "Hown_plain".
    rewrite lookup_total_alt.
    destruct (_ !! uid) eqn:Hlook_ptr_plain.
    - iDestruct (big_sepM2_lookup_l with "Hptr0_plain") as (?) "(%Hlook_plain&@)"; [done|].
      iDestruct (own_slice_len with "Hsl_pks") as %?.
      iDestruct (big_sepL2_length with "Hsl0_pks") as %?.
      rewrite Hlook_plain /=. word.
    - iDestruct (big_sepM2_lookup_l_none with "Hptr0_plain") as "%Hlook_plain"; [done|].
      by rewrite Hlook_plain. }
  wp_if_destruct.
  { wp_apply (wp_RWMutex__RUnlock with "[-HΦ HQ]") as "Hlock".
    { iFrame "∗∗#%". }
    wp_end. iFrame "∗#%". word. }
  wp_apply (hashchain.wp_HashChain_Prove with "[$Hown_chain]") as "* @"; [word|].
  iPersist "Hsl_proof".
  case_decide as Ht; [|word]. clear Ht.
  list_elem audits (pred $ length σ.(state.digs)) as last_audit.
  iDestruct (big_sepL2_lookup_r with "Hown_audits")
    as "(%ptr_audit&%Hlook_sl0_audits&@)"; [done|].
  iDestruct (big_sepL_lookup with "His_sigs") as "@"; [done|].
  rewrite take_ge in His_link; [|lia].
  wp_apply (wp_load_slice_index with "[$Hsl_audits]"); [word|..].
  { iPureIntro. exact_eq Hlook_sl0_audits. f_equal. word. }
  iIntros "Hsl_audits". wp_auto.
  wp_apply (wp_Server_getHist with "[Hown_hidden Hown_plain Hstr_history
    Hcap_audits Hown_gs Hptr_plain Hown_HashChain Hsl_audits]") as "* @".
  { iFrame "∗#%". word. }
  wp_apply (wp_Server_getBound with "[$Hown_serv $Hown_ro]") as "* @".
  { iFrame "%". word. }

  wp_apply (wp_RWMutex__RUnlock with "[-HΦ HQ]") as "Hlock".
  { iFrame "∗∗#%". }
  wp_end.
  iFrame (Hlast_dig) "∗ Hown_ro". iFrame "#%".
  replace (length _ - 1) with (Z.of_nat $ pred $ length σ.(state.digs)) by lia.
  iFrame "#".
  repeat iSplit; try iPureIntro.
  - word.
  - word.
  - exact_eq His_link. f_equal. lia.
  - exact_eq Hwish. f_equal. word.
  - iExactEq "Hwish_bound". rewrite /named. f_equal. word.
Qed.

Lemma wp_Server_Audit s γ obj (prevEpoch : w64) Q :
  {{{
    is_pkg_init server ∗
    "Hown_serv_lock" ∷ Server.lock_perm γ s obj ∗
    "Hperm_read" ∷ perm_read γ Q
  }}}
  s @! (go.PointerType server.Server) @! "Audit" #prevEpoch
  {{{
    sl_proofs err σ, RET (#sl_proofs, #err);
    let numEps := length σ.(state.digs) in
    "Hown_serv_lock" ∷ Server.lock_perm γ s obj ∗
    "HQ" ∷ Q σ ∗
    "Herr" ∷
      match err with
      | true => ⌜uint.nat prevEpoch ≥ numEps⌝
      | false =>
        (* we could explicitly tie down update labels and vals,
        but callers don't currently need that.
        this spec still gives the auditor same digs as server,
        and dig commits to exactly one map. *)
        ∃ proofs,
        "%Hnoof_eps" ∷ ⌜numEps = sint.nat (W64 $ numEps)⌝ ∗

        "#Hsl_proofs" ∷ ktcore.AuditProofSlice1D.own sl_proofs proofs (□) ∗
        "%Hlen_proofs" ∷ ⌜(uint.Z prevEpoch + length proofs + 1)%Z = numEps⌝ ∗

        "#His_upds" ∷ ([∗ list] i ↦ aud ∈ proofs,
          ∃ dig0 dig1,
          let predEp := (uint.nat prevEpoch + i)%nat in
          "%Hlook0" ∷ ⌜σ.(state.digs) !! predEp = Some dig0⌝ ∗
          "%Hlook1" ∷ ⌜σ.(state.digs) !! (S predEp) = Some dig1⌝ ∗
          "#His_upd" ∷ ktcore.wish_ListUpdate dig0 aud.(ktcore.AuditProof.Updates) dig1) ∗
        "#His_sigs" ∷ ([∗ list] i ↦ aud ∈ proofs,
          ∃ link,
          let ep := (S $ uint.nat prevEpoch + i)%nat in
          "%His_link" ∷ ⌜hashchain.valid (take (S ep) σ.(state.digs)) None link (S ep)⌝ ∗
          "#His_sig" ∷ ktcore.wish_LinkSig γ.(cfg.sig_pk) (W64 ep) link aud.(ktcore.AuditProof.LinkSig))
      end
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hown_serv_lock".
  wp_apply wp_with_defer as "* Hdefer". simpl.
  wp_auto.
  wp_apply (wp_RWMutex__RLock with "[$Hlock]") as "[Hlocked H]".
  iNamed "H".
  iApply ncfupd_wp.
  rewrite /perm_read /own.
  iMod "Hperm_read" as "(%&Hown_gs'&Hperm)".
  iCombine "Hown_gs Hown_gs'" gives %<-.
  iMod ("Hperm" with "[$Hown_gs']") as "HQ".
  iModIntro.

  iNamed "Hown_hist". iNamed "His_audits".
  iDestruct (own_slice_len with "Hsl_audits") as %?.
  iDestruct (own_slice_wf with "Hsl_audits") as %?.
  iDestruct (big_sepL2_length with "Hown_audits") as %?.
  wp_auto.
  pose proof Hlast_dig as Hsome_digs.
  rewrite last_lookup in Hsome_digs.
  apply lookup_lt_Some in Hsome_digs.
  wp_if_destruct.
  { wp_apply (wp_RWMutex__RUnlock with "[-HΦ HQ]") as "Hlock".
    { iFrame "∗∗#%". }
    wp_end. iFrame "∗#". word. }
  case_decide as Ht; [|word]. clear Ht. wp_auto.
  iDestruct (own_slice_split_all with "Hsl_audits") as "[Hsl0 Hsl1]"; [shelve|].
  wp_apply (wp_slice_append with "[$Hsl1]")
    as "%sl_proof (Hsl_proof&_&Hsl1)".
  { iDestruct own_slice_nil as "$".
    iDestruct own_slice_cap_nil as "$". }
  Unshelve. 2: { word. }
  iDestruct (own_slice_combine with "Hsl0 Hsl1") as "Hsl_audits"; [len|].
  rewrite take_drop -slice_slice_trivial /=.
  iPersist "Hsl_proof".
  wp_apply (wp_RWMutex__RUnlock with "[-HΦ HQ]") as "Hlock".
  { iFrame "∗∗#%". }
  wp_end. iFrame "∗#".

  replace (sint.nat (word.add _ _)) with (S $ uint.nat prevEpoch) by word.
  iExists (drop (S $ uint.nat prevEpoch) audits).
  repeat iSplit; try iPureIntro.
  - word.
  - iDestruct (big_sepL2_drop with "Hown_audits") as "$".
  - len.
  - iDestruct (big_sepL_drop _ _  (uint.nat prevEpoch) with "His_upds") as "H".
    rewrite drop_drop.
    replace (1 + uint.nat prevEpoch)%nat with (S $ uint.nat prevEpoch) by lia.
    iFrame "#".
  - iDestruct (big_sepL_drop with "His_sigs") as "$".
Qed.

Lemma wp_Server_Start s γ obj Q :
  {{{
    is_pkg_init server ∗
    "Hown_serv_lock" ∷ Server.lock_perm γ s obj ∗
    "Hperm_read" ∷ perm_read γ Q
  }}}
  s @! (go.PointerType server.Server) @! "Start" #()
  {{{
    chain vrf ptr_chain ptr_vrf σ last_link, RET (#ptr_chain, #ptr_vrf);
    let agreeγ := γ.(cfg.agreeγ) in
    let numEps := length σ.(state.digs) in
    "Hown_serv_lock" ∷ Server.lock_perm γ s obj ∗
    "HQ" ∷ Q σ ∗

    "#Hptr_chain" ∷ StartChain.own ptr_chain chain (□) ∗
    "#Hptr_vrf" ∷ StartVrf.own ptr_vrf vrf (□) ∗

    "%Hnoof_eps" ∷ ⌜numEps = sint.nat (W64 $ numEps)⌝ ∗
    "%His_PrevEpochLen" ∷ ⌜uint.nat chain.(StartChain.PrevEpochLen) < numEps⌝ ∗
    "%His_PrevLink" ∷ ⌜hashchain.valid
      (take (uint.nat chain.(StartChain.PrevEpochLen)) σ.(state.digs))
      None chain.(StartChain.PrevLink)
      (uint.nat chain.(StartChain.PrevEpochLen))⌝ ∗
    "%His_ChainProof" ∷ ⌜hashchain.wish_Proof chain.(StartChain.ChainProof)
      (drop (uint.nat chain.(StartChain.PrevEpochLen)) σ.(state.digs))⌝ ∗
    "%His_last_link" ∷ ⌜hashchain.valid σ.(state.digs) None last_link numEps⌝ ∗
    "#His_LinkSig" ∷ ktcore.wish_LinkSig γ.(cfg.sig_pk)
      (W64 $ numEps - 1) last_link chain.(StartChain.LinkSig) ∗

    "%Heq_VrfPk" ∷ ⌜agreeγ.(ktcore.Agree.vrf_pk) = vrf.(StartVrf.VrfPk)⌝ ∗
    "#His_VrfPk" ∷ cryptoffi.is_vrf_pk vrf.(StartVrf.VrfPk) ∗
    "#His_VrfSig" ∷ ktcore.wish_VrfSig γ.(cfg.sig_pk)
      agreeγ.(ktcore.Agree.vrf_pk) vrf.(StartVrf.VrfSig) ∗

    (* bootstrap caller's facts about our Agree state. *)
    "%Heq_digs_start" ∷ ⌜agreeγ.(ktcore.Agree.digs_start) = 0%nat⌝ ∗
    "%Heq_cut" ∷ ⌜agreeγ.(ktcore.Agree.cut) = None⌝
  }}}.
Proof.
  wp_start as "@".
  iNamed "Hown_serv_lock". iNamed "Hown_ro". iNamed "Hown_secs".
  wp_apply wp_with_defer as "* Hdefer". simpl.
  wp_auto.
  wp_apply (wp_RWMutex__RLock with "[$Hlock]") as "[Hlocked H]".
  iNamed "H".
  iApply ncfupd_wp.
  rewrite /perm_read /own.
  iMod "Hperm_read" as "(%&Hown_gs'&Hperm)".
  iCombine "Hown_gs Hown_gs'" gives %<-.
  iMod ("Hperm" with "[$Hown_gs']") as "HQ".
  iModIntro.

  iNamed "Hown_hist". iNamed "His_audits".
  iDestruct (own_slice_len with "Hsl_audits") as %?.
  iDestruct (big_sepL2_length with "Hown_audits") as %?.
  wp_auto.
  pose proof Hlast_dig as Hsome_digs.
  rewrite last_lookup in Hsome_digs.
  apply lookup_lt_Some in Hsome_digs.
  wp_apply (hashchain.wp_HashChain_Bootstrap with "[$Hown_chain]") as "* @"; [word|].
  case_decide as Ht; [|word]. clear Ht.
  wp_bind.
  list_elem audits (pred $ length σ.(state.digs)) as last_audit.
  iDestruct (big_sepL2_lookup_r with "Hown_audits")
    as "(%ptr_audit&%Hlook_sl0_audits&@)"; [done|].
  iDestruct (big_sepL_lookup with "His_sigs") as "@"; [done|].
  rewrite take_ge in His_link; [|lia].
  wp_apply (wp_load_slice_index with "[$Hsl_audits]"); [word|..].
  { iPureIntro. exact_eq Hlook_sl0_audits. f_equal. word. }
  iIntros "Hsl_audits". wp_auto.
  wp_apply cryptoffi.wp_VrfPrivateKey_PublicKey as "* H".
  { iFrame "#". }
  iNamedSuffix "H" "_vrf".
  wp_apply wp_alloc as "* Hptr_chain".
  wp_apply wp_alloc as "* Hptr_vrf".
  iPersist "Hsl_proof Hsl_enc_vrf Hptr_chain Hptr_vrf".
  wp_apply (wp_RWMutex__RUnlock with "[-HΦ HQ]") as "Hlock".
  { iFrame "∗∗#%". }

  iApply ("HΦ" $! (StartChain.mk' _ _ _ _) (StartVrf.mk' _ _)). simpl.
  simpl. iFrame "∗#".
  replace (uint.nat (word.sub _ _)) with (pred $ length σ.(state.digs)); [|word].
  iFrame "%".
  replace (_ - _) with (Z.of_nat $ pred $ length σ.(state.digs)); [|lia].
  iDestruct (cryptoffi.own_vrf_sk_to_pk with "[]") as "His_vrf_pk"; [done|].
  iFrame "#".
  repeat iSplit; try iPureIntro.
  - word.
  - word.
  - exact_eq His_link. f_equal. lia.
  - done.
Qed.

Lemma wp_New (uidγ : gmap w64 gname) :
  {{{ is_pkg_init server }}}
  @! server.New #()
  {{{
    γ obj ptr_server sl_sigPk, RET (#ptr_server, #sl_sigPk);
    "#His_inv" ∷ is_inv γ ∗
    "Hlocks" ∷ ([∗] replicate (pred $ Z.to_nat rwmutex.actualMaxReaders)
      (Server.lock_perm γ ptr_server obj)) ∗
    "#Hsl_sigPk" ∷ sl_sigPk ↦*□ γ.(cfg.sig_pk) ∗
    "#His_sigPk" ∷ cryptoffi.is_sig_pk γ.(cfg.sig_pk) (sigpred.P γ.(cfg.agreeγ))
  }}}.
Proof.
  wp_start as "@". wp_auto.
  wp_apply wp_alloc as "* Hptr_mu".
  wp_apply cryptoffi.wp_VrfGenerateKey as "* @".
  iMod (mono_list_own_alloc []) as (digsγ) "[Hauth_digs _]".
  remember (ktcore.Agree.mk vrfPk digsγ 0%nat None 0%nat) as agreeγ.
  wp_apply (cryptoffi.wp_SigGenerateKey (sigpred.P agreeγ)) as "* @".
  wp_apply cryptoffi.wp_VrfPrivateKey_PublicKey as "* @".
  { iFrame "#". }
  iRename "Hsl_enc" into "Hsl_vrfPk". iPersist "Hsl_vrfPk".
  wp_apply ktcore.wp_SignVrf as "* @".
  { iFrame "#". rewrite /vrfP. by subst. }
  wp_apply cryptoffi.wp_RandBytes as "* @".
  rename b into commit_sec.
  iRename "Hsl_b" into "Hsl_commit_sec".
  wp_apply wp_alloc as "* Hptr_secs".
  wp_apply wp_alloc as "* Hptr_merkle".
  iDestruct (merkle.own_Map_init with "[$Hptr_merkle]") as "@"; [solve_pkg_init|].
  wp_apply wp_map_make1 as "* Hptr_plain".
  wp_apply wp_alloc as "* Hptr_keys".
  wp_apply hashchain.wp_New as "* @".
  wp_apply wp_alloc as "* Hptr_hist".
  wp_apply chan.wp_make1 as "% %chanγ (#His_chan&%&Hown_chan)".
  wp_apply wp_alloc as "%ptr_serv Hptr_serv".

  wp_apply (merkle.wp_Map_Hash with "[$Hown_Map]") as "* @".
  iDestruct (merkle.own_Map_to_is_map with "[$Hown_Map]") as %[Hinv_merkle ?].
  wp_apply (hashchain.wp_HashChain_Append with "[$Hown_HashChain]") as "* @ {Hsl_val}".
  { by iFrame "#". }
  iMod (mono_list_auth_own_update_app [_] with "Hauth_digs")
    as "[[Hgs_digs Hgs_digs'] #Hlb_digs]".
  simpl in *.
  eassert (ktcore.mono_plain _ [hash]).
  { rewrite /ktcore.mono_plain. apply list_reln_singleton. }
  wp_apply ktcore.wp_SignLink as "* @".
  { iFrame "#". rewrite /linkP.
    simplify_eq/=. by iFrame "#%". }
  wp_apply wp_alloc as "%ptr_audit Hptr_audit".
  wp_apply wp_slice_literal. iSplitR; first done. iIntros "* [Ht _]". wp_auto.
  replace (sint.nat _) with 0%nat by word. simpl.
  (* TODO: [Ht] not framing without specifying [ptr_audit]. *)
  wp_apply (wp_slice_append _ _ _ [ptr_audit] with "[Ht]")
    as "% (Hsl_audits&Hcap_audits&_)".
  { iDestruct own_slice_nil as "$".
    iDestruct own_slice_cap_nil as "$".
    iFrame "Ht". }
  Unshelve. 3: apply _. 2: apply _.
  simpl.

  iMod (dghost_var_alloc (∅ : ktcore.plain_ty)) as (pendγ) "[Hgs_pend Hgs_pend']".
  eremember (Server.mk' (secrets.mk' commit_sec)) as obj.
  eremember (cfg.mk sigPk pendγ uidγ agreeγ) as γ.
  eremember (state.mk ∅ [hash]) as σ.
  iMod (start_bag (work.own_aux γ obj.(Server.secs)) with "His_chan Hown_chan")
    as "#His_chan_bag"; [done|].
  iStructNamed "Hptr_serv". simpl in *.
  iPersist "secs workQ mu keys hist".
  iPersist "s sigPk Hsl_sigPk Hptr_secs Hptr_keys Hptr_audit Hsl_commit_sec".
  iMod (inv_alloc nroot _ (∃ σ, inv_aux γ σ) with "[Hgs_digs' Hgs_pend']") as "Ht".
  { iExists σ. simplify_eq/=.
    iFrame "∗". rewrite /valid /=.
    iFrame "%".
    iModIntro. iSplit; [naive_solver|].
    iPureIntro. intros **. simplify_eq/=.
    by rewrite Hinv_merkle ktcore.plain_inv_empty. }
  iAssert (is_inv γ)%I with "Ht" as "{Ht} #His_inv".
  iMod (init_RWMutex (Server.own_aux γ ptr_serv obj)
    with "[-HΦ Hptr_mu] Hptr_mu") as "Hlock_perms".
  { admit. } (* TODO: Fractional *)
  { iExists σ. simplify_eq/=.
    iFrame "∗#". simpl.
    rewrite Hinv_merkle ktcore.plain_inv_empty.
    iModIntro. repeat iSplit; try iPureIntro; try done.
    { rewrite /keyStore.own_plain. naive_solver. }
    2: { by iApply op_add_digs. }
    iExists [ktcore.AuditProof.mk' [] _].
    iFrame "Hptr_audit #". simpl. repeat iSplit; try done.
    by iDestruct own_slice_nil as "$". }
  iDestruct (big_sepL_replicate_impl _ (Server.lock_perm γ ptr_serv obj)
    with "Hlock_perms []") as "Hlock_perms".
  { iIntros "!> H". simplify_eq/=. iFrame "∗#". simpl. word. }
  assert (Z.to_nat rwmutex.actualMaxReaders =
    S $ pred $ Z.to_nat rwmutex.actualMaxReaders) as Ht.
  { rewrite rwmutex.actualMaxReaders_unseal. lia. }
  iEval (rewrite Ht) in "Hlock_perms". clear Ht. simpl.
  iDestruct "Hlock_perms" as "[Hlock_perm Hlock_perms]".
  wp_apply (wp_fork with "[Hlock_perm]").
  { by wp_apply (wp_Server_worker with "[$]"). }
  wp_end. simplify_eq/=. iFrame "∗#".
Admitted.

End proof.
End server.
