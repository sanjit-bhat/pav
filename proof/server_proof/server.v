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
    sigγ : sigpred.cfg.t;
  }.
End cfg.

Module state.
Record t :=
  mk {
    (* pending map of all keys.
    client gives server permission to add to this.
    all writable post-conds only reference pending. *)
    pending : ktcore.keys_ty;
    (* hist of digs.
    server can update this by adding dig that corresponds to curr pending.
    all read-only post-conds only reference hist. *)
    hist : list (list w8);
  }.
End state.

Notation get_vrf_pk γ := (γ.(cfg.sigγ).(sigpred.cfg.vrf_pk)).
Notation digsγ γ := (γ.(cfg.sigγ).(sigpred.cfg.digs)).

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own_aux γ obj q : iProp Σ :=
  "Hown_pend" ∷ dghost_var γ.(cfg.pendγ) (DfracOwn q) obj.(state.pending) ∗
  (* client remembers lb's of this. *)
  "Hown_hist" ∷ mono_list_auth_own (digsγ γ) q obj.(state.hist).

(* other 1/2 in server lock inv. *)
Definition own γ obj : iProp Σ := own_aux γ obj (1/2).

Definition valid γ obj : iProp Σ :=
  "#Hperm_uids" ∷ ([∗ map] uid ↦ pks ∈ obj.(state.pending),
    ∃ uidγ,
    "%Hlook_uidγ" ∷ ⌜γ.(cfg.uidγ) !! uid = Some uidγ⌝ ∗
    "#Hpks" ∷ ([∗ list] ver ↦ pk ∈ pks,
      ∃ i,
      (* client owns mlist_auth for their uid.
      for adversarial uid, auth in inv. *)
      mono_list_idx_own uidγ i ((W64 ver), pk))) ∗
  "%Hsub_pend" ∷ ⌜∀ last_dig,
    last obj.(state.hist) = Some last_dig →
    ktcore.keys_sub (ktcore.to_plain (get_vrf_pk γ) last_dig) obj.(state.pending)⌝ ∗
  "%Hsub_hist" ∷ ⌜sigpred.mono_maps obj.(state.hist)⌝.

Definition inv_aux γ obj : iProp Σ :=
  "Hown_serv" ∷ own γ obj ∗
  "#His_serv" ∷ valid γ obj.

#[global] Instance inv_aux_timeless γ obj : Timeless (inv_aux γ obj).
Proof. apply _. Qed.

Definition is_inv γ := inv nroot (∃ obj, inv_aux γ obj).

(** helpers for inv. *)

Lemma hist_pks_prefix uid γ (i j : nat) (x y : list w8) :
  (i ≤ j)%nat →
  is_inv γ -∗
  mono_list_idx_own (digsγ γ) i x -∗
  mono_list_idx_own (digsγ γ) j y ={⊤}=∗
  ⌜ktcore.to_pks (get_vrf_pk γ) uid x `prefix_of` ktcore.to_pks (get_vrf_pk γ) uid y⌝.
Proof.
  iIntros (?) "#Hinv #Hidx0 #Hidx1".
  rewrite /is_inv.
  iInv "Hinv" as ">@" "Hclose".
  iNamed "Hown_serv".
  iDestruct (mono_list_auth_idx_lookup with "Hown_hist Hidx0") as %Hlook0.
  iDestruct (mono_list_auth_idx_lookup with "Hown_hist Hidx1") as %Hlook1.
  iMod ("Hclose" with "[-]") as "_"; [iFrame "∗#"|].
  iNamed "His_serv".
  iIntros "!> !%".
  by eapply ktcore.plain_mono_lookup.
Qed.

Lemma hist_to_put_perms γ i x :
  is_inv γ -∗
  mono_list_idx_own (digsγ γ) i x ={⊤}=∗
  ∀ uid pks,
    ⌜ktcore.to_plain (get_vrf_pk γ) x !! uid = Some pks⌝ -∗
    (* if empty pks, might not have uidγ. *)
    ⌜length pks > 0%nat⌝ -∗
    ∃ uidγ,
      ⌜γ.(cfg.uidγ) !! uid = Some uidγ⌝ ∗
      ([∗ list] ver ↦ pk ∈ pks,
        ∃ i,
        mono_list_idx_own uidγ i ((W64 ver), pk)).
Proof.
  iIntros "#Hinv #Hidx".
  rewrite /is_inv.
  iInv "Hinv" as ">@" "Hclose".
  iNamed "Hown_serv".
  iDestruct (mono_list_auth_idx_lookup with "Hown_hist Hidx") as %Hlook_hist.
  iMod ("Hclose" with "[-]") as "_"; [by iFrame "∗#"|].
  iNamed "His_serv".
  iModIntro.

  iIntros "* %Hlook_uid %Hlen_pks".
  apply lookup_lt_Some in Hlook_hist as ?.
  list_elem (obj.(state.hist)) (pred (length obj.(state.hist))) as last_dig.
  opose proof (ktcore.plain_mono_lookup (get_vrf_pk γ) uid _
    Hlook_hist Hlast_dig_lookup _) as Hsub0; [done|lia|].
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

Definition Q_read_lb prev_lb γ obj : iProp Σ :=
  mono_list_lb_own (digsγ γ) obj.(state.hist) ∗
  ⌜prev_lb `prefix_of` obj.(state.hist)⌝.

Lemma op_read_lb γ prev_lb :
  is_inv γ -∗
  mono_list_lb_own (digsγ γ) prev_lb -∗
  (|={⊤,∅}=>
    ∃ obj, own γ obj ∗
      (own γ obj
        ={∅,⊤}=∗ Q_read_lb prev_lb γ obj)).
Proof.
  iIntros "#Hinv #Hlb".
  rewrite /is_inv.
  iInv "Hinv" as ">@" "Hclose".
  iApply fupd_mask_intro.
  { set_solver. }
  iIntros "Hmask".
  iFrame.
  iIntros "@".
  iMod "Hmask" as "_".
  iDestruct (mono_list_lb_own_get with "Hown_hist") as "#Hlb'".
  iDestruct (mono_list_auth_lb_valid with "Hown_hist Hlb") as %[_ ?].
  iMod ("Hclose" with "[-]") as "_".
  - iFrame "∗#".
  - by iFrame "#%".
Qed.

Definition Q_read_idx prev_idx γ obj : iProp Σ :=
  mono_list_lb_own (digsγ γ) obj.(state.hist) ∗
  ⌜prev_idx < length obj.(state.hist)⌝.

(* op_read_idx necessary, even tho weaker than op_read_lb.
cli_call takes in curried Q_read, since it's used in both pre and post.
at currying time, not under good flag, so client doesn't have prev_lb.
but it does have have prev_idx!
that's an arg to, e.g., CallHistory, independent of good-ness. *)
Lemma op_read_idx γ prev_idx (a : list w8) :
  is_inv γ -∗
  mono_list_idx_own (digsγ γ) prev_idx a -∗
  (|={⊤,∅}=>
    ∃ obj, own γ obj ∗
      (own γ obj
        ={∅,⊤}=∗ Q_read_idx prev_idx γ obj)).
Proof.
  iIntros "#Hinv #Hidx".
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

Definition pure_put uid (ver : w64) pk (pend : ktcore.keys_ty) :=
  let pks := pend !!! uid in
  (* drop put if not right version.
  this enforces a "linear" version history. *)
  if bool_decide (uint.nat ver ≠ length pks) then pend else
  <[uid:=pks ++ [pk]]>pend.

Lemma sub_over_put pend uid ver pk :
  ktcore.keys_sub pend (pure_put uid ver pk pend).
Proof.
  rewrite /pure_put.
  case_bool_decide; [done|].
  rewrite /ktcore.keys_sub.
  apply insert_included; [apply _|].
  rewrite lookup_total_alt.
  intros ? ->. simpl.
  by apply prefix_app_r.
Qed.

Lemma op_put γ uid uidγ i ver pk :
  is_inv γ -∗
  ⌜γ.(cfg.uidγ) !! uid = Some uidγ⌝ -∗
  mono_list_idx_own uidγ i (ver, pk) -∗
  □ (|={⊤,∅}=> ∃ obj, own γ obj ∗
    (let obj' := set state.pending (pure_put uid ver pk) obj in
    own γ obj' ={∅,⊤}=∗ True)).
Proof.
  iIntros "#Hinv %Hlook_uidγ #Hmono_idx".
  iModIntro.
  rewrite /is_inv.
  iInv "Hinv" as ">@" "Hclose".
  iApply fupd_mask_intro.
  { set_solver. }
  iIntros "Hmask".
  iFrame.
  iIntros "H".
  iMod "Hmask" as "_".
  iMod ("Hclose" with "[-]"); [|done].
  iModIntro.
  iFrame.

  destruct obj. simpl in *.
  iNamed "His_serv".
  iFrame "%". iSplit; try iPureIntro; simpl in *.
  - rewrite /pure_put.
    case_bool_decide; [iFrame "#"|].
    iApply big_sepM_insert_2; [|iFrame "#"].
    iFrame "%".
    iApply big_sepL_snoc.
    iSplit.
    2: { iExists _. iExactEq "Hmono_idx". repeat f_equal. word. }
    rewrite lookup_total_alt.
    destruct (pending !! uid) eqn:Hlook;
      rewrite Hlook; simpl; [|done].
    iDestruct (big_sepM_lookup with "Hperm_uids") as "@"; [done|].
    by simplify_eq/=.
  - intros.
    trans pending; [naive_solver|].
    apply sub_over_put.
Qed.

Lemma op_add_hist γ :
  is_inv γ -∗
  □ (|={⊤,∅}=> ∃ obj, own γ obj ∗
    ∀ dig,
    ⌜ktcore.to_plain (get_vrf_pk γ) dig = obj.(state.pending)⌝ -∗
    let obj' := set (state.hist) (.++ [dig]) obj in
    (own γ obj' ={∅,⊤}=∗ True)).
Proof.
  iIntros "#Hinv".
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
  - unfold sigpred.mono_maps in *.
    rewrite fmap_app /=.
    apply list_reln_snoc; [done|].
    intros * Hlast.
    rewrite fmap_last in Hlast.
    apply fmap_Some in Hlast as (?&Hlast&?).
    apply Hsub_pend in Hlast.
    simplify_eq/=.
    (* TODO: know keys_sub (last hist) pend,
    but ¬ (keys_sub → hidden_sub), so we're stuck.
    could:
    1) turn pending into dig. but that adds unnecessary complexity.
    2) make hist be list of plains.
    but that's not good loses info needed for Server specs.
    3) weaken hist reln to keys_sub.
    sigpred still needs to be over hidden_sub,
    but we can track that separately. *)
Admitted.

End proof.

(** golang server state. *)

Module secrets.
Record t := mk' {
  commit : list w8;
}.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own γ ptr obj : iProp Σ :=
  ∃ ptr_sig ptr_vrf sl_commit,
  "#Hstr_secrets" ∷ ptr ↦□ (server.secrets.mk ptr_sig ptr_vrf sl_commit) ∗
  "#Hown_sig" ∷ cryptoffi.own_sig_sk ptr_sig γ.(cfg.sig_pk)
    (ktcore.sigpred γ.(cfg.sigpredγ)) ∗
  "#Hown_vrf" ∷ cryptoffi.own_vrf_sk ptr_vrf γ.(cfg.vrf_pk) ∗
  "#Hsl_commit" ∷ sl_commit ↦*□ obj.(commit) ∗
  "%Hlen_commit" ∷ ⌜Z.of_nat (length obj.(commit)) = cryptoffi.hash_len⌝.

End proof.
End secrets.

Module keyStore.
Record t := mk' {
  plain : ktcore.keys_ty;
}.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own_plain ptr_plain (plain : ktcore.keys_ty) q : iProp Σ :=
  ∃ ptr0_plain,
  "Hptr_plain" ∷ map.own_map ptr_plain (DfracOwn q) ptr0_plain ∗
  "Hptr0_plain" ∷ ([∗ map] uid ↦ sl_pks;pks ∈ ptr0_plain;plain,
    ∃ sl0_pks,
    "Hsl_pks" ∷ sl_pks ↦*{#q} sl0_pks ∗
    "Hcap_pks" ∷ own_slice_cap slice.t sl_pks (DfracOwn q) ∗
    "#Hsl0_pks" ∷ ([∗ list] sl_pk;pk ∈ sl0_pks;pks,
      "Hsl_pk" ∷ sl_pk ↦*□ pk)).

Definition is_hidden γ commit_sec plain (hidden : gmap (list w8) (list w8)) : iProp Σ :=
  [∗ map] uid ↦ kt_pks ∈ plain,
    [∗ list] ver ↦ kt_pk ∈ kt_pks,
      ∃ label rand mapVal,
      "#His_MapLabel" ∷ ktcore.is_MapLabel γ.(cfg.vrf_pk) uid (W64 ver) label ∗
      "#His_CommitRand" ∷ ktcore.is_CommitRand commit_sec label rand ∗
      "#His_MapVal" ∷ ktcore.is_MapVal kt_pk rand mapVal ∗
      "%Hlook" ∷ ⌜hidden !! label = Some mapVal⌝.

Definition own γ ptr obj secs dig q : iProp Σ :=
  ∃ ptr_hidden hidden ptr_plain,
  "#Hstr_keyStore" ∷ ptr ↦□ (server.keyStore.mk ptr_hidden ptr_plain) ∗
  "Hown_hidden" ∷ merkle.own_Map ptr_hidden hidden dig (DfracOwn q) ∗
  "Hown_plain" ∷ own_plain ptr_plain obj.(plain) q ∗
  "#His_hidden" ∷ is_hidden γ secs.(secrets.commit) obj.(plain) hidden ∗
  "#His_dig" ∷ merkle.is_map hidden dig.

End proof.
End keyStore.

Module history.
Record t := mk' {
  digs : list (list w8);
}.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition is_audits γ digs audits : iProp Σ :=
  ∃ init_dig,
  "%Hlen_audits" ∷ ⌜length digs = length audits⌝ ∗
  "#His_upds" ∷ ([∗ list] ep ↦ aud ∈ audits,
    (* AuditProof is a transition to an epoch.
    for AuditProof @! ep0, need init_dig to transition from. *)
    ∃ dig0 dig1,
    "%Hlook0" ∷ ⌜(init_dig :: digs) !! ep = Some dig0⌝ ∗
    "%Hlook1" ∷ ⌜(init_dig :: digs) !! (S ep) = Some dig1⌝ ∗
    "#His_upd" ∷ ktcore.wish_ListUpdate dig0 aud.(ktcore.AuditProof.Updates) dig1) ∗
  "#His_sigs" ∷ ([∗ list] ep ↦ aud ∈ audits,
    ∃ link,
    "#His_link" ∷ hashchain.is_chain (take (S ep) digs) None link (S ep) ∗
    "#His_sig" ∷ ktcore.wish_LinkSig γ.(cfg.sig_pk) (W64 ep) link
      aud.(ktcore.AuditProof.LinkSig)).

Definition own γ ptr obj q : iProp Σ :=
  ∃ ptr_chain sl_audits sl0_audits audits sl_vrfSig vrfSig,
  "Hstr_history" ∷ ptr ↦{#q} (server.history.mk ptr_chain sl_audits sl_vrfSig) ∗
  "Hown_chain" ∷ hashchain.own ptr_chain obj.(digs) (DfracOwn q) ∗

  "Hsl_audits" ∷ sl_audits ↦*{#q} sl0_audits ∗
  "Hcap_audits" ∷ own_slice_cap loc sl_audits (DfracOwn q) ∗
  "#Hown_audits" ∷ ([∗ list] idx ↦ p; aud ∈ sl0_audits; audits,
    ktcore.AuditProof.own p aud (□)) ∗
  "#His_audits" ∷ is_audits γ obj.(digs) audits ∗

  "#Hsl_vrfSig" ∷ sl_vrfSig ↦*□ vrfSig ∗
  "#His_vrfSig" ∷ ktcore.wish_VrfSig γ.(cfg.sig_pk) γ.(cfg.vrf_pk) vrfSig.

End proof.
End history.

Module work.
Record t := mk' {
  uid : w64;
  ver : w64;
  pk : list w8;
}.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own γ secs ptr obj : iProp Σ :=
  ∃ sl_pk sl_mapLabel mapLabel sl_mapVal mapVal rand uidγ i,
  "Hstr_Work" ∷ ptr ↦ (server.work.mk obj.(uid) obj.(ver) sl_pk sl_mapLabel sl_mapVal) ∗
  "#Hsl_pk" ∷ sl_pk ↦*□ obj.(pk) ∗
  "#Hsl_mapLabel" ∷ sl_mapLabel ↦*□ mapLabel ∗
  "#Hsl_mapVal" ∷ sl_mapVal ↦*□ mapVal ∗

  "#His_mapLabel" ∷ ktcore.is_MapLabel γ.(cfg.vrf_pk) obj.(uid) obj.(ver) mapLabel ∗
  "#His_rand" ∷ ktcore.is_CommitRand secs.(secrets.commit) mapLabel rand ∗
  "#His_mapVal" ∷ ktcore.is_MapVal obj.(pk) rand mapVal ∗

  "%Hlook_uidγ" ∷ ⌜γ.(cfg.uidγ) !! obj.(uid) = Some uidγ⌝ ∗
  "#Hput_perm" ∷ mono_list_idx_own uidγ i (obj.(ver), obj.(pk)).

Definition own_aux γ secs (ptr : loc) : iProp Σ := ∃ obj, own γ secs ptr obj.

End proof.
End work.

Module Server.
Record t :=
  mk' {
    secs : secrets.t;
  }.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

(* experimenting with diff abstractions to fit the diff use cases. *)

Definition own_ro_aux γ ptr obj : iProp Σ :=
  ∃ ptr_secs ptr_workQ workQγ,
  "#Hfld_secs" ∷ ptr.[server.Server.t, "secs"] ↦□ ptr_secs ∗
  "#Hfld_workQ" ∷ ptr.[server.Server.t, "workQ"] ↦□ ptr_workQ ∗

  "#Hown_secs" ∷ secrets.own γ ptr_secs obj.(secs) ∗
  "#His_workQ" ∷ handoff.is_chan_handoff workQγ ptr_workQ (work.own_aux γ obj.(secs)).

Definition own_ro γ ptr : iProp Σ := ∃ obj, own_ro_aux γ ptr obj.

Definition own_locked γ ptr σ obj q : iProp Σ :=
  ∃ ptr_keys keys ptr_hist hist lastDig,
  "#Hfld_keys" ∷ ptr.[server.Server.t, "keys"] ↦□ ptr_keys ∗
  "#Hfld_hist" ∷ ptr.[server.Server.t, "hist"] ↦□ ptr_hist ∗

  "Hown_keys" ∷ keyStore.own γ ptr_keys keys obj.(secs) lastDig q ∗
  "Hown_hist" ∷ history.own γ ptr_hist hist q ∗

  (* other 1/2 in server inv. *)
  "Hown_gs" ∷ own_aux γ σ (q/2) ∗
  "%Heq_hist" ∷ ⌜σ.(state.hist).*1 = hist.(history.digs)⌝ ∗
  "%Heq_last_hist" ∷ ⌜last σ.(state.hist) = Some (lastDig, keys.(keyStore.plain))⌝ ∗
  "#Hop_add_hist" ∷ □ (|={⊤,∅}=> ∃ σ, own γ σ ∗
    ∀ dig,
    let σ' := set (state.hist) (.++ [(dig, σ.(state.pending))]) σ in
    (own γ σ' ={∅,⊤}=∗ True)).

Definition own γ ptr σ q : iProp Σ :=
  ∃ obj,
  "#Hown_ro" ∷ own_ro_aux γ ptr obj ∗
  "Hown_locked" ∷ own_locked γ ptr σ obj q.

Definition own_aux γ ptr q : iProp Σ := ∃ σ, own γ ptr σ q.

Definition own_lock γ ptr : iProp Σ :=
  ∃ ptr_mu,
  "#Hfld_mu" ∷ ptr.[server.Server.t, "mu"] ↦□ ptr_mu ∗
  "Hlock" ∷ own_RWMutex ptr_mu (own_aux γ ptr).

End proof.
End Server.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

(** fetch-side helper funcs. *)

Lemma wp_Server_getHist s γ obj (uid prefixLen : w64) q lastDig lastKeys :
  {{{
    is_pkg_init server ∗
    "Hown_serv" ∷ Server.own γ s obj q ∗
    "%Hlast_hist" ∷ ⌜last obj.(state.hist) = Some (lastDig, lastKeys)⌝ ∗
    "%Heq_prefixLen" ∷ ⌜uint.nat prefixLen ≤ length (lastKeys !!! uid)⌝
  }}}
  s @! (go.PointerType server.Server) @! "getHist" #uid #prefixLen
  {{{
    sl_hist hist, RET #sl_hist;
    let pks := lastKeys !!! uid in
    "Hown_serv" ∷ Server.own γ s obj q ∗
    "#Hsl_hist" ∷ ktcore.MembSlice1D.own sl_hist hist (□) ∗
    "#Hwish_hist" ∷ ktcore.wish_ListMemb γ.(cfg.vrf_pk) uid prefixLen lastDig hist ∗
    "%Heq_hist" ∷ ⌜Forall2
      (λ x y, x = y.(ktcore.Memb.PkOpen).(ktcore.CommitOpen.Val))
      (drop (uint.nat prefixLen) pks) hist⌝
  }}}.
Proof. Admitted.

Lemma wp_Server_getBound s γ obj (uid numVers : w64) q lastDig lastKeys :
  {{{
    is_pkg_init server ∗
    "Hown_serv" ∷ Server.own γ s obj q ∗
    "%Hlast_hist" ∷ ⌜last obj.(state.hist) = Some (lastDig, lastKeys)⌝ ∗
    "%Heq_numVers" ∷ ⌜uint.nat numVers = length (lastKeys !!! uid)⌝
  }}}
  s @! (go.PointerType server.Server) @! "getBound" #uid #numVers
  {{{
    ptr_bound bound, RET #ptr_bound;
    "Hown_serv" ∷ Server.own γ s obj q ∗
    "#Hptr_bound" ∷ ktcore.NonMemb.own ptr_bound bound (□) ∗
    "#Hwish_bound" ∷ ktcore.wish_NonMemb γ.(cfg.vrf_pk) uid numVers lastDig bound
  }}}.
Proof. Admitted.

(** top-level methods. *)

Lemma wp_Server_Put s γ uid sl_pk pk ver :
  {{{
    is_pkg_init server ∗
    "#Hown_serv_ro" ∷ Server.own_ro γ s ∗
    "#Hsl_pk" ∷ sl_pk ↦*□ pk ∗
    (* caller doesn't need anything from Put.
    and in fact, Put might logically execute *after* Put returns. *)
    "#Hop_put" ∷ □ (|={⊤,∅}=> ∃ obj, own γ obj ∗
      let obj' := set state.pending (pure_put uid ver pk) obj in
      (own γ obj' ={∅,⊤}=∗ True))
  }}}
  s @! (go.PointerType server.Server) @! "Put" #uid #ver #sl_pk
  {{{ RET #(); True }}}.
Proof. Admitted.

Lemma wp_Server_History s γ (uid prevEpoch prevVerLen : w64) Q :
  {{{
    is_pkg_init server ∗
    "Hown_serv_lock" ∷ Server.own_lock γ s ∗
    "#Hop_read" ∷ □ (|={⊤,∅}=> ∃ obj, own γ obj ∗
      (own γ obj ={∅,⊤}=∗ Q obj))
  }}}
  s @! (go.PointerType server.Server) @! "History" #uid #prevEpoch #prevVerLen
  {{{
    sl_chainProof sl_linkSig sl_hist ptr_bound err obj lastDig lastKeys,
    RET (#sl_chainProof, #sl_linkSig, #sl_hist, #ptr_bound, #err);
    let numEps := length obj.(state.hist) in
    let pks := lastKeys !!! uid in
    "Hown_serv_lock" ∷ Server.own_lock γ s ∗
    "HQ" ∷ Q obj ∗
    "%Hlast_hist" ∷ ⌜last obj.(state.hist) = Some (lastDig, lastKeys)⌝ ∗
    "#Herr" ∷
      match err with
      | true => ⌜uint.nat prevEpoch ≥ numEps ∨
        uint.nat prevVerLen > length pks⌝
      | false =>
        ∃ lastLink chainProof linkSig hist bound,
        "%Hnoof_eps" ∷ ⌜numEps = sint.nat (W64 $ numEps)⌝ ∗
        "%Hnoof_vers" ∷ ⌜length pks = sint.nat (W64 $ length pks)⌝ ∗
        "#His_lastLink" ∷ hashchain.is_chain obj.(state.hist).*1 None lastLink numEps ∗

        "#Hsl_chainProof" ∷ sl_chainProof ↦*□ chainProof ∗
        "#Hsl_linkSig" ∷ sl_linkSig ↦*□ linkSig ∗
        "#Hsl_hist" ∷ ktcore.MembSlice1D.own sl_hist hist (□) ∗
        "#Hptr_bound" ∷ ktcore.NonMemb.own ptr_bound bound (□) ∗

        "%Hwish_chainProof" ∷ ⌜hashchain.wish_Proof chainProof
          (drop (S (uint.nat prevEpoch)) obj.(state.hist).*1)⌝ ∗
        "#Hwish_linkSig" ∷ ktcore.wish_LinkSig γ.(cfg.sig_pk)
          (W64 $ (Z.of_nat numEps - 1)) lastLink linkSig ∗
        "#Hwish_hist" ∷ ktcore.wish_ListMemb γ.(cfg.vrf_pk) uid prevVerLen
          lastDig hist ∗
        "%Heq_hist" ∷ ⌜Forall2
          (λ x y, x = y.(ktcore.Memb.PkOpen).(ktcore.CommitOpen.Val))
          (drop (uint.nat prevVerLen) pks) hist⌝ ∗
        "#Hwish_bound" ∷ ktcore.wish_NonMemb γ.(cfg.vrf_pk) uid
          (W64 $ length pks) lastDig bound
      end
  }}}.
Proof. Admitted.

Lemma wp_Server_Audit s γ (prevEpoch : w64) Q :
  {{{
    is_pkg_init server ∗
    "Hown_serv_lock" ∷ Server.own_lock γ s ∗
    "#Hop_read" ∷ □ (|={⊤,∅}=> ∃ obj, own γ obj ∗
      (own γ obj ={∅,⊤}=∗ Q obj))
  }}}
  s @! (go.PointerType server.Server) @! "Audit" #prevEpoch
  {{{
    sl_proofs err obj, RET (#sl_proofs, #err);
    let numEps := length obj.(state.hist) in
    "Hown_serv_lock" ∷ Server.own_lock γ s ∗
    "HQ" ∷ Q obj ∗
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
          "%Hlook0" ∷ ⌜obj.(state.hist).*1 !! predEp = Some dig0⌝ ∗
          "%Hlook1" ∷ ⌜obj.(state.hist).*1 !! (S predEp) = Some dig1⌝ ∗
          "#His_upd" ∷ ktcore.wish_ListUpdate dig0 aud.(ktcore.AuditProof.Updates) dig1) ∗
        "#His_sigs" ∷ ([∗ list] i ↦ aud ∈ proofs,
          ∃ link,
          let ep := (uint.nat prevEpoch + S i)%nat in
          "#His_link" ∷ hashchain.is_chain (take (S ep) obj.(state.hist).*1)
            None link (S ep) ∗
          "#His_sig" ∷ ktcore.wish_LinkSig γ.(cfg.sig_pk) (W64 ep) link aud.(ktcore.AuditProof.LinkSig))
      end
  }}}.
Proof. Admitted.

Lemma wp_Server_Start s γ Q :
  {{{
    is_pkg_init server ∗
    "Hown_serv_lock" ∷ Server.own_lock γ s ∗
    "#Hop_read" ∷ □ (|={⊤,∅}=> ∃ obj, own γ obj ∗
      (own γ obj ={∅,⊤}=∗ Q obj))
  }}}
  s @! (go.PointerType server.Server) @! "Start" #()
  {{{
    ptr_chain chain ptr_vrf vrf obj last_link, RET (#ptr_chain, #ptr_vrf);
    let numEps := length obj.(state.hist) in
    "Hown_serv_lock" ∷ Server.own_lock γ s ∗
    "HQ" ∷ Q obj ∗
    "%Hnoof_eps" ∷ ⌜numEps = sint.nat (W64 $ numEps)⌝ ∗

    "#Hptr_chain" ∷ StartChain.own ptr_chain chain (□) ∗
    "#Hptr_vrf" ∷ StartVrf.own ptr_vrf vrf (□) ∗

    "%His_PrevEpochLen" ∷ ⌜uint.nat chain.(StartChain.PrevEpochLen) < numEps⌝ ∗
    "#His_PrevLink" ∷ hashchain.is_chain
      (take (uint.nat chain.(StartChain.PrevEpochLen)) obj.(state.hist).*1)
      None chain.(StartChain.PrevLink)
      (uint.nat chain.(StartChain.PrevEpochLen)) ∗
    "%His_ChainProof" ∷ ⌜hashchain.wish_Proof chain.(StartChain.ChainProof)
      (drop (uint.nat chain.(StartChain.PrevEpochLen)) obj.(state.hist).*1)⌝ ∗
    "#His_last_link" ∷ hashchain.is_chain obj.(state.hist).*1 None
      last_link numEps ∗
    "#His_LinkSig" ∷ ktcore.wish_LinkSig γ.(cfg.sig_pk)
      (W64 $ numEps - 1) last_link chain.(StartChain.LinkSig) ∗

    "%Heq_VrfPk" ∷ ⌜γ.(cfg.vrf_pk) = vrf.(StartVrf.VrfPk)⌝ ∗
    "#His_VrfPk" ∷ cryptoffi.is_vrf_pk vrf.(StartVrf.VrfPk) ∗
    "#His_VrfSig" ∷ ktcore.wish_VrfSig γ.(cfg.sig_pk) γ.(cfg.vrf_pk)
      vrf.(StartVrf.VrfSig)
  }}}.
Proof. Admitted.

End proof.
End server.
