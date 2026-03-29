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
    pending : ktcore.plain_ty;
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
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

(* TODO: [iDestruct own_aux as "[H0 H1]"] uses [into_sep_sep] (high priority)
instead of [into_sep_fractional_half] (priority 100).
not sure if this is a bug in instance priority. *)
Definition own_aux γ obj q : iProp Σ :=
  "Hown_pend" ∷ dghost_var γ.(cfg.pendγ) (DfracOwn q) obj.(state.pending) ∗
  (* client remembers lb's of this. *)
  "Hown_hist" ∷ mono_list_auth_own (digsγ γ) q obj.(state.hist).

(* other 1/2 in server lock inv. *)
Definition own γ obj : iProp Σ := own_aux γ obj (1/2).

(* TODO: prove below admits using auditor.v as reference. *)
#[global] Instance own_aux_frac γ obj :
  fractional.Fractional (λ q, own_aux γ obj q).
Proof. Admitted.

#[global] Instance own_aux_as_frac γ obj q :
  fractional.AsFractional (own_aux γ obj q) (λ q, own_aux γ obj q) q.
Proof. auto. Qed.

#[global] Instance own_aux_combine_sep_gives γ obj0 obj1 q0 q1 :
  CombineSepGives (own_aux γ obj0 q0) (own_aux γ obj1 q1) (⌜obj0 = obj1⌝).
Proof. Admitted.

#[global] Instance own_aux_combine_sep_as γ obj0 obj1 q0 q1 :
  CombineSepAs (own_aux γ obj0 q0) (own_aux γ obj1 q1) (own_aux γ obj0 (q0 + q1)) | 60.
Proof. Admitted.

Definition valid γ obj : iProp Σ :=
  "#Hperm_uids" ∷ ([∗ map] uid ↦ pks ∈ obj.(state.pending),
    ∃ uidγ,
    "%Hlook_uidγ" ∷ ⌜γ.(cfg.uidγ) !! uid = Some uidγ⌝ ∗
    "#Hpks" ∷ ([∗ list] ver ↦ pk ∈ pks,
      ∃ i,
      (* client owns mlist_auth for their uid.
      for adversarial uid, auth in inv. *)
      mono_list_idx_own uidγ i (ver, pk))) ∗
  "%Hsub_pend" ∷ ⌜∀ last_dig,
    last obj.(state.hist) = Some last_dig →
    ktcore.plain_sub (ktcore.to_plain (get_vrf_pk γ) last_dig) obj.(state.pending)⌝ ∗
  "%Hsub_hist" ∷ ⌜ktcore.mono_plain (get_vrf_pk γ) obj.(state.hist)⌝.

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
  by eapply ktcore.mono_plain_lookup.
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
        mono_list_idx_own uidγ i (ver, pk)).
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
  opose proof (ktcore.mono_plain_lookup (get_vrf_pk γ) uid _
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

Definition perm_add_hist γ : iProp Σ :=
  □ (|={⊤,∅}=> ∃ obj, own γ obj ∗
    ∀ dig,
    ⌜ktcore.to_plain (get_vrf_pk γ) dig = obj.(state.pending)⌝ -∗
    let obj' := set (state.hist) (.++ [dig]) obj in
    (own γ obj' ={∅,⊤}=∗ True)).

Lemma op_add_hist γ : is_inv γ -∗ perm_add_hist γ.
Proof.
  rewrite /perm_add_hist. iIntros "#Hinv".
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
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Definition own γ ptr obj : iProp Σ :=
  ∃ ptr_sig ptr_vrf sl_commit,
  "#Hstr_secrets" ∷ ptr ↦□ (server.secrets.mk ptr_sig ptr_vrf sl_commit) ∗
  "#Hown_sig" ∷ cryptoffi.own_sig_sk ptr_sig γ.(cfg.sig_pk)
    (sigpred.P γ.(cfg.sigγ)) ∗
  "#Hown_vrf" ∷ cryptoffi.own_vrf_sk ptr_vrf (get_vrf_pk γ) ∗
  "#Hsl_commit" ∷ sl_commit ↦*□ obj.(commit) ∗
  "%Hlen_commit" ∷ ⌜Z.of_nat (length obj.(commit)) = cryptoffi.hash_len⌝.

End proof.
End secrets.

Module keyStore.
Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
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
  ∃ ptr_hidden hidden ptr_plain ptr0_plain,
  let plain := ktcore.to_plain (get_vrf_pk γ) dig in
  "#Hstr_keyStore" ∷ ptr ↦□ (server.keyStore.mk ptr_hidden ptr_plain) ∗
  "Hown_hidden" ∷ merkle.own_Map ptr_hidden hidden dig (DfracOwn q) ∗
  "Hptr_plain" ∷ ptr_plain ↦${#q} ptr0_plain ∗
  "Hown_plain" ∷ own_plain ptr0_plain plain q ∗
  "%Hbij_maps" ∷ ⌜ktcore.is_plain (get_vrf_pk γ) plain hidden⌝ ∗
  "%His_commit" ∷ ⌜is_commit secs.(secrets.commit) hidden⌝.

End proof.
End keyStore.

Module history.
Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

Definition is_audits γ digs audits : iProp Σ :=
  "%Hlen_audits" ∷ ⌜length digs = length audits⌝ ∗
  (* epoch 0 UpdateProof is invalid. *)
  "#His_upds" ∷ ([∗ list] pred_ep ↦ p ∈ ktcore.AuditProof.Updates <$> drop 1 audits,
    ∃ dig0 dig1,
    "%Hlook0" ∷ ⌜digs !! pred_ep = Some dig0⌝ ∗
    "%Hlook1" ∷ ⌜digs !! (S pred_ep) = Some dig1⌝ ∗
    "#His_upd" ∷ ktcore.wish_ListUpdate dig0 p dig1) ∗
  "#His_sigs" ∷ ([∗ list] ep ↦ sig ∈ ktcore.AuditProof.LinkSig <$> audits,
    ∃ link,
    "%His_link" ∷ ⌜hashchain.inv_fn link (S $ S ep) = (take (S ep) digs, None)⌝ ∗
    "#His_sig" ∷ ktcore.wish_LinkSig γ.(cfg.sig_pk) (W64 ep) link sig).

Definition own γ ptr digs q : iProp Σ :=
  ∃ ptr_chain sl_audits sl0_audits audits sl_vrfSig vrfSig,
  "Hstr_history" ∷ ptr ↦{#q} (server.history.mk ptr_chain sl_audits sl_vrfSig) ∗
  "Hown_chain" ∷ hashchain.own ptr_chain digs (DfracOwn q) ∗

  "Hsl_audits" ∷ sl_audits ↦*{#q} sl0_audits ∗
  "Hcap_audits" ∷ own_slice_cap loc sl_audits (DfracOwn q) ∗
  "#Hown_audits" ∷ ([∗ list] idx ↦ p; aud ∈ sl0_audits; audits,
    ktcore.AuditProof.own p aud (□)) ∗
  "#His_audits" ∷ is_audits γ digs audits ∗

  "#Hsl_vrfSig" ∷ sl_vrfSig ↦*□ vrfSig ∗
  "#His_vrfSig" ∷ ktcore.wish_VrfSig γ.(cfg.sig_pk) (get_vrf_pk γ) vrfSig.

End proof.
End history.

Module work.
Record t' := mk' {
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
  ∃ sl_pk sl_mapLabel mapLabel sl_mapVal mapVal rand,
  "#Hstr_work" ∷ ptr ↦□ (server.work.mk obj.(uid) obj.(ver) sl_pk sl_mapLabel sl_mapVal) ∗
  "#Hsl_pk" ∷ sl_pk ↦*□ obj.(pk) ∗
  "#Hsl_mapLabel" ∷ sl_mapLabel ↦*□ mapLabel ∗
  "#Hsl_mapVal" ∷ sl_mapVal ↦*□ mapVal ∗

  "%His_mapLabel" ∷ ⌜ktcore.map_label_fn (get_vrf_pk γ) obj.(uid)
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
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
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
  ∃ ptr_keys ptr_hist last_dig,
  "#Hfld_keys" ∷ ptr.[server.Server.t, "keys"] ↦□ ptr_keys ∗
  "#Hfld_hist" ∷ ptr.[server.Server.t, "hist"] ↦□ ptr_hist ∗

  "Hown_keys" ∷ keyStore.own γ ptr_keys obj.(secs) last_dig q ∗
  "Hown_hist" ∷ history.own γ ptr_hist σ.(state.hist) q ∗

  (* other 1/2 in server inv. *)
  "Hown_gs" ∷ own_aux γ σ (q/2) ∗
  "%Hlast_dig" ∷ ⌜last σ.(state.hist) = Some last_dig⌝ ∗
  "%Heq_hist_pend" ∷ ⌜ktcore.to_plain (get_vrf_pk γ) last_dig = σ.(state.pending)⌝ ∗
  "#Hperm_add_hist" ∷ perm_add_hist γ.

Definition own_aux γ ptr obj q : iProp Σ := ∃ σ, own γ ptr σ obj q.

Definition lock_perm γ ptr obj : iProp Σ :=
  ∃ ptr_mu,
  "#Hfld_mu" ∷ ptr.[server.Server.t, "mu"] ↦□ ptr_mu ∗

  "Hlock" ∷ own_RWMutex ptr_mu (own_aux γ ptr obj) ∗
  "#Hown_ro" ∷ own_ro γ ptr obj.

End proof.
End Server.

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

(** fetch-side helper funcs. *)

(* TODO: upstream. *)
Lemma subslice_snoc {A} n m (l : list A) x :
  l !! m = Some x →
  (n ≤ m)%nat →
  subslice n (S m) l = subslice n m l ++ [x].
Proof.
  (* TODO: rm [subslice_split_r], worse version of [subslice_app_contig]. *)
  intros **.
  rewrite -(subslice_app_contig _ m); [|lia].
  by erewrite subslice_singleton; [|done].
Qed.

Lemma wp_Server_getHist s γ σ obj (uid prefixLen : w64) q last_dig :
  let pks := ktcore.to_pks (get_vrf_pk γ) uid last_dig in
  {{{
    is_pkg_init server ∗
    "Hown_serv" ∷ Server.own γ s σ obj q ∗
    "#Hown_serv_ro" ∷ Server.own_ro γ s obj ∗
    "%Hlast_dig" ∷ ⌜last σ.(state.hist) = Some last_dig⌝ ∗
    "%Heq_prefixLen" ∷ ⌜uint.nat prefixLen ≤ length pks⌝
  }}}
  s @! (go.PointerType server.Server) @! "getHist" #uid #prefixLen
  {{{
    sl_hist hist, RET #sl_hist;
    "Hown_serv" ∷ Server.own γ s σ obj q ∗
    "#Hsl_hist" ∷ ktcore.MembSlice1D.own sl_hist hist (□) ∗
    "#Hwish_hist" ∷ ktcore.wish_ListMemb (get_vrf_pk γ) uid
      (uint.nat prefixLen) last_dig hist ∗
    "%Heq_hist" ∷ ⌜drop (uint.nat prefixLen) pks =
      ktcore.CommitOpen.Val <$> (ktcore.Memb.PkOpen <$> hist)⌝
  }}}.
Proof.
  simpl. wp_start as "@".
  iNamed "Hown_serv_ro". iNamed "Hown_secs".
  iNamed "Hown_serv". iNamed "Hown_keys".
  iNamed "Hown_plain".
  simplify_eq/=. wp_auto.
  wp_apply (wp_map_lookup1 with "[$Hptr_plain]") as "Hptr_plain".
  (* destruct "uid existence" early to reduce complexity. *)
  destruct (ktcore.to_plain (get_vrf_pk γ) last_dig !! uid) as [pks|] eqn:Hlook_uid.
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

    "#Hwish_hist" ∷ ktcore.wish_ListMemb (get_vrf_pk γ) uid
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
  wp_apply wp_slice_literal as "* Ht".
  { iIntros "**". by wp_auto. }
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
  let pks := ktcore.to_pks (get_vrf_pk γ) uid last_dig in
  {{{
    is_pkg_init server ∗
    "Hown_serv" ∷ Server.own γ s σ obj q ∗
    "#Hown_serv_ro" ∷ Server.own_ro γ s obj ∗
    "%Hlast_dig" ∷ ⌜last σ.(state.hist) = Some last_dig⌝ ∗
    "%Heq_numVers" ∷ ⌜uint.nat numVers = length pks⌝
  }}}
  s @! (go.PointerType server.Server) @! "getBound" #uid #numVers
  {{{
    ptr_bound bound, RET #ptr_bound;
    "Hown_serv" ∷ Server.own γ s σ obj q ∗
    "#Hptr_bound" ∷ ktcore.NonMemb.own ptr_bound bound (□) ∗
    "#Hwish_bound" ∷ ktcore.wish_NonMemb (get_vrf_pk γ) uid
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
    ∃ (i : w64) (t0 : loc) sl_upd sl0_upd upd old_dig,
    let old_pend := ktcore.to_plain (get_vrf_pk γ) old_dig in
    "i" ∷ i_ptr ↦ i ∗
    "%Hlt_i" ∷ ⌜0 ≤ sint.Z i ≤ length work⌝ ∗
    "w" ∷ w_ptr ↦ t0 ∗
    "upd" ∷ upd_ptr ↦ sl_upd ∗
    "Hsl_upd" ∷ sl_upd ↦* sl0_upd ∗
    "Hcap_upd" ∷ own_slice_cap loc sl_upd 1 ∗
    "#Hsl0_upd" ∷ ([∗ list] ptr;obj ∈ sl0_upd;upd, ktcore.UpdateProof.own ptr obj (□)) ∗
    "#His_upd" ∷ ktcore.wish_ListUpdate last_dig upd old_dig ∗
    "Hown_keys" ∷ keyStore.own γ ptr_keys obj.(Server.secs) old_dig 1 ∗
    "Hown_gs" ∷ own_aux γ {| state.pending := old_pend; state.hist := hist |} (1/2)
  )%I with "[Hown_keys Hown_gs upd Hsl_upd Hcap_upd w i]" as "IH".
  { iFrame "∗". iExists []. simpl.
    iSplit; [word|].
    iSplit; [done|].
    iApply ktcore.wish_ListUpdate_nil. }
  wp_for "IH".
  case_bool_decide.
  { iNamed "Hown_keys".
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
      let sl_pks := default slice.nil (ptr0_plain !! w.(work.uid)) in
      "Hsl_pks" ∷ sl_pks ↦* sl0_pks ∗
      "Hcap_pks" ∷ own_slice_cap slice.t sl_pks 1 ∗
      "#Hsl0_pks" ∷ ([∗ list] sl_pk;pk ∈
        sl0_pks;ktcore.to_pks (get_vrf_pk γ) w.(work.uid) old_dig,
        "Hsl_pk" ∷ sl_pk ↦*□ pk) ∗
      "Hown_plain" ∷ keyStore.own_plain (delete w.(work.uid) ptr0_plain)
        (delete w.(work.uid) (ktcore.to_plain (get_vrf_pk γ) old_dig)) 1
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

    iAssert (⌜uint.nat w.(work.ver) =
      length $ ktcore.to_pks (get_vrf_pk γ) w.(work.uid) old_dig⌝)%I
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
    iDestruct "Hown_hist_gs" as "[Hhist Hhist']".
    iMod ("Hperm" with "[$Hpend' $Hhist']") as "_".
    iAssert (own_aux _ _ (1/2))%I with "[$Hpend $Hhist]" as "Hown_gs".
    iModIntro.

    wp_apply (merkle.wp_Map_Put with "[$Hown_hidden]") as "%%%new_dig @".
    { iFrame "#%".
      destruct His_mapLabel as (Ht&_).
      by apply cryptoffi.is_vrf_len in Ht. }
    iPersist "Hsl_updProof". simpl.
    wp_apply (wp_map_lookup1 with "[$Hptr_plain]") as "Hptr_plain".
    wp_apply wp_slice_literal as "* Ht".
    { iIntros "**". by wp_auto. }
    replace (sint.nat _) with 0%nat by word. simpl.
    wp_apply (wp_slice_append with "[$Hsl_pks $Hcap_pks $Ht]")
      as "%sl_pks (Hsl_pks&Hcap_pks&_)".
    simpl. wp_apply (wp_map_insert with "[$Hptr_plain]") as "Hptr_plain".
    wp_apply wp_alloc as "%ptr_info Hptr_info".
    iPersist "Hptr_info".
    wp_apply wp_slice_literal as "* Ht".
    { iIntros "**". by wp_auto. }
    replace (sint.nat _) with 0%nat by word. simpl.
    wp_apply (wp_slice_append with "[$Hsl_upd $Hcap_upd $Ht]")
      as "%sl_upd' (Hsl_upd&Hcap_upd&_)".

    wp_for_post.
    iDestruct (merkle.own_Map_to_is_map with "Hown_Map") as %Hnew_dig.
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
    - apply map_Forall_insert_2; [|done].
      apply ktcore.map_val_iff in His_mapVal.
      naive_solver. }
Admitted.

(** top-level methods. *)

(* TODO: instead of duplicating the op perm bodies, should use their defns. *)
Lemma wp_Server_Put s γ obj uid sl_pk pk ver :
  {{{
    is_pkg_init server ∗
    "#Hown_serv_ro" ∷ Server.own_ro γ s obj ∗
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

(* TODO: when adapting below to lock_perm change, obj conflicts with σ.
need to rename existing obj to σ. *)
Lemma wp_Server_History s γ (uid prevEpoch prevVerLen : w64) Q :
  {{{
    is_pkg_init server ∗
    "Hown_serv_lock" ∷ Server.lock_perm γ s ∗
    "#Hop_read" ∷ □ (|={⊤,∅}=> ∃ obj, own γ obj ∗
      (own γ obj ={∅,⊤}=∗ Q obj))
  }}}
  s @! (go.PointerType server.Server) @! "History" #uid #prevEpoch #prevVerLen
  {{{
    sl_chainProof sl_linkSig sl_hist ptr_bound err obj last_dig,
    RET (#sl_chainProof, #sl_linkSig, #sl_hist, #ptr_bound, #err);
    let numEps := length obj.(state.hist) in
    let pks := ktcore.to_pks (get_vrf_pk γ) uid last_dig in
    "Hown_serv_lock" ∷ Server.lock_perm γ s ∗
    "HQ" ∷ Q obj ∗
    "%Hlast_hist" ∷ ⌜last obj.(state.hist) = Some last_dig⌝ ∗
    "#Herr" ∷
      match err with
      | true => ⌜uint.nat prevEpoch ≥ numEps ∨
        uint.nat prevVerLen > length pks⌝
      | false =>
        ∃ lastLink chainProof linkSig hist bound,
        "%Hnoof_eps" ∷ ⌜numEps = sint.nat (W64 $ numEps)⌝ ∗
        "%Hnoof_vers" ∷ ⌜length pks = sint.nat (W64 $ length pks)⌝ ∗
        "%His_lastLink" ∷ ⌜hashchain.inv_fn lastLink (S numEps) = (obj.(state.hist), None)⌝ ∗

        "#Hsl_chainProof" ∷ sl_chainProof ↦*□ chainProof ∗
        "#Hsl_linkSig" ∷ sl_linkSig ↦*□ linkSig ∗
        "#Hsl_hist" ∷ ktcore.MembSlice1D.own sl_hist hist (□) ∗
        "#Hptr_bound" ∷ ktcore.NonMemb.own ptr_bound bound (□) ∗

        "%Hwish_chainProof" ∷ ⌜hashchain.wish_Proof chainProof
          (drop (S (uint.nat prevEpoch)) obj.(state.hist))⌝ ∗
        "#Hwish_linkSig" ∷ ktcore.wish_LinkSig γ.(cfg.sig_pk)
          (W64 $ (Z.of_nat numEps - 1)) lastLink linkSig ∗
        "#Hwish_hist" ∷ ktcore.wish_ListMemb (get_vrf_pk γ) uid (uint.nat prevVerLen)
          last_dig hist ∗
        "%Heq_hist" ∷ ⌜Forall2
          (λ x y, x = y.(ktcore.Memb.PkOpen).(ktcore.CommitOpen.Val))
          (drop (uint.nat prevVerLen) pks) hist⌝ ∗
        "#Hwish_bound" ∷ ktcore.wish_NonMemb (get_vrf_pk γ) uid
          (length pks) last_dig bound
      end
  }}}.
Proof. Admitted.

Lemma wp_Server_Audit s γ (prevEpoch : w64) Q :
  {{{
    is_pkg_init server ∗
    "Hown_serv_lock" ∷ Server.lock_perm γ s ∗
    "#Hop_read" ∷ □ (|={⊤,∅}=> ∃ obj, own γ obj ∗
      (own γ obj ={∅,⊤}=∗ Q obj))
  }}}
  s @! (go.PointerType server.Server) @! "Audit" #prevEpoch
  {{{
    sl_proofs err obj, RET (#sl_proofs, #err);
    let numEps := length obj.(state.hist) in
    "Hown_serv_lock" ∷ Server.lock_perm γ s ∗
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
          "%Hlook0" ∷ ⌜obj.(state.hist) !! predEp = Some dig0⌝ ∗
          "%Hlook1" ∷ ⌜obj.(state.hist) !! (S predEp) = Some dig1⌝ ∗
          "#His_upd" ∷ ktcore.wish_ListUpdate dig0 aud.(ktcore.AuditProof.Updates) dig1) ∗
        "#His_sigs" ∷ ([∗ list] i ↦ aud ∈ proofs,
          ∃ link,
          let ep := (uint.nat prevEpoch + S i)%nat in
          "%His_link" ∷ ⌜hashchain.inv_fn link (S $ S ep) =
            (take (S ep) obj.(state.hist), None)⌝ ∗
          "#His_sig" ∷ ktcore.wish_LinkSig γ.(cfg.sig_pk) (W64 ep) link aud.(ktcore.AuditProof.LinkSig))
      end
  }}}.
Proof. Admitted.

Lemma wp_Server_Start s γ Q :
  {{{
    is_pkg_init server ∗
    "Hown_serv_lock" ∷ Server.lock_perm γ s ∗
    "#Hop_read" ∷ □ (|={⊤,∅}=> ∃ obj, own γ obj ∗
      (own γ obj ={∅,⊤}=∗ Q obj))
  }}}
  s @! (go.PointerType server.Server) @! "Start" #()
  {{{
    ptr_chain chain ptr_vrf vrf obj last_link, RET (#ptr_chain, #ptr_vrf);
    let numEps := length obj.(state.hist) in
    "Hown_serv_lock" ∷ Server.lock_perm γ s ∗
    "HQ" ∷ Q obj ∗
    "%Hnoof_eps" ∷ ⌜numEps = sint.nat (W64 $ numEps)⌝ ∗

    "#Hptr_chain" ∷ StartChain.own ptr_chain chain (□) ∗
    "#Hptr_vrf" ∷ StartVrf.own ptr_vrf vrf (□) ∗

    "%His_PrevEpochLen" ∷ ⌜uint.nat chain.(StartChain.PrevEpochLen) < numEps⌝ ∗
    "%His_PrevLink" ∷ ⌜hashchain.inv_fn chain.(StartChain.PrevLink)
      (S $ uint.nat chain.(StartChain.PrevEpochLen)) =
      (take (uint.nat chain.(StartChain.PrevEpochLen)) obj.(state.hist), None)⌝ ∗
    "%His_ChainProof" ∷ ⌜hashchain.wish_Proof chain.(StartChain.ChainProof)
      (drop (uint.nat chain.(StartChain.PrevEpochLen)) obj.(state.hist))⌝ ∗
    "%His_last_link" ∷ ⌜hashchain.inv_fn last_link (S numEps) =
      (obj.(state.hist), None)⌝ ∗
    "#His_LinkSig" ∷ ktcore.wish_LinkSig γ.(cfg.sig_pk)
      (W64 $ numEps - 1) last_link chain.(StartChain.LinkSig) ∗

    "%Heq_VrfPk" ∷ ⌜get_vrf_pk γ = vrf.(StartVrf.VrfPk)⌝ ∗
    "#His_VrfPk" ∷ cryptoffi.is_vrf_pk vrf.(StartVrf.VrfPk) ∗
    "#His_VrfSig" ∷ ktcore.wish_VrfSig γ.(cfg.sig_pk) (get_vrf_pk γ)
      vrf.(StartVrf.VrfSig)
  }}}.
Proof. Admitted.

End proof.
End server.
