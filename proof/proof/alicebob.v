From New.generatedproof.github_com.sanjit_bhat.pav Require Import alicebob.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof Require Import bytes time.
From New.proof.github_com.goose_lang Require Import primitive std.
From New.proof.github_com.sanjit_bhat.pav Require Import
  advrpc auditor client cryptoffi ktcore server.

Module alicebob.

Module Trust.
Inductive t :=
  | No
  | SigPred
  | Full.

Definition rank t : nat :=
  match t with No => 0 | SigPred => 1 | Full => 2 end.
End Trust.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : alicebob.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

#[global] Instance : IsPkgInit (iProp Σ) alicebob := define_is_pkg_init True%I.
#[global] Instance : GetIsPkgInitWf (iProp Σ) alicebob := build_get_is_pkg_init_wf.

(* TODO: [solve_pkg_init] should recursively unfold pkg deps.
currently, it unfolds just one level.
for efficiency, it should only add unique pkgs to the context.
[solve_pkg_init2] is just an inefficient hack that hard-codes to two-levels. *)
Ltac solve_pkg_init2 :=
  unfold named;
  lazymatch goal with
  | |- environments.envs_entails ?env (is_pkg_init _) => idtac
  | _ => fail "not a is_pkg_init goal"
  end;
  try iAssumption;
  iClear "∗";
  do 2 (
    iEval (rewrite ?is_pkg_init_unfold; simpl is_pkg_init_deps; unfold named) in "#";
    repeat
      lazymatch goal with
      | |- environments.envs_entails ?env _ =>
          lazymatch env with
          | context[environments.Esnoc _ ?i (_ ∗ _)%I] =>
              iDestruct i as "[? ?]"
          | context[environments.Esnoc _ ?i (□ _)%I] =>
              iDestruct i as "#?"
          end
      end);
  solve [ iFrame "#" ].

Lemma wp_testAliceBob (serv_trust adtr_trust : Trust.t)
    (alice_good bob_good : bool)
    (servAddr : w64) (servGood : bool) sl_adtrAddrs (adtrAddrs : list w64) :
  {{{
    is_pkg_init alicebob ∗
    "#Hsl_adtrAddrs" ∷ sl_adtrAddrs ↦*□ adtrAddrs ∗
    "%Hlen_adtrAddrs" ∷ ⌜length adtrAddrs = 3%nat⌝ ∗
    "%Heq_servGood" ∷ ⌜servGood =
      bool_decide (Trust.rank Trust.No < Trust.rank serv_trust)⌝ ∗
    "%Hmin_trust" ∷ ⌜Trust.rank Trust.No < Trust.rank serv_trust ∨
      Trust.rank Trust.No < Trust.rank adtr_trust⌝
  }}}
  @! alicebob.testAliceBob #servAddr #servGood #sl_adtrAddrs
  {{{ RET #(); True }}}.
Proof.
  wp_start as "@". wp_auto.
  subst. set (bool_decide (Trust.rank Trust.No < Trust.rank serv_trust)) as servGood.
  iMod (mono_list_own_alloc ([] : list (nat * list w8))) as (alice_uidγ) "[Halice_puts _]".
  iMod (mono_list_own_alloc ([] : list (nat * list w8))) as (bob_uidγ) "[Hbob_puts _]".
  iAssert (
    |={⊤}=>
    match alice_good with
    | true => mono_list_auth_own alice_uidγ 1 ([] : list (nat * list w8))
    | false => client.ver.is_uid_inv alice_uidγ
    end)%I with "[Halice_puts]" as "> Halice_good".
  { case_match; [by iFrame|].
    iApply inv_alloc.
    iFrame. }
  iAssert (
    |={⊤}=>
    match bob_good with
    | true => mono_list_auth_own bob_uidγ 1 ([] : list (nat * list w8))
    | false => client.ver.is_uid_inv bob_uidγ
    end)%I with "[Hbob_puts]" as "> Hbob_good".
  { case_match; [by iFrame|].
    iApply inv_alloc.
    iFrame. }
  set ({[W64 0:=alice_uidγ; W64 1:=bob_uidγ]} : gmap w64 gname) as uidγs.

  wp_apply (server.wp_New uidγs) as "* H".
  iNamedSuffix "H" "_serv".
  wp_apply (server.wp_NewRpcServer with "[$Hlocks_serv]") as "* @".
  wp_apply advrpc.wp_Server_Serve.
  { iFrame "#". solve_pkg_init2. }
  wp_apply time.wp_Sleep.
  set (match serv_trust with
    | Trust.No => server.Trust.No
    | Trust.SigPred => server.Trust.SigPred γ.(server.cfg.agreeγ)
    | Trust.Full => server.Trust.Full γ
    end) as serv_trust'.
  assert (∀ t, server.Trust.get_full serv_trust' = Some t → t = γ) as Heq_serv_full.
  { intros. destruct serv_trust; try done; by simplify_eq/=. }
  assert (∀ t, server.Trust.get_sigpred serv_trust' = Some t → t = γ.(server.cfg.agreeγ))
    as Heq_serv_sig.
  { intros. destruct serv_trust; try done; by simplify_eq/=. }
  wp_apply (client.wp_New uidγs serv_trust' with "[$Halice_good]") as "* @".
  { iFrame "#".
    iSplitR. { iPureIntro. by simplify_map_eq/=. }
    rewrite (assoc _).
    iSplitR.
    - destruct (server.Trust.get_full _); try done.
      opose proof (Heq_serv_full _ _); [done|by subst].
    - destruct (server.Trust.get_sigpred _); try done.
      opose proof (Heq_serv_sig _ _); [done|by subst]. }
  clear Hblame.
  wp_apply primitive.wp_Assume as "%".
  case_bool_decide as Ht; try done.
  apply ktcore.rw_Blame0 in Ht. subst.
  destruct (decide (_ ≠ ∅)) as [Ht|Ht]; try done. clear Ht.
  iNamedSuffix "Herr" "_al".
  wp_apply primitive.wp_Assume as "%".
  case_bool_decide as Ht; try done. subst.
  wp_apply (client.wp_New uidγs serv_trust' with "[$Hbob_good]") as "* @".
  { iFrame "#".
    iSplitR. { iPureIntro. by simplify_map_eq/=. }
    rewrite (assoc _).
    iSplitR.
    - destruct (server.Trust.get_full _); try done.
      opose proof (Heq_serv_full _ _); [done|by subst].
    - destruct (server.Trust.get_sigpred _); try done.
      opose proof (Heq_serv_sig _ _); [done|by subst]. }
  clear Hblame.
  wp_apply primitive.wp_Assume as "%".
  case_bool_decide as Ht; try done.
  apply ktcore.rw_Blame0 in Ht. subst.
  destruct (decide (_ ≠ ∅)) as [Ht|Ht]; try done. clear Ht.
  iNamedSuffix "Herr" "_bob".
  wp_apply primitive.wp_Assume as "%".
  case_bool_decide as Ht; try done. subst.
  wp_apply (client.wp_Client_Get with "[$Hclient_bob]") as "* @".
  clear Hblame.
  wp_apply primitive.wp_Assume as "%".
  case_bool_decide as Ht; try done.
  apply ktcore.rw_Blame0 in Ht. subst.
  destruct (decide (_ ≠ ∅)) as [Ht|Ht]; try done. clear Ht.
  iNamedSuffix "Herr" "_bob0". simpl in *.
  wp_apply primitive.wp_Assume as "%".
  case_bool_decide as Ht; try done. subst.

  iDestruct (own_slice_len with "Hsl_adtrAddrs") as %?.
  (* TODO: [wp_if_join], like [wp_for], should automatically generalize
  over the exclusive context. *)
  iPersist "adtrAddrs servGood servAddr servPk alice bob".
  wp_if_join
    (λ v,
    |==> ∃ adtr0 adtr1 sl_adtr0Pk sl_adtr1Pk,
    "->" ∷ ⌜v = execute_val⌝ ∗
    "err" ∷ err_ptr ↦ ktcore.blame_to_u64 ∅ ∗
    "ep" ∷ ep_ptr ↦ W64 0 ∗
    "#adtr0" ∷ adtr0_ptr ↦□ adtr0 ∗
    "#adtr1" ∷ adtr1_ptr ↦□ adtr1 ∗
    "#adtr0Pk" ∷ adtr0Pk_ptr ↦□ sl_adtr0Pk ∗
    "#adtr1Pk" ∷ adtr1Pk_ptr ↦□ sl_adtr1Pk ∗
    "HservGood0" ∷ if servGood then True else
      ∃ adtr0γ adtr1γ,
      "Hadtr0" ∷ auditor.Auditor.lock_perm adtr0 adtr0γ ∗
      "Hadtr1" ∷ auditor.Auditor.lock_perm adtr1 adtr1γ ∗
      "%Heq_servGood0" ∷ ⌜adtr0γ.(auditor.cfg.serv_good) = serv_trust'⌝ ∗
      "%Heq_servGood1" ∷ ⌜adtr1γ.(auditor.cfg.serv_good) = serv_trust'⌝ ∗
      "#Hsl_sigPk0" ∷ sl_adtr0Pk ↦*□ adtr0γ.(auditor.cfg.adtr_sig_pk) ∗
      "#Hsl_sigPk1" ∷ sl_adtr1Pk ↦*□ adtr1γ.(auditor.cfg.adtr_sig_pk) ∗
      "#His_sigPk0" ∷ cryptoffi.is_sig_pk adtr0γ.(auditor.cfg.adtr_sig_pk)
        (sigpred.P adtr0γ.(auditor.cfg.agreeγ)) ∗
      "#His_sigPk1" ∷ cryptoffi.is_sig_pk adtr1γ.(auditor.cfg.adtr_sig_pk)
        (sigpred.P adtr1γ.(auditor.cfg.agreeγ))
    )%I with "[err ep adtr0 adtr1 adtr0Pk adtr1Pk]".
  { iPersist "adtr0 adtr1 adtr0Pk adtr1Pk". by iFrame "∗#". }
  { wp_apply (auditor.wp_New serv_trust') as "* @".
    { iFrame "#".
      destruct (server.Trust.get_full _); try done.
      opose proof (Heq_serv_full _ _); [done|subst].
      by iFrame "#". }
    clear Hblame.
    wp_apply primitive.wp_Assume as "%".
    case_bool_decide as Ht; try done.
    apply ktcore.rw_Blame0 in Ht. subst.
    destruct (decide (_ ≠ ∅)) as [Ht|Ht]; try done. clear Ht.
    iNamedSuffix "Herr" "_adtr0".
    wp_apply (auditor.wp_New serv_trust') as "* @".
    { iFrame "#".
      destruct (server.Trust.get_full _); try done.
      opose proof (Heq_serv_full _ _); [done|subst].
      by iFrame "#". }
    clear Hblame.
    wp_apply primitive.wp_Assume as "%".
    case_bool_decide as Ht; try done.
    apply ktcore.rw_Blame0 in Ht. subst.
    destruct (decide (_ ≠ ∅)) as [Ht|Ht]; try done. clear Ht.
    iNamedSuffix "Herr" "_adtr1".
    replace (Z.to_nat rwmutex.actualMaxReaders) with
      (S $ pred $ Z.to_nat rwmutex.actualMaxReaders).
    2: { rewrite rwmutex.actualMaxReaders_unseal. lia. }
    simpl.
    iDestruct "Hlocks_adtr0" as "[Hadtr0 Hlocks_adtr0]".
    iDestruct "Hlocks_adtr1" as "[Hadtr1 Hlocks_adtr1]".
    list_elem adtrAddrs 0%nat as adtrAddr0.
    list_elem adtrAddrs 1%nat as adtrAddr1.
    case_decide as Ht; [|word]. clear Ht.
    wp_apply (wp_load_slice_index with "[$Hsl_adtrAddrs]") as "_"; [word|done|].
    wp_apply (auditor.wp_NewRpcServer with "[$Hlocks_adtr0]") as "* H".
    iNamedSuffix "H" "0".
    wp_apply advrpc.wp_Server_Serve.
    { iFrame "#". solve_pkg_init2. }
    case_decide as Ht; [|word]. clear Ht.
    wp_apply (wp_load_slice_index with "[$Hsl_adtrAddrs]") as "_"; [word|done|].
    wp_apply (auditor.wp_NewRpcServer with "[$Hlocks_adtr1]") as "* H".
    iNamedSuffix "H" "1".
    wp_apply advrpc.wp_Server_Serve.
    { iFrame "#". solve_pkg_init2. }
    wp_apply time.wp_Sleep.
    iPersist "adtr0 adtr1 adtr0Pk adtr1Pk".
    iFrame "adtr0 adtr1 adtr0Pk adtr1Pk".
    by iFrame "∗#". }
Admitted.

End proof.
End alicebob.
