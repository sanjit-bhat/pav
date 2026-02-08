From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import
  cryptoffi cryptoutil hashchain merkle safemarshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import
  serde.

Module ktcore.
Import serde.ktcore.

(* gmap from uid's to list of pks (indexed by version). *)
Definition keys_ty := gmap w64 (list $ list w8).

(* FIXME: needed for lia to unify [length digs] terms where one has keys_ty and
the other has its unfolding *)
#[global] Hint Unfold keys_ty : word.

Definition keys_sub : relation keys_ty := map_included (λ _, prefix).

Section proof.
Context `{hG: heapGS Σ, !ffi_semantics _ _, !globalsGS Σ} {go_ctx : GoContext}.
Context `{!pavG Σ}.

Definition is_MapLabel vrf_pk uid ver map_label : iProp Σ :=
  let enc := MapLabel.pure_enc (MapLabel.mk' uid ver) in
  cryptoffi.is_vrf_out vrf_pk (Some enc) map_label.

Lemma is_MapLabel_det pk uid ver map_label0 map_label1 :
  is_MapLabel pk uid ver map_label0 -∗
  is_MapLabel pk uid ver map_label1 -∗
  ⌜map_label0 = map_label1⌝.
Proof.
  rewrite /is_MapLabel.
  iIntros "#H0 #H1".
  iDestruct (cryptoffi.is_vrf_out_det with "H0 H1") as %->.
  done.
Qed.

(* externalize [rand] bc some clients want to determ
derive [map_val] from [kt_pk]. *)
Definition is_MapVal kt_pk rand map_val : iProp Σ :=
  let enc := CommitOpen.pure_enc (CommitOpen.mk' kt_pk rand) in
  cryptoffi.is_hash (Some enc) map_val.

Lemma is_MapVal_det pk rand map_val0 map_val1 :
  is_MapVal pk rand map_val0 -∗
  is_MapVal pk rand map_val1 -∗
  ⌜map_val0 = map_val1⌝.
Proof.
  iIntros "#H0 #H1".
  iDestruct (cryptoffi.is_hash_det with "H0 H1") as %->.
  done.
Qed.

Local Definition decode_map_label odata :=
  rem0 ← odata;
  guard (length rem0 ≥ 8);;
  let uid := le_to_u64 (take 8 rem0) in
  let rem1 := drop 8 rem0 in
  guard (length rem1 ≥ 8);;
  let ver := le_to_u64 (take 8 rem1) in
  Some (uid, uint.nat ver).

Local Definition decode_map_val odata :=
  rem0 ← odata;
  guard (length rem0 ≥ 8);;
  let pk_len := sint.nat (le_to_u64 (take 8 rem0)) in
  let rem1 := drop 8 rem0 in
  guard (length rem1 ≥ pk_len);;
  let pk := take pk_len rem1 in
  (* drop the remaining rand. we don't need that. *)
  Some (pk).

Local Definition is_dec_map_label vrf_pk obj map_label : iProp Σ :=
  ∃ odata,
  "#His_vrf_out" ∷ cryptoffi.is_vrf_out vrf_pk odata map_label ∗
  "%Hdec" ∷ ⌜obj = decode_map_label odata⌝.

Local Definition is_dec_map_val obj map_val : iProp Σ :=
  ∃ odata,
  "#His_hash" ∷ cryptoffi.is_hash odata map_val ∗
  "%Hdec" ∷ ⌜obj = decode_map_val odata⌝.

Local Definition is_oflat vrf_pk oflat hidden : iProp Σ :=
  ([∗ list] x;y ∈ oflat;map_to_list hidden,
    is_dec_map_label vrf_pk x.1 y.1 ∗
    is_dec_map_val x.2 y.2).

Local Definition to_flat oflat : list (w64 * nat * list w8) :=
  omap
    (λ '(olabel, oval),
      '(uid, ver) ← olabel;
      pk ← oval;
      Some (uid, ver, pk))
    oflat.

Local Definition to_mapped flat : gmap w64 (gmap nat (list w8)) :=
  foldl
    (λ m '(uid, ver, pk),
      let m_uid := m !!! uid in
      let m_uid' := <[ver:=pk]>m_uid in
      <[uid:=m_uid']>m)
    ∅ flat.

Local Fixpoint get_contig (m_uid : gmap nat (list w8)) ver fuel :=
  match fuel with 0%nat => [] | S fuel' =>
  match m_uid !! ver with None => [] | Some pk =>
  pk :: get_contig m_uid (S ver) fuel' end end.

Local Definition to_plain mapped : gmap w64 (list (list w8)) :=
  (* size is simple upper bound on max ver. *)
  (λ m_uid, get_contig m_uid 0 (size m_uid)) <$> mapped.

Definition is_plain_keys (vrf_pk : list w8)
    (plain : keys_ty) (hidden : gmap (list w8) (list w8)) : iProp Σ :=
  ∃ oflat,
  "#His_oflat" ∷ is_oflat vrf_pk oflat hidden ∗
  "%Heq_plain" ∷ ⌜plain = to_plain (to_mapped (to_flat oflat))⌝.

(* determinism helpers. *)

Local Lemma is_dec_map_label_inj vrf_pk obj0 obj1 map_label :
  is_dec_map_label vrf_pk obj0 map_label -∗
  is_dec_map_label vrf_pk obj1 map_label -∗
  ⌜obj0 = obj1⌝.
Proof.
  iNamedSuffix 1 "0".
  iNamedSuffix 1 "1".
  iDestruct (cryptoffi.is_vrf_out_inj with "His_vrf_out0 His_vrf_out1") as %<-.
  by simplify_eq/=.
Qed.

Local Lemma is_dec_map_val_inj obj0 obj1 map_val :
  is_dec_map_val obj0 map_val -∗
  is_dec_map_val obj1 map_val -∗
  ⌜obj0 = obj1⌝.
Proof.
  iNamedSuffix 1 "0".
  iNamedSuffix 1 "1".
  iDestruct (cryptoffi.is_hash_inj with "His_hash0 His_hash1") as %<-.
  by simplify_eq/=.
Qed.

Local Lemma decoded_det vrf_pk l decoded0 decoded1 :
  ([∗ list] kv;d ∈ l;decoded0,
    is_dec_map_label vrf_pk kv.1 d.1 ∗ is_dec_map_val kv.2 d.2) -∗
  ([∗ list] kv;d ∈ l;decoded1,
    is_dec_map_label vrf_pk kv.1 d.1 ∗ is_dec_map_val kv.2 d.2) -∗
  ⌜decoded0 = decoded1⌝.
Proof.
  revert decoded0 decoded1.
  induction l as [|kv l' IH]; intros decoded0 decoded1; simpl.
  - destruct decoded0 as [|? ?]; [destruct decoded1 as [|? ?]|];
      [done|iIntros "_ []"|iIntros "[]"].
  - destruct decoded0 as [|d0 ds0]; [iIntros "[]"|].
    destruct decoded1 as [|d1 ds1]; [iIntros "_ []"|].
    iIntros "[[#Hlabel0 #Hval0] #Htail0] [[#Hlabel1 #Hval1] #Htail1]".
    iDestruct (is_dec_map_label_det with "Hlabel0 Hlabel1") as %Heq_fst.
    iDestruct (is_dec_map_val_det with "Hval0 Hval1") as %Heq_snd.
    iDestruct (IH with "Htail0 Htail1") as %Heq_tail.
    iPureIntro.
    destruct d0, d1; simpl in *. congruence.
Qed.

Lemma is_flat_keys_det vrf_pk hidden flat0 flat1 :
  is_flat_keys vrf_pk hidden flat0 -∗
  is_flat_keys vrf_pk hidden flat1 -∗
  ⌜flat0 = flat1⌝.
Proof.
  iIntros "#H0 #H1".
  iDestruct "H0" as (decoded0) "[#Hdec0 %Hfilter0]".
  iDestruct "H1" as (decoded1) "[#Hdec1 %Hfilter1]".
  iDestruct (decoded_det with "Hdec0 Hdec1") as %<-.
  iPureIntro. congruence.
Qed.

(* used by clients who agree across the same digs. *)
Lemma is_plain_keys_det vrf_pk hidden plain0 plain1 :
  is_plain_keys vrf_pk hidden plain0 -∗
  is_plain_keys vrf_pk hidden plain1 -∗
  ⌜plain0 = plain1⌝.
Proof.
  iIntros "#H0 #H1".
  iDestruct "H0" as (flat0 interm0) "(#Hflat0 & %Hinterm0 & %Hplain0)".
  iDestruct "H1" as (flat1 interm1) "(#Hflat1 & %Hinterm1 & %Hplain1)".
  iDestruct (is_flat_keys_det with "Hflat0 Hflat1") as %<-.
  iPureIntro. congruence.
Qed.

(* inversion helpers. *)

(* TODO: depends on dropping hash_len req from cryptoffi.is_hash_invert. *)
Local Lemma is_hash_invert' hash : ⊢ ∃ odata, cryptoffi.is_hash odata hash.
Proof. Admitted.

Local Lemma decoded_invert vrf_pk l :
  ⊢ ∃ decoded, [∗ list] kv;d ∈ l;decoded,
    is_dec_map_label vrf_pk kv.1 d.1 ∗ is_dec_map_val kv.2 d.2.
Proof.
  induction l as [|kv l' IH]; simpl.
  - iExists []. done.
  - iDestruct IH as (decoded') "#Htail".
    iDestruct (cryptoffi.is_vrf_out_invert vrf_pk kv.1) as (odata_l) "#Hvrf".
    iDestruct (is_hash_invert' kv.2) as (odata_v) "#Hhash".
    iExists ((decode_map_label odata_l, decode_map_val odata_v) :: decoded').
    iSplit.
    + iSplit.
      * rewrite /is_dec_map_label. iExists odata_l. iFrame "#". done.
      * rewrite /is_dec_map_val. iExists odata_v. iFrame "#". done.
    + iExact "Htail".
Qed.

Lemma is_flat_keys_invert vrf_pk hidden :
  ⊢ ∃ flat, is_flat_keys vrf_pk hidden flat.
Proof.
  iDestruct (decoded_invert vrf_pk (map_to_list hidden)) as (decoded) "#Hdec".
  iExists (omap (λ '(olabel, oval),
    '(uid, ver) ← olabel;
    pk ← oval;
    Some (uid, ver, pk)) decoded).
  rewrite /is_flat_keys. iExists decoded. iFrame "#". done.
Qed.

(* used by auditor.
to prove, is_plain_keys can't require bijection. *)
Lemma is_plain_keys_invert vrf_pk hidden :
  ⊢ ∃ plain, is_plain_keys vrf_pk hidden plain.
Proof.
  iDestruct (is_flat_keys_invert vrf_pk hidden) as (flat) "#Hflat".
  iExists ((λ m_uid, get_contig m_uid 0 (size m_uid)) <$> assemble flat).
  rewrite /is_plain_keys.
  iExists flat, (assemble flat). iFrame "#". done.
Qed.

(* monotonicity helpers. *)

Local Lemma get_contig_prefix m0 m1 ver fuel0 fuel1 :
  m0 ⊆ m1 → fuel0 ≤ fuel1 →
  prefix (get_contig m0 ver fuel0) (get_contig m1 ver fuel1).
Proof.
  revert ver fuel1.
  induction fuel0 as [|fuel0' IH]; intros ver fuel1 Hsub Hfuel; simpl.
  - apply prefix_nil.
  - destruct fuel1 as [|fuel1']; [lia|].
    destruct (m0 !! ver) as [pk|] eqn:Hlook0.
    + apply map_subseteq_spec in Hsub.
      pose proof (Hsub _ _ Hlook0) as Hlook1.
      simpl. rewrite Hlook1.
      apply prefix_cons. apply IH; [|lia].
      by apply map_subseteq_spec.
    + apply prefix_nil.
Qed.

(* flat0's entries are contained in flat1
when hidden0 ⊆ hidden1. *)
Local Lemma is_flat_keys_sub vrf_pk hidden0 hidden1 flat0 flat1 :
  hidden0 ⊆ hidden1 →
  is_flat_keys vrf_pk hidden0 flat0 -∗
  is_flat_keys vrf_pk hidden1 flat1 -∗
  ⌜∀ e, e ∈ flat0 → e ∈ flat1⌝.
Proof.
  iIntros (Hhsub) "#H0 #H1".
  iDestruct "H0" as (decoded0) "[#Hdec0 %Hfilter0]".
  iDestruct "H1" as (decoded1) "[#Hdec1 %Hfilter1]".
  iDestruct (big_sepL2_forall with "Hdec0") as "[%Hlen0 #HH0]".
  iDestruct (big_sepL2_forall with "Hdec1") as "[%Hlen1 #HH1]".
  iAssert (⌜∀ d, d ∈ decoded0 →
    ∃ d', d' ∈ decoded1 ∧ d'.1 = d.1 ∧ d'.2 = d.2⌝) as %Hdsub.
  { iIntros (d Hd_in).
    apply elem_of_list_lookup in Hd_in as [k Hd_look].
    (* find the corresponding entry in map_to_list hidden0. *)
    assert (k < length (map_to_list hidden0)) as Hk_bound.
    { apply lookup_lt_Some in Hd_look. lia. }
    assert (is_Some ((map_to_list hidden0) !! k)) as [kv Hkv_look].
    { apply lookup_lt_is_Some. lia. }
    (* get crypto facts for this entry in hidden0. *)
    iDestruct ("HH0" $! k kv d with "[] []") as "[#Hlabel0 #Hval0]";
      [done..|].
    (* kv = (label, val) is in hidden0, hence in hidden1. *)
    assert ((kv.1, kv.2) ∈ map_to_list hidden0) as Hkv_elem.
    { apply elem_of_list_lookup. exists k. by destruct kv. }
    apply elem_of_map_to_list in Hkv_elem.
    apply map_subseteq_spec in Hhsub.
    pose proof (Hhsub _ _ Hkv_elem) as Hkv_in1.
    apply elem_of_map_to_list in Hkv_in1.
    apply elem_of_list_lookup in Hkv_in1 as [j Hj_look].
    (* find the corresponding decoded entry. *)
    assert (j < length decoded1) as Hj_bound.
    { apply lookup_lt_Some in Hj_look. lia. }
    assert (is_Some (decoded1 !! j)) as [d' Hd'_look].
    { apply lookup_lt_is_Some. lia. }
    (* get crypto facts for this entry in hidden1. *)
    iDestruct ("HH1" $! j _ d' with "[] []") as "[#Hlabel1 #Hval1]".
    { iPureIntro. by destruct kv. }
    { done. }
    (* determinism: same label/val → same decoded result. *)
    iDestruct (is_dec_map_label_det with "Hlabel0 Hlabel1") as %Heq_l.
    iDestruct (is_dec_map_val_det with "Hval0 Hval1") as %Heq_v.
    iPureIntro. exists d'. split; [|done].
    apply elem_of_list_lookup. by exists j. }
  (* now purely: decoded subset → flat subset. *)
  iPureIntro. subst flat0 flat1.
  intros e He.
  apply elem_of_list_omap in He as (d & Hf & Hd_in).
  specialize (Hdsub d Hd_in) as (d' & Hd'_in & Hfst & Hsnd).
  apply elem_of_list_omap. exists d'. split; [|done].
  by destruct d, d'; simpl in *; subst.
Qed.

(* assembling a subset of entries gives inner submaps.
TODO: this relies on the collision-free property of VRF labels,
or a stronger characterization of assemble. *)
Local Lemma assemble_incl flat0 flat1 uid :
  (∀ e, e ∈ flat0 → e ∈ flat1) →
  (assemble flat0) !!! uid ⊆ (assemble flat1) !!! uid.
Proof. Admitted.

Local Lemma assemble_size_le flat0 flat1 uid :
  (∀ e, e ∈ flat0 → e ∈ flat1) →
  size ((assemble flat0) !!! uid) ≤ size ((assemble flat1) !!! uid).
Proof. Admitted.

Local Lemma assemble_dom flat0 flat1 uid :
  (∀ e, e ∈ flat0 → e ∈ flat1) →
  is_Some ((assemble flat0) !! uid) →
  is_Some ((assemble flat1) !! uid).
Proof. Admitted.

(* used by auditor. *)
Lemma is_plain_keys_over_sub vrf_pk hidden0 hidden1 plain0 plain1 :
  hidden0 ⊆ hidden1 →
  is_plain_keys vrf_pk hidden0 plain0 -∗
  is_plain_keys vrf_pk hidden1 plain1 -∗
  ⌜keys_sub plain0 plain1⌝.
Proof.
  iIntros (Hhsub) "#H0 #H1".
  iDestruct "H0" as (flat0 interm0) "(#Hflat0 & %Hinterm0 & %Hplain0)".
  iDestruct "H1" as (flat1 interm1) "(#Hflat1 & %Hinterm1 & %Hplain1)".
  iDestruct (is_flat_keys_sub with "Hflat0 Hflat1") as %Hfsub; [done|].
  iPureIntro. subst plain0 plain1 interm0 interm1.
  rewrite /keys_sub /map_included /map_relation.
  intros uid.
  rewrite !lookup_fmap.
  destruct ((assemble flat0) !! uid) as [m_uid0|] eqn:Hlook0; simpl; [|done].
  (* uid is in assemble flat0, so it must be in assemble flat1. *)
  destruct (assemble_dom flat0 flat1 uid Hfsub) as [m_uid1 Hlook1].
  { by eexists. }
  rewrite Hlook1. simpl.
  apply get_contig_prefix.
  - pose proof (assemble_incl flat0 flat1 uid Hfsub) as Hincl.
    rewrite lookup_total_alt Hlook0 lookup_total_alt Hlook1 /= in Hincl.
    done.
  - pose proof (assemble_size_le flat0 flat1 uid Hfsub) as Hsize.
    rewrite !lookup_total_alt Hlook0 Hlook1 /= in Hsize.
    done.
Qed.

(* hidden is fully made up of contiguous versions.
i.e., hidden and the computed plain are bijective. *)
Definition is_contig (vrf_pk : list w8) (hidden : gmap (list w8) (list w8)) : iProp Σ.
Admitted.

(* used in server update. *)
Lemma is_plain_keys_add vrf_pk hidden plain uid kt_pk label val rand :
  let pks := plain !!! uid in
  is_plain_keys vrf_pk hidden plain -∗
  is_contig vrf_pk hidden -∗
  is_MapLabel vrf_pk uid (length pks) label -∗
  is_MapVal kt_pk rand val -∗
  let hidden' := <[label:=val]>hidden in
  let plain' := <[uid:=pks ++ [kt_pk]]>plain in
  is_plain_keys vrf_pk hidden' plain' ∗ is_contig vrf_pk hidden'.
Proof. Admitted.

End proof.
End ktcore.
