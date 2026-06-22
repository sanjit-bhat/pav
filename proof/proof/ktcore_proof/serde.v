From New.generatedproof.github_com.sanjit_bhat.pav Require Import ktcore.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import safemarshal.
From New.proof.github_com.tchajed Require Import marshal.

From New.proof.github_com.sanjit_bhat.pav.ktcore_proof Require Import base.

(** core serde spec requirements:
- deterministic encoding of object.
- optional correctness: encoded object decodes to same object.
- security: specs usable even for weak caller.
- "composable". e.g., predicates on struct re-use field predicates.

impl:
- [pure_enc] gives deterministic encoding.
- [wish] transports correctness from encoder to decoder.
it's just [pure_enc] plus a [valid] predicate.
[valid] says that variable-length objects (e.g., lists)
have lengths that fit within the s64 slice length.
- [pure_enc] and [valid] of bigger objects is the
[pure_enc] and [valid] of their components. *)

(* generic injectivity for list encodings of the form
   [mjoin (enc <$> l)], reducing to element-level injectivity. *)
Lemma mjoin_enc_inj {A} (enc : A → list w8) (valid : A → Prop) l0 l1 t0 t1 :
  (∀ a0 a1 s0 s1, valid a0 → valid a1 →
     enc a0 ++ s0 = enc a1 ++ s1 → a0 = a1 ∧ s0 = s1) →
  length l0 = length l1 →
  Forall valid l0 → Forall valid l1 →
  mjoin (enc <$> l0) ++ t0 = mjoin (enc <$> l1) ++ t1 →
  l0 = l1 ∧ t0 = t1.
Proof.
  intros Hinj. revert l1 t0 t1.
  induction l0 as [|a0 l0 IH]; intros [|a1 l1] t0 t1 Hlen Hv0 Hv1 Heq;
    simpl in *; [by simplify_eq/=|done|done|].
  injection Hlen as Hlen.
  apply Forall_cons in Hv0 as [Hv0a Hv0].
  apply Forall_cons in Hv1 as [Hv1a Hv1].
  rewrite -!app_assoc in Heq.
  apply Hinj in Heq as [-> Heq]; [|done..].
  apply IH in Heq as [-> ->]; [|done..].
  done.
Qed.

Module ktcore.

Notation VrfSigTag := 0 (only parsing).
Notation LinkSigTag := 1 (only parsing).

Module VrfSig.
Record t :=
  mk' {
    SigTag: w8;
    VrfPk: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.w8.pure_enc obj.(SigTag) ++
  safemarshal.Slice1D.pure_enc obj.(VrfPk).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(VrfPk).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid
    /safemarshal.w8.pure_enc /safemarshal.Slice1D.pure_enc
    /safemarshal.w64.pure_enc /safemarshal.Slice1D.valid.
  intros (-> & Hv0) (Heq & Hv1).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Htag Heq]; [|done].
  apply app_inj_1 in Heq as [Hlen Heq]; [|len].
  apply (inj u64_le) in Hlen.
  assert (length obj0.(VrfPk) = length obj1.(VrfPk)) by word.
  apply app_inj_1 in Heq as [Hpk Htail]; [|done].
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_VrfPk,
  "Hstr_VrfSig" ∷ ptr ↦{d} (ktcore.VrfSig.mk obj.(SigTag) sl_VrfPk) ∗

  "Hsl_VrfPk" ∷ sl_VrfPk ↦*{d} obj.(VrfPk).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.VrfSigEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d ∗
    ⌜wish b' obj b⌝
  }}}.
Proof. Admitted.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.VrfSigDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj tail, ⌜wish b obj tail⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj d ∗
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof. Admitted.

End proof.
End VrfSig.

Module LinkSig.
Record t :=
  mk' {
    SigTag: w8;
    Epoch: w64;
    Link: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.w8.pure_enc obj.(SigTag) ++
  safemarshal.w64.pure_enc obj.(Epoch) ++
  safemarshal.Slice1D.pure_enc obj.(Link).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(Link).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid
    /safemarshal.w8.pure_enc /safemarshal.w64.pure_enc
    /safemarshal.Slice1D.pure_enc /safemarshal.Slice1D.valid.
  intros (-> & Hv0) (Heq & Hv1).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Htag Heq]; [|done].
  apply app_inj_1 in Heq as [Hep Heq]; [|len].
  apply (inj u64_le) in Hep.
  apply app_inj_1 in Heq as [Hlen Heq]; [|len].
  apply (inj u64_le) in Hlen.
  assert (length obj0.(Link) = length obj1.(Link)) by word.
  apply app_inj_1 in Heq as [Hlink Htail]; [|done].
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_Link,
  "Hstr_LinkSig" ∷ ptr ↦{d} (ktcore.LinkSig.mk obj.(SigTag) obj.(Epoch) sl_Link) ∗

  "Hsl_Link" ∷ sl_Link ↦*{d} obj.(Link).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.LinkSigEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d ∗
    ⌜wish b' obj b⌝
  }}}.
Proof. Admitted.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.LinkSigDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj tail, ⌜wish b obj tail⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj d ∗
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof. Admitted.

End proof.
End LinkSig.

Module MapLabel.
Record t :=
  mk' {
    Uid: w64;
    Ver: w64;
  }.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc obj.(Uid) ++
  safemarshal.w64.pure_enc obj.(Ver).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /safemarshal.w64.pure_enc.
  intros -> Heq.
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Huid Heq]; [|len].
  apply (inj u64_le) in Huid.
  apply app_inj_1 in Heq as [Hver Htail]; [|len].
  apply (inj u64_le) in Hver.
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  "Hstruct" ∷ ptr ↦{d} (ktcore.MapLabel.mk obj.(Uid) obj.(Ver)).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.MapLabelEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d ∗
    ⌜wish b' obj b⌝
  }}}.
Proof. Admitted.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.MapLabelDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj tail, ⌜wish b obj tail⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj d ∗
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof. Admitted.

End proof.
End MapLabel.

Module CommitOpen.
Record t :=
  mk' {
    Val: list w8;
    Rand: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.Slice1D.pure_enc obj.(Val) ++
  safemarshal.Slice1D.pure_enc obj.(Rand).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(Val) ∧
  safemarshal.Slice1D.valid obj.(Rand).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid
    /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc
    /safemarshal.Slice1D.valid.
  intros (-> & Hv0a & Hv0b) (Heq & Hv1a & Hv1b).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Hl1 Heq]; [|len].
  apply (inj u64_le) in Hl1.
  assert (length obj0.(Val) = length obj1.(Val)) by word.
  apply app_inj_1 in Heq as [Hval Heq]; [|done].
  apply app_inj_1 in Heq as [Hl2 Heq]; [|len].
  apply (inj u64_le) in Hl2.
  assert (length obj0.(Rand) = length obj1.(Rand)) by word.
  apply app_inj_1 in Heq as [Hrand Htail]; [|done].
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_Val sl_Rand,
  "Hstr_CommitOpen" ∷ ptr ↦{d} (ktcore.CommitOpen.mk sl_Val sl_Rand) ∗

  "Hsl_Val" ∷ sl_Val ↦*{d} obj.(Val) ∗
  "Hsl_Rand" ∷ sl_Rand ↦*{d} obj.(Rand).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.CommitOpenEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d ∗
    ⌜wish b' obj b⌝
  }}}.
Proof. Admitted.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.CommitOpenDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj tail, ⌜wish b obj tail⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj d ∗
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof. Admitted.

End proof.
End CommitOpen.

Module Memb.
Record t :=
  mk' {
    LabelProof: list w8;
    PkOpen: CommitOpen.t;
    MerkleProof: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.Slice1D.pure_enc obj.(LabelProof) ++
  CommitOpen.pure_enc obj.(PkOpen) ++
  safemarshal.Slice1D.pure_enc obj.(MerkleProof).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(LabelProof) ∧
  CommitOpen.valid obj.(PkOpen) ∧
  safemarshal.Slice1D.valid obj.(MerkleProof).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid
    /CommitOpen.pure_enc /CommitOpen.valid
    /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc
    /safemarshal.Slice1D.valid.
  intros (-> & Hv0a & (Hv0b & Hv0c) & Hv0d) (Heq & Hv1a & (Hv1b & Hv1c) & Hv1d).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Hpre1 Heq]; [|len].
  apply (inj u64_le) in Hpre1.
  assert (length obj0.(LabelProof) = length obj1.(LabelProof)) by word.
  apply app_inj_1 in Heq as [Hlp Heq]; [|done].
  apply app_inj_1 in Heq as [Hpre2 Heq]; [|len].
  apply (inj u64_le) in Hpre2.
  assert (length obj0.(PkOpen).(CommitOpen.Val) = length obj1.(PkOpen).(CommitOpen.Val)) by word.
  apply app_inj_1 in Heq as [Hval Heq]; [|done].
  apply app_inj_1 in Heq as [Hpre3 Heq]; [|len].
  apply (inj u64_le) in Hpre3.
  assert (length obj0.(PkOpen).(CommitOpen.Rand) = length obj1.(PkOpen).(CommitOpen.Rand)) by word.
  apply app_inj_1 in Heq as [Hrand Heq]; [|done].
  apply app_inj_1 in Heq as [Hpre4 Heq]; [|len].
  apply (inj u64_le) in Hpre4.
  assert (length obj0.(MerkleProof) = length obj1.(MerkleProof)) by word.
  apply app_inj_1 in Heq as [Hmp Htail]; [|done].
  destruct obj0 as [LP0 [Val0 Rand0] MP0], obj1 as [LP1 [Val1 Rand1] MP1].
  by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_LabelProof ptr_PkOpen sl_MerkleProof,
  "Hstr_Memb" ∷ ptr ↦{d} (ktcore.Memb.mk sl_LabelProof ptr_PkOpen sl_MerkleProof) ∗

  "Hsl_LabelProof" ∷ sl_LabelProof ↦*{d} obj.(LabelProof) ∗
  "Hown_PkOpen" ∷ CommitOpen.own ptr_PkOpen obj.(PkOpen) d ∗
  "Hsl_MerkleProof" ∷ sl_MerkleProof ↦*{d} obj.(MerkleProof).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.MembEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d ∗
    ⌜wish b' obj b⌝
  }}}.
Proof. Admitted.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.MembDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj tail, ⌜wish b obj tail⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj d ∗
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof. Admitted.

End proof.
End Memb.

Module MembSlice1D.
Definition t := list Memb.t.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc (W64 $ length obj) ++ mjoin (Memb.pure_enc <$> obj).

Definition valid (obj : t) :=
  sint.Z (W64 (length obj)) = length obj ∧
  Forall (λ x, Memb.valid x) obj.

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid /safemarshal.w64.pure_enc.
  intros (-> & Hlen0 & Hvf0) (Heq & Hlen1 & Hvf1).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Hl Heq]; [|len].
  apply (inj u64_le) in Hl.
  assert (length obj0 = length obj1) by word.
  assert (Hinj : ∀ a0 a1 s0 s1, Memb.valid a0 → Memb.valid a1 →
    Memb.pure_enc a0 ++ s0 = Memb.pure_enc a1 ++ s1 → a0 = a1 ∧ s0 = s1).
  { intros a0 a1 s0 s1 Hva0 Hva1 Henc.
    apply (Memb.wish_det s0 s1 a0 a1 (b := Memb.pure_enc a0 ++ s0));
      rewrite /Memb.wish; by split. }
  apply (mjoin_enc_inj _ _ _ _ _ _ Hinj) in Heq as [-> ->]; done.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ ptr0,
  ptr ↦*{d} ptr0 ∗
  ([∗ list] ptr;obj ∈ ptr0;obj,
    Memb.own ptr obj d).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.MembSlice1DEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d ∗
    ⌜wish b' obj b⌝
  }}}.
Proof. Admitted.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.MembSlice1DDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj tail, ⌜wish b obj tail⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj d ∗
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof. Admitted.

End proof.
End MembSlice1D.

Module NonMemb.
Record t :=
  mk' {
    LabelProof: list w8;
    MerkleProof: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.Slice1D.pure_enc obj.(LabelProof) ++
  safemarshal.Slice1D.pure_enc obj.(MerkleProof).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(LabelProof) ∧
  safemarshal.Slice1D.valid obj.(MerkleProof).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid
    /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc
    /safemarshal.Slice1D.valid.
  intros (-> & Hv0a & Hv0b) (Heq & Hv1a & Hv1b).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Hl1 Heq]; [|len].
  apply (inj u64_le) in Hl1.
  assert (length obj0.(LabelProof) = length obj1.(LabelProof)) by word.
  apply app_inj_1 in Heq as [Hlp Heq]; [|done].
  apply app_inj_1 in Heq as [Hl2 Heq]; [|len].
  apply (inj u64_le) in Hl2.
  assert (length obj0.(MerkleProof) = length obj1.(MerkleProof)) by word.
  apply app_inj_1 in Heq as [Hmp Htail]; [|done].
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_LabelProof sl_MerkleProof,
  "Hstr_NonMemb" ∷ ptr ↦{d} (ktcore.NonMemb.mk sl_LabelProof sl_MerkleProof) ∗

  "Hsl_LabelProof" ∷ sl_LabelProof ↦*{d} obj.(LabelProof) ∗
  "Hsl_MerkleProof" ∷ sl_MerkleProof ↦*{d} obj.(MerkleProof).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.NonMembEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d ∗
    ⌜wish b' obj b⌝
  }}}.
Proof. Admitted.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.NonMembDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj tail, ⌜wish b obj tail⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj d ∗
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof. Admitted.

End proof.
End NonMemb.

Module UpdateProof.
Record t :=
  mk' {
    MapLabel: list w8;
    MapVal: list w8;
    NonMembProof: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.Slice1D.pure_enc obj.(MapLabel) ++
  safemarshal.Slice1D.pure_enc obj.(MapVal) ++
  safemarshal.Slice1D.pure_enc obj.(NonMembProof).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(MapLabel) ∧
  safemarshal.Slice1D.valid obj.(MapVal) ∧
  safemarshal.Slice1D.valid obj.(NonMembProof).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid
    /safemarshal.Slice1D.pure_enc /safemarshal.w64.pure_enc
    /safemarshal.Slice1D.valid.
  intros (-> & Hv0a & Hv0b & Hv0c) (Heq & Hv1a & Hv1b & Hv1c).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Hl1 Heq]; [|len].
  apply (inj u64_le) in Hl1.
  assert (length obj0.(MapLabel) = length obj1.(MapLabel)) by word.
  apply app_inj_1 in Heq as [Hml Heq]; [|done].
  apply app_inj_1 in Heq as [Hl2 Heq]; [|len].
  apply (inj u64_le) in Hl2.
  assert (length obj0.(MapVal) = length obj1.(MapVal)) by word.
  apply app_inj_1 in Heq as [Hmv Heq]; [|done].
  apply app_inj_1 in Heq as [Hl3 Heq]; [|len].
  apply (inj u64_le) in Hl3.
  assert (length obj0.(NonMembProof) = length obj1.(NonMembProof)) by word.
  apply app_inj_1 in Heq as [Hnmp Htail]; [|done].
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_MapLabel sl_MapVal sl_NonMembProof,
  "Hstr_UpdateProof" ∷ ptr ↦{d} (ktcore.UpdateProof.mk sl_MapLabel sl_MapVal sl_NonMembProof) ∗

  "Hsl_MapLabel" ∷ sl_MapLabel ↦*{d} obj.(MapLabel) ∗
  "Hsl_MapVal" ∷ sl_MapVal ↦*{d} obj.(MapVal) ∗
  "Hsl_NonMembProof" ∷ sl_NonMembProof ↦*{d} obj.(NonMembProof).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.UpdateProofEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d ∗
    ⌜wish b' obj b⌝
  }}}.
Proof. Admitted.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.UpdateProofDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj tail, ⌜wish b obj tail⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj d ∗
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof. Admitted.

End proof.
End UpdateProof.

Module UpdateProofSlice1D.
Definition t := list UpdateProof.t.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc (W64 $ length obj) ++ mjoin (UpdateProof.pure_enc <$> obj).

Definition valid (obj : t) :=
  sint.Z (W64 (length obj)) = length obj ∧
  Forall (λ x, UpdateProof.valid x) obj.

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid /safemarshal.w64.pure_enc.
  intros (-> & Hlen0 & Hvf0) (Heq & Hlen1 & Hvf1).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Hl Heq]; [|len].
  apply (inj u64_le) in Hl.
  assert (length obj0 = length obj1) by word.
  assert (Hinj : ∀ a0 a1 s0 s1, UpdateProof.valid a0 → UpdateProof.valid a1 →
    UpdateProof.pure_enc a0 ++ s0 = UpdateProof.pure_enc a1 ++ s1 → a0 = a1 ∧ s0 = s1).
  { intros a0 a1 s0 s1 Hva0 Hva1 Henc.
    apply (UpdateProof.wish_det s0 s1 a0 a1 (b := UpdateProof.pure_enc a0 ++ s0));
      rewrite /UpdateProof.wish; by split. }
  apply (mjoin_enc_inj _ _ _ _ _ _ Hinj) in Heq as [-> ->]; done.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ ptr0,
  ptr ↦*{d} ptr0 ∗
  ([∗ list] ptr;obj ∈ ptr0;obj,
    UpdateProof.own ptr obj d).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.UpdateProofSlice1DEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d ∗
    ⌜wish b' obj b⌝
  }}}.
Proof. Admitted.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.UpdateProofSlice1DDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj tail, ⌜wish b obj tail⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj d ∗
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof. Admitted.

End proof.
End UpdateProofSlice1D.

Module AuditProof.
Record t :=
  mk' {
    Updates: list UpdateProof.t;
    LinkSig: list w8;
  }.

Definition pure_enc obj :=
  UpdateProofSlice1D.pure_enc obj.(Updates) ++
  safemarshal.Slice1D.pure_enc obj.(LinkSig).

Definition valid obj :=
  UpdateProofSlice1D.valid obj.(Updates) ∧
  safemarshal.Slice1D.valid obj.(LinkSig).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
(* TODO: nested struct embedding a list-encoded field [Updates].
   composition via [UpdateProofSlice1D.wish_det] needs the [Updates ++ LinkSig]
   split exposed without [app_assoc] reassociating through the folded inner
   encoders ([rewrite -!app_assoc] sees through definitions). unsolved. *)
Proof. Admitted.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ ptr_Updates sl_LinkSig,
  "Hstr_AuditProof" ∷ ptr ↦{d} (ktcore.AuditProof.mk ptr_Updates sl_LinkSig) ∗

  "Hsl_Updates" ∷ UpdateProofSlice1D.own ptr_Updates obj.(Updates) d ∗
  "Hsl_LinkSig" ∷ sl_LinkSig ↦*{d} obj.(LinkSig).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.AuditProofEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d ∗
    ⌜wish b' obj b⌝
  }}}.
Proof. Admitted.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.AuditProofDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj tail, ⌜wish b obj tail⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj d ∗
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof. Admitted.

End proof.
End AuditProof.

Module AuditProofSlice1D.
Definition t := list AuditProof.t.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc (W64 $ length obj) ++ mjoin (AuditProof.pure_enc <$> obj).

Definition valid (obj : t) :=
  sint.Z (W64 (length obj)) = length obj ∧
  Forall (λ x, AuditProof.valid x) obj.

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /valid /safemarshal.w64.pure_enc.
  intros (-> & Hlen0 & Hvf0) (Heq & Hlen1 & Hvf1).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Hl Heq]; [|len].
  apply (inj u64_le) in Hl.
  assert (length obj0 = length obj1) by word.
  assert (Hinj : ∀ a0 a1 s0 s1, AuditProof.valid a0 → AuditProof.valid a1 →
    AuditProof.pure_enc a0 ++ s0 = AuditProof.pure_enc a1 ++ s1 → a0 = a1 ∧ s0 = s1).
  { intros a0 a1 s0 s1 Hva0 Hva1 Henc.
    apply (AuditProof.wish_det s0 s1 a0 a1 (b := AuditProof.pure_enc a0 ++ s0));
      rewrite /AuditProof.wish; by split. }
  apply (mjoin_enc_inj _ _ _ _ _ _ Hinj) in Heq as [-> ->]; done.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ktcore.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ ptr0,
  ptr ↦*{d} ptr0 ∗
  ([∗ list] ptr;obj ∈ ptr0;obj,
    ktcore.AuditProof.own ptr obj d).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! ktcore.AuditProofSlice1DEncode #sl_b #ptr_obj
  {{{
    sl_b', RET #sl_b';
    let b' := b ++ pure_enc obj in
    sl_b' ↦* b' ∗
    own_slice_cap w8 sl_b' 1 ∗
    own ptr_obj obj d ∗
    ⌜wish b' obj b⌝
  }}}.
Proof. Admitted.

Lemma wp_dec sl_b d b :
  {{{
    is_pkg_init ktcore ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! ktcore.AuditProofSlice1DDecode #sl_b
  {{{
    ptr_obj sl_tail err, RET (#ptr_obj, #sl_tail, #err);
    match err with
    | true => ¬ ∃ obj tail, ⌜wish b obj tail⌝
    | false =>
      ∃ obj tail,
      own ptr_obj obj d ∗
      sl_tail ↦*{d} tail ∗
      ⌜wish b obj tail⌝
    end
  }}}.
Proof. Admitted.

End proof.
End AuditProofSlice1D.

End ktcore.
