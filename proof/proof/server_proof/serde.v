From New.generatedproof.github_com.sanjit_bhat.pav Require Import server.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.github_com.sanjit_bhat.pav Require Import
  ktcore safemarshal.
From New.proof.github_com.tchajed Require Import marshal.

From New.proof.github_com.sanjit_bhat.pav.server_proof Require Import base.

Module server.

Module StartChain.
Record t :=
  mk' {
    PrevEpochLen: w64;
    PrevLink: list w8;
    ChainProof: list w8;
    LinkSig: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc obj.(PrevEpochLen) ++
  safemarshal.Slice1D.pure_enc obj.(PrevLink) ++
  safemarshal.Slice1D.pure_enc obj.(ChainProof) ++
  safemarshal.Slice1D.pure_enc obj.(LinkSig).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(PrevLink) ∧
  safemarshal.Slice1D.valid obj.(ChainProof) ∧
  safemarshal.Slice1D.valid obj.(LinkSig).

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
  apply app_inj_1 in Heq as [Hpe Heq]; [|len].
  apply (inj u64_le) in Hpe.
  apply app_inj_1 in Heq as [Hp1 Heq]; [|len].
  apply (inj u64_le) in Hp1.
  assert (length obj0.(PrevLink) = length obj1.(PrevLink)) by word.
  apply app_inj_1 in Heq as [Hpl Heq]; [|done].
  apply app_inj_1 in Heq as [Hp2 Heq]; [|len].
  apply (inj u64_le) in Hp2.
  assert (length obj0.(ChainProof) = length obj1.(ChainProof)) by word.
  apply app_inj_1 in Heq as [Hcp Heq]; [|done].
  apply app_inj_1 in Heq as [Hp3 Heq]; [|len].
  apply (inj u64_le) in Hp3.
  assert (length obj0.(LinkSig) = length obj1.(LinkSig)) by word.
  apply app_inj_1 in Heq as [Hls Htail]; [|done].
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_PrevLink sl_ChainProof sl_LinkSig,
  "Hstruct" ∷ ptr ↦{d} (server.StartChain.mk obj.(PrevEpochLen) sl_PrevLink sl_ChainProof sl_LinkSig) ∗

  "Hsl_PrevLink" ∷ sl_PrevLink ↦*{d} obj.(PrevLink) ∗
  "Hsl_ChainProof" ∷ sl_ChainProof ↦*{d} obj.(ChainProof) ∗
  "Hsl_LinkSig" ∷ sl_LinkSig ↦*{d} obj.(LinkSig).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! server.StartChainEncode #sl_b #ptr_obj
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
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! server.StartChainDecode #sl_b
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
End StartChain.

Module StartVrf.
Record t :=
  mk' {
    VrfPk: list w8;
    VrfSig: list w8;
  }.

Definition pure_enc obj :=
  safemarshal.Slice1D.pure_enc obj.(VrfPk) ++
  safemarshal.Slice1D.pure_enc obj.(VrfSig).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(VrfPk) ∧
  safemarshal.Slice1D.valid obj.(VrfSig).

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
  apply app_inj_1 in Heq as [Hp1 Heq]; [|len].
  apply (inj u64_le) in Hp1.
  assert (length obj0.(VrfPk) = length obj1.(VrfPk)) by word.
  apply app_inj_1 in Heq as [Hvk Heq]; [|done].
  apply app_inj_1 in Heq as [Hp2 Heq]; [|len].
  apply (inj u64_le) in Hp2.
  assert (length obj0.(VrfSig) = length obj1.(VrfSig)) by word.
  apply app_inj_1 in Heq as [Hvs Htail]; [|done].
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_VrfPk sl_VrfSig,
  "Hstruct" ∷ ptr ↦{d} (server.StartVrf.mk sl_VrfPk sl_VrfSig) ∗

  "Hsl_VrfPk" ∷ sl_VrfPk ↦*{d} obj.(VrfPk) ∗
  "Hsl_VrfSig" ∷ sl_VrfSig ↦*{d} obj.(VrfSig).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! server.StartVrfEncode #sl_b #ptr_obj
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
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! server.StartVrfDecode #sl_b
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
End StartVrf.

Module StartReply.
Record t :=
  mk' {
    Chain: StartChain.t;
    Vrf: StartVrf.t;
  }.

Definition pure_enc obj :=
  StartChain.pure_enc obj.(Chain) ++
  StartVrf.pure_enc obj.(Vrf).

Definition valid obj :=
  StartChain.valid obj.(Chain) ∧
  StartVrf.valid obj.(Vrf).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof. Admitted.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ ptr_Chain ptr_Vrf,
  "Hstruct" ∷ ptr ↦{d} (server.StartReply.mk ptr_Chain ptr_Vrf) ∗

  "Hown_Chain" ∷ StartChain.own ptr_Chain obj.(Chain) d ∗
  "Hown_Vrf" ∷ StartVrf.own ptr_Vrf obj.(Vrf) d.

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! server.StartReplyEncode #sl_b #ptr_obj
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
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! server.StartReplyDecode #sl_b
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
End StartReply.

Module PutArg.
Record t :=
  mk' {
    Uid: w64;
    Pk: list w8;
    Ver: w64;
  }.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc obj.(Uid) ++
  safemarshal.Slice1D.pure_enc obj.(Pk) ++
  safemarshal.w64.pure_enc obj.(Ver).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(Pk).

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
  intros (-> & Hv0) (Heq & Hv1).
  rewrite -!app_assoc in Heq.
  apply app_inj_1 in Heq as [Huid Heq]; [|len].
  apply (inj u64_le) in Huid.
  apply app_inj_1 in Heq as [Hp Heq]; [|len].
  apply (inj u64_le) in Hp.
  assert (length obj0.(Pk) = length obj1.(Pk)) by word.
  apply app_inj_1 in Heq as [Hpk Heq]; [|done].
  apply app_inj_1 in Heq as [Hver Htail]; [|len].
  apply (inj u64_le) in Hver.
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_Pk,
  "Hstruct" ∷ ptr ↦{d} (server.PutArg.mk obj.(Uid) sl_Pk obj.(Ver)) ∗

  "Hsl_Pk" ∷ sl_Pk ↦*{d} obj.(Pk).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! server.PutArgEncode #sl_b #ptr_obj
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
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! server.PutArgDecode #sl_b
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
End PutArg.

Module HistoryArg.
Record t :=
  mk' {
    Uid: w64;
    PrevEpoch: w64;
    PrevVerLen: w64;
  }.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc obj.(Uid) ++
  safemarshal.w64.pure_enc obj.(PrevEpoch) ++
  safemarshal.w64.pure_enc obj.(PrevVerLen).

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
  apply app_inj_1 in Heq as [Hpe Heq]; [|len].
  apply (inj u64_le) in Hpe.
  apply app_inj_1 in Heq as [Hpv Htail]; [|len].
  apply (inj u64_le) in Hpv.
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  "Hstruct" ∷ ptr ↦{d} (server.HistoryArg.mk obj.(Uid) obj.(PrevEpoch) obj.(PrevVerLen)).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! server.HistoryArgEncode #sl_b #ptr_obj
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
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! server.HistoryArgDecode #sl_b
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
End HistoryArg.

Module HistoryReply.
Record t :=
  mk' {
    ChainProof: list w8;
    LinkSig: list w8;
    Hist: list ktcore.Memb.t;
    Bound: ktcore.NonMemb.t;
    Err: bool;
  }.

Definition pure_enc obj :=
  safemarshal.Slice1D.pure_enc obj.(ChainProof) ++
  safemarshal.Slice1D.pure_enc obj.(LinkSig) ++
  ktcore.MembSlice1D.pure_enc obj.(Hist) ++
  ktcore.NonMemb.pure_enc obj.(Bound) ++
  safemarshal.bool.pure_enc obj.(Err).

Definition valid obj :=
  safemarshal.Slice1D.valid obj.(ChainProof) ∧
  safemarshal.Slice1D.valid obj.(LinkSig) ∧
  ktcore.MembSlice1D.valid obj.(Hist) ∧
  ktcore.NonMemb.valid obj.(Bound).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof. Admitted.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ sl_ChainProof sl_LinkSig ptr_Hist ptr_Bound,
  "Hstruct" ∷ ptr ↦{d} (server.HistoryReply.mk sl_ChainProof sl_LinkSig ptr_Hist ptr_Bound obj.(Err)) ∗

  "Hsl_ChainProof" ∷ sl_ChainProof ↦*{d} obj.(ChainProof) ∗
  "Hsl_LinkSig" ∷ sl_LinkSig ↦*{d} obj.(LinkSig) ∗
  "Hown_Hist" ∷ ktcore.MembSlice1D.own ptr_Hist obj.(Hist) d ∗
  "Hown_Bound" ∷ ktcore.NonMemb.own ptr_Bound obj.(Bound) d.

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! server.HistoryReplyEncode #sl_b #ptr_obj
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
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! server.HistoryReplyDecode #sl_b
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
End HistoryReply.

Module AuditArg.
Record t :=
  mk' {
    PrevEpoch: w64;
  }.

Definition pure_enc obj :=
  safemarshal.w64.pure_enc obj.(PrevEpoch).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof.
  rewrite /wish /pure_enc /safemarshal.w64.pure_enc.
  intros -> Heq.
  apply app_inj_1 in Heq as [Hpe Htail]; [|len].
  apply (inj u64_le) in Hpe.
  destruct obj0, obj1. by simplify_eq/=.
Qed.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  "Hstruct" ∷ ptr ↦{d} (server.AuditArg.mk obj.(PrevEpoch)).

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! server.AuditArgEncode #sl_b #ptr_obj
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
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! server.AuditArgDecode #sl_b
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
End AuditArg.

Module AuditReply.
Record t :=
  mk' {
    P: list ktcore.AuditProof.t;
    Err: bool;
  }.

Definition pure_enc obj :=
  ktcore.AuditProofSlice1D.pure_enc obj.(P) ++
  safemarshal.bool.pure_enc obj.(Err).

Definition valid obj :=
  ktcore.AuditProofSlice1D.valid obj.(P).

Definition wish b obj tail :=
  b = pure_enc obj ++ tail ∧
  valid obj.

Lemma wish_det tail0 tail1 obj0 obj1 {b} :
  wish b obj0 tail0 →
  wish b obj1 tail1 →
  obj0 = obj1 ∧ tail0 = tail1.
Proof. Admitted.

Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : server.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Definition own ptr obj d : iProp Σ :=
  ∃ ptr_P,
  "Hstruct" ∷ ptr ↦{d} (server.AuditReply.mk ptr_P obj.(Err)) ∗

  "Hown_P" ∷ ktcore.AuditProofSlice1D.own ptr_P obj.(P) d.

Lemma wp_enc obj sl_b b ptr_obj d :
  {{{
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦* b ∗
    "Hcap_b" ∷ own_slice_cap w8 sl_b 1 ∗
    "Hown_obj" ∷ own ptr_obj obj d
  }}}
  @! server.AuditReplyEncode #sl_b #ptr_obj
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
    is_pkg_init server ∗
    "Hsl_b" ∷ sl_b ↦*{d} b
  }}}
  @! server.AuditReplyDecode #sl_b
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
End AuditReply.

End server.
