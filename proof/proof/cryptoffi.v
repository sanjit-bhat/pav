From New.generatedproof.github_com.sanjit_bhat.pav Require Import cryptoffi.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.crypto Require Import ed25519.
From New.proof.github_com.sanjit_bhat.pav.cryptoffi Require Import ffi.
From Coq.Logic Require Import ClassicalEpsilon.

(* note: [crypto_ffi] (the trusted, proven low-level hash FFI spec) is already
in scope transitively via [prelude] -> [crypto_prelude], so we reference its
names qualified ([crypto_ffi.total_hash_fn], [crypto_ffi.wp_Hash], etc.) rather
than [Import]ing it here, which would re-activate its module-level settings and
perturb downstream tactic behaviour. *)

Module cryptoffi.

Definition hash_len := 32.
Lemma hash_len_unfold : hash_len = 32.
Proof. done. Qed.
#[global] Hint Rewrite hash_len_unfold : word.
#[global] Opaque hash_len.

Section hash_defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

(* [total_hash_fn] is the idealized, real-world hash function provided by the
trusted crypto FFI ([crypto_ffi]). It is a function on byte lists; the relevant
facts about it ([total_hash_fn] is injective on its inputs and produces
length-[hash_len] outputs) are carried as part of [is_pkg_init cryptoffi] (see
[is_hash_props] below), since the trusted [crypto_ffi] model does not expose
them as pure facts. *)
Local Notation H := (crypto_ffi.total_hash_fn (cryptoGS := crypto_ffi.goose_cryptoGS)).

(* [hash_good data] holds when [data] is "well-hashed": its hash has the right
length and [data] is the unique pre-image of its hash. On this set
[total_hash_fn] is a length-[hash_len] injection, which is exactly what's needed
to turn it into a partial bijection. *)
Definition hash_good (data : list w8) : Prop :=
  Z.of_nat (length (H data)) = hash_len ∧
  (∀ data', H data' = H data → data' = data).

(* [hash_good] is decidable using classical logic (already a dependency of the
development), which lets us define [hash_fn]/[hash_inv_fn] as plain functions. *)
Local Instance hash_good_dec data : Decision (hash_good data) :=
  excluded_middle_informative _.

Definition hash_fn (data : list w8) : option $ list w8 :=
  if decide (hash_good data) then Some (H data) else None.

(* [hash_inv_fn] is the partial inverse: pick (classically) some [data] with
[hash_fn data = Some hash]; by injectivity it is unique. *)
Definition hash_inv_fn (hash : list w8) : option $ list w8 :=
  match excluded_middle_informative (∃ data, hash_fn data = Some hash) with
  | left pf => Some (proj1_sig (constructive_indefinite_description _ pf))
  | right _ => None
  end.

(* [hash_fn] and [hash_inv_fn] are partial bijections.
in particular, we make the forward fn ([hash_fn]) partial
(even tho it's total in the real-world)
so that it exhibits an inverse. *)
Lemma hash_bij_l data hash :
  hash_fn data = Some hash →
  hash_inv_fn hash = Some data.
Proof.
  intros Hfn. rewrite /hash_inv_fn.
  destruct excluded_middle_informative as [pf|n].
  2: { exfalso. apply n. by eexists. }
  destruct constructive_indefinite_description as [data' Hfn']. simpl.
  f_equal.
  (* both [data] and [data'] hash to [hash], and both are well-hashed, so they
  are equal by injectivity. *)
  move: Hfn Hfn'. rewrite /hash_fn.
  destruct (decide (hash_good data)) as [Hg|]; [|done].
  destruct (decide (hash_good data')) as [Hg'|]; [|done].
  intros [= <-] [= Heq].
  destruct Hg as [_ Hinj]. by apply Hinj.
Qed.

Lemma hash_bij_r data hash :
  hash_inv_fn hash = Some data →
  hash_fn data = Some hash.
Proof.
  rewrite /hash_inv_fn.
  destruct excluded_middle_informative as [pf|]; [|done].
  destruct constructive_indefinite_description as [data' Hfn']. simpl.
  intros [= <-]. done.
Qed.

Lemma is_hash_len data hash :
  hash_fn data = Some hash →
  Z.of_nat $ length hash = hash_len.
Proof.
  rewrite /hash_fn. destruct (decide (hash_good data)) as [[Hlen _]|]; [|done].
  intros [= <-]. done.
Qed.

Lemma is_hash_len' data hash :
  hash_inv_fn hash = Some data →
  Z.of_nat $ length hash = hash_len.
Proof.
  intros Hhash.
  apply hash_bij_r in Hhash.
  by apply is_hash_len in Hhash.
Qed.

Definition own_Hasher (ptr : loc) (b : list w8) : iProp Σ :=
  ∃ sl_b,
  "Hstruct" ∷ ptr ↦ (cryptoffi.Hasher.mk sl_b) ∗
  "Hsl_b" ∷ sl_b ↦* b ∗
  "Hsl_b_cap" ∷ own_slice_cap w8 sl_b (DfracOwn 1).

(* [is_hash_props] is the persistent resource carried by [is_pkg_init cryptoffi].
It packages (1) the trusted crypto-FFI prophecy invariant [is_hash_proph_inv]
(needed to run [wp_Hash]), together with the [HashContext] it's about, and
(2) the trusted idealization that [total_hash_fn] is a length-[hash_len]
injection (i.e. every input is [hash_good]). These are the facts the trusted
[crypto_ffi] model does not expose purely; they are established by the trusted
[wp_initialize']. *)
Definition is_hash_props : iProp Σ :=
  ∃ hash_ctx : crypto_ffi.HashContext,
  "#Hproph_inv" ∷ crypto_ffi.is_hash_proph_inv ∗
  "%Hgood" ∷ ⌜∀ data, hash_good data⌝.

#[global] Instance is_hash_props_pers : Persistent is_hash_props.
Proof. apply _. Qed.

End hash_defs.

Section init.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : cryptoffi.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

#[global] Instance : IsPkgInit (iProp Σ) cryptoffi := define_is_pkg_init is_hash_props.
#[global] Instance : GetIsPkgInitWf (iProp Σ) cryptoffi := build_get_is_pkg_init_wf.

Lemma wp_initialize' get_is_pkg_init :
  get_is_pkg_init_prop cryptoffi get_is_pkg_init →
  {{{ own_initializing get_is_pkg_init }}}
    cryptoffi.initialize' #()
  {{{ RET #(); own_initializing get_is_pkg_init ∗ is_pkg_init cryptoffi }}}.
Proof. Admitted.
End init.

Section hash_wps.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : cryptoffi.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_NewHasher :
  {{{ is_pkg_init cryptoffi }}}
  @! cryptoffi.NewHasher #()
  {{{
    ptr_hr, RET #ptr_hr;
    "Hown_hr" ∷ own_Hasher ptr_hr []
  }}}.
Proof.
  wp_start.
  wp_apply wp_alloc as "* Hstruct".
  iApply "HΦ". rewrite /own_Hasher.
  iFrame "Hstruct".
  iDestruct (own_slice_nil (DfracOwn 1)) as "$".
  by iDestruct own_slice_cap_nil as "$".
Qed.

Lemma wp_Hasher_Write hr data sl_b d0 b :
  {{{
    is_pkg_init cryptoffi ∗
    "Hown_hr" ∷ own_Hasher hr data ∗
    "Hsl_b" ∷ sl_b ↦*{d0} b
  }}}
  hr @! (go.PointerType cryptoffi.Hasher) @! "Write" #sl_b
  {{{
    RET #();
    "Hown_hr" ∷ own_Hasher hr (data ++ b) ∗
    "Hsl_b" ∷ sl_b ↦*{d0} b
  }}}.
Proof.
  wp_start. iNamed "Hpre". iNamedSuffix "Hown_hr" "_hr".
  wp_auto.
  wp_apply (wp_slice_append with "[$Hsl_b_hr $Hsl_b_cap_hr $Hsl_b]")
    as "* (Hsl_b_hr & Hsl_b_cap_hr & Hsl_b)".
  iApply "HΦ". rewrite /own_Hasher. iFrame.
Qed.

Lemma wp_Hasher_Sum sl_b_in hr data b_in :
  {{{
    is_pkg_init cryptoffi ∗
    "Hown_hr" ∷ own_Hasher hr data ∗
    "Hsl_b_in" ∷ sl_b_in ↦* b_in ∗
    "Hsl_b_in_cap" ∷ own_slice_cap w8 sl_b_in (DfracOwn 1)
  }}}
  hr @! (go.PointerType cryptoffi.Hasher) @! "Sum" #sl_b_in
  {{{
    sl_b_out hash, RET #sl_b_out;
    "Hown_hr" ∷ own_Hasher hr data ∗
    "Hsl_b_out" ∷ sl_b_out ↦* (b_in ++ hash) ∗
    "%His_hash" ∷ ⌜hash_fn data = Some hash⌝
  }}}.
Proof.
  wp_start. iNamed "Hpre". iNamedSuffix "Hown_hr" "_hr".
  iDestruct (is_pkg_init_access with "[$]") as "Hprops".
  rewrite /is_hash_props. iNamed "Hprops".
  wp_auto.
  (* the buffer slice -> string. *)
  wp_apply (wp_bytes_to_string with "[$Hsl_b_hr]") as "Hsl_b_hr".
  (* run the trusted hash FFI: [ExternalOp Hash], using the proph invariant. *)
  wp_func_call. wp_call.
  wp_apply (crypto_ffi.wp_Hash data with "Hproph_inv") as "%hash %Hcf".
  (* hash string -> slice, then append onto the input slice. *)
  wp_apply (wp_string_to_bytes) as "%sl_hash [Hsl_hash Hsl_hash_cap]".
  wp_apply (wp_slice_append with "[$Hsl_b_in $Hsl_b_in_cap $Hsl_hash]")
    as "* (Hsl_b_out & Hsl_b_out_cap & Hsl_hash)".
  iApply ("HΦ" $! _ hash).
  iSplitL "Hstruct_hr Hsl_b_hr Hsl_b_cap_hr".
  { rewrite /own_Hasher. iFrame. }
  iFrame "Hsl_b_out".
  iPureIntro.
  (* the trusted FFI gives [crypto_ffi.hash_fn data = Some hash], i.e. [data]
  was actually hashed and [hash = total_hash_fn data]. With [hash_good data]
  (from [is_pkg_init]) this gives the closed [hash_fn data = Some hash]. *)
  rewrite /crypto_ffi.hash_fn in Hcf.
  destruct (crypto_ffi.has_hash _ _) eqn:Hhh; [|done].
  injection Hcf as <-.
  rewrite /hash_fn. rewrite decide_True; [done|]. apply Hgood.
Qed.

End hash_wps.

(* Seal [hash_fn]/[hash_inv_fn] so downstream proofs treat them as opaque,
matching how they were used when these were [Admitted]. Their only interface is
[hash_bij_l], [hash_bij_r], [is_hash_len], [is_hash_len']. *)
#[global] Opaque hash_fn hash_inv_fn.

Section vrf_defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

(** Verifiable Random Functions (VRFs).
IETF spec: https://www.rfc-editor.org/rfc/rfc9381.html.
we model correctness (is_vrf_proof), "Full Uniqueness" (is_vrf_out_det),
and "Full Collision Resistance" (is_vrf_out_inj). *)

(* own_vrf_sk provides ownership of an sk from the VrfGenerateKey function. *)
Definition own_vrf_sk (ptr_sk : loc) (pk : list w8) : iProp Σ.
Proof. Admitted.

(* think of this as DfracDiscarded. *)
#[global] Instance own_vrf_sk_pers ptr_sk pk :
  Persistent (own_vrf_sk ptr_sk pk).
Proof. Admitted.

(* is_vrf_pk says that pk satisfies certain mathematical crypto checks.
this is in contrast to is_sig_pk, which additionally says that
the corresponding sk never left the ffi. *)
Definition is_vrf_pk (pk : list w8) : iProp Σ.
Proof. Admitted.

#[global] Instance is_vrf_pk_pers pk : Persistent (is_vrf_pk pk).
Proof. Admitted.

(* own_vrf_pk just wraps is_vrf_pk with ownership of the heap resources
corresponding to the pk bytes. *)
Definition own_vrf_pk (ptr_pk : loc) (pk : list w8) : iProp Σ.
Proof. Admitted.

(* think of this as DfracDiscarded. *)
#[global] Instance own_vrf_pk_pers ptr_pk pk :
  Persistent (own_vrf_pk ptr_pk pk).
Proof. Admitted.

Lemma own_vrf_sk_to_pk ptr_sk pk : own_vrf_sk ptr_sk pk -∗ is_vrf_pk pk.
Proof. Admitted.

Lemma own_vrf_pk_valid ptr_pk pk : own_vrf_pk ptr_pk pk -∗ is_vrf_pk pk.
Proof. Admitted.

(* is_vrf_proof helps model correctness.
i.e., a caller gets this from Prove / Verify,
and uses it to prove that Verify should not return an error. *)
(* NOTE: could make [is_vrf_proof] a pure func.
after all, it models a real-world determ procedure. *)
Definition is_vrf_proof (pk data proof : list w8) : iProp Σ.
Proof. Admitted.

#[global] Instance is_vrf_proof_pers pk data proof :
  Persistent (is_vrf_proof pk data proof).
Proof. Admitted.

(* [vrf_fn] does not talk about the VRF proof.
this is convenient because the spec does not rule out multiple proofs
between the same pk, data, and output. *)
(* [vrf_fn] models "Full Uniqueness". this always holds for ECVRF. *)
Definition vrf_fn (pk data : list w8) : option $ list w8.
Proof. Admitted.

(* [vrf_inv_fn] models "Full Collision Resistance".
From the spec, "Full" (as opposed to "Trusted") holds for ECVRF as long
as the `validate_key` parameter to `ECVRF_verify` is true.
key validation is done when running `VrfPublicKeyDecode`
on an adversarially-provided pk. it is represented by [is_vrf_pk].
in this model, the partial function internalizes valid keys. *)
Definition vrf_inv_fn (pk out : list w8) : option $ list w8.
Proof. Admitted.

(* [vrf_fn] and [vrf_inv_fn] are partial bijections. *)
Lemma vrf_bij_l pk data out :
  vrf_fn pk data = Some out →
  vrf_inv_fn pk out = Some data.
Proof. Admitted.

Lemma vrf_bij_r pk data out :
  vrf_inv_fn pk out = Some data →
  vrf_fn pk data = Some out.
Proof. Admitted.

Lemma is_vrf_len pk data out :
  vrf_fn pk data = Some out →
  Z.of_nat $ length out = hash_len.
Proof. Admitted.

Lemma is_vrf_len' pk data out :
  vrf_inv_fn pk out = Some data →
  Z.of_nat $ length out = hash_len.
Proof.
  intros Hvrf.
  apply vrf_bij_r in Hvrf.
  by apply is_vrf_len in Hvrf.
Qed.

End vrf_defs.

Section vrf_wps.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : cryptoffi.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_VrfGenerateKey :
  {{{ is_pkg_init cryptoffi }}}
  @! cryptoffi.VrfGenerateKey #()
  {{{
    ptr_vrfSk (vrfPk : list w8), RET #ptr_vrfSk;
    "#Hown_vrf_sk" ∷ own_vrf_sk ptr_vrfSk vrfPk
  }}}.
Proof. Admitted.

Lemma wp_VrfPrivateKey_Prove ptr_sk pk sl_data (data : list w8) d0 :
  {{{
    is_pkg_init cryptoffi ∗
    "#Hown_vrf_sk" ∷ own_vrf_sk ptr_sk pk ∗
    "Hsl_data" ∷ sl_data ↦*{d0} data
  }}}
  ptr_sk @! (go.PointerType cryptoffi.VrfPrivateKey) @! "Prove" #sl_data
  {{{
    sl_out sl_proof (out proof : list w8), RET (#sl_out, #sl_proof);
    "Hsl_data" ∷ sl_data ↦*{d0} data ∗
    "Hsl_out" ∷ sl_out ↦* out ∗
    "Hsl_proof" ∷ sl_proof ↦* proof ∗
    "#His_vrf_proof" ∷ is_vrf_proof pk data proof ∗
    "%His_vrf_out" ∷ ⌜vrf_fn pk data = Some out⌝
  }}}.
Proof. Admitted.

Lemma wp_VrfPrivateKey_Evaluate ptr_sk pk sl_data (data : list w8) d0 :
  {{{
    is_pkg_init cryptoffi ∗
    "#Hown_vrf_sk" ∷ own_vrf_sk ptr_sk pk ∗
    "Hsl_data" ∷ sl_data ↦*{d0} data
  }}}
  ptr_sk @! (go.PointerType cryptoffi.VrfPrivateKey) @! "Evaluate" #sl_data
  {{{
    sl_out (out : list w8), RET #sl_out;
    "Hsl_data" ∷ sl_data ↦*{d0} data ∗
    "Hsl_out" ∷ sl_out ↦* out ∗
    "%His_vrf_out" ∷ ⌜vrf_fn pk data = Some out⌝
  }}}.
Proof. Admitted.

Lemma wp_VrfPublicKey_Verify ptr_pk pk sl_data sl_proof (data proof : list w8) d0 d1 :
  {{{
    is_pkg_init cryptoffi ∗
    "#Hown_vrf_pk" ∷ own_vrf_pk ptr_pk pk ∗
    "Hsl_data" ∷ sl_data ↦*{d0} data ∗
    "Hsl_proof" ∷ sl_proof ↦*{d1} proof
  }}}
  ptr_pk @! (go.PointerType cryptoffi.VrfPublicKey) @! "Verify" #sl_data #sl_proof
  {{{
    sl_out (out : list w8) (err : bool), RET (#sl_out, #err);
    "Hsl_data" ∷ sl_data ↦*{d0} data ∗
    "Hsl_proof" ∷ sl_proof ↦*{d1} proof ∗
    "Hsl_out" ∷ sl_out ↦* out ∗
    "Hgenie" ∷
      match err with
      | true => ¬ is_vrf_proof pk data proof
      | false =>
        "#His_proof" ∷ is_vrf_proof pk data proof ∗
        "%His_out" ∷ ⌜vrf_fn pk data = Some out⌝
      end
  }}}.
Proof. Admitted.

Lemma wp_VrfPrivateKey_PublicKey ptr_sk pk :
  {{{
    is_pkg_init cryptoffi ∗
    "#Hown_vrf_sk" ∷ own_vrf_sk ptr_sk pk
  }}}
  ptr_sk @! (go.PointerType cryptoffi.VrfPrivateKey) @! "PublicKey" #()
  {{{
    sl_enc, RET #sl_enc;
    "Hsl_enc" ∷ sl_enc ↦* pk
  }}}.
Proof. Admitted.

Lemma wp_VrfPublicKeyEncode ptr_pk pk :
  {{{
    is_pkg_init cryptoffi ∗
    "#Hown_vrf_pk" ∷ own_vrf_pk ptr_pk pk
  }}}
  @! cryptoffi.VrfPublicKeyEncode #ptr_pk
  {{{
    sl_enc, RET #sl_enc;
    "Hsl_enc" ∷ sl_enc ↦* pk ∗
    "#His_vrf_pk" ∷ is_vrf_pk pk
  }}}.
Proof. Admitted.

Lemma wp_VrfPublicKeyDecode sl_enc pk d0 :
  {{{
    is_pkg_init cryptoffi ∗
    "Hsl_enc" ∷ sl_enc ↦*{d0} pk
  }}}
  @! cryptoffi.VrfPublicKeyDecode #sl_enc
  {{{
    ptr_pk err, RET (#ptr_pk, #err);
    "Hsl_enc" ∷ sl_enc ↦*{d0} pk ∗
    "Hgenie" ∷
      match err with
      | true => ¬ is_vrf_pk pk
      | false =>
        "#Hown_vrf_pk" ∷ own_vrf_pk ptr_pk pk
      end
  }}}.
Proof. Admitted.

End vrf_wps.

Section sig_defs.
Context `{!heapGS Σ}.
Context {sem : go.Semantics}.
Collection W := sem.
#[local] Set Default Proof Using "W".

(** Signatures. *)

(* own_sig_sk says that an sk is in-distribution.
furthermore, it came from calling the Generate fn,
and the underlying sk is enclosed in the ffi,
forcing all users to establish the sigpred.
pk is a mathematical list so it can leave the ffi and be sent
between parties. *)
Definition own_sig_sk (ptr_sk : loc) (pk : list w8) (P : list w8 → iProp Σ) : iProp Σ.
Proof. Admitted.

(* think of this as DfracDiscarded. *)
#[global] Instance own_sig_sk_pers ptr_sk pk P :
  Persistent (own_sig_sk ptr_sk pk P).
Proof. Admitted.

(* is_sig_pk says that pk is in-distribution.
also, that it came from the Generate fn,
tied by P to a corresponding sk in the ffi. *)
Definition is_sig_pk (pk : list w8) (P : list w8 → iProp Σ) : iProp Σ.
Proof. Admitted.

#[global] Instance is_sig_pk_pers pk P : Persistent (is_sig_pk pk P).
Proof. Admitted.

Lemma own_sig_sk_to_pk ptr_sk pk P : own_sig_sk ptr_sk pk P -∗ is_sig_pk pk P.
Proof. Admitted.

(* is_sig says that Verify will ret True on these inputs.
relative to the crypto model, it says the inputs are in the set of
memoized=True Verify inputs. *)
Definition is_sig (pk msg sig : list w8) : iProp Σ.
Proof. Admitted.

#[global] Instance is_sig_pers pk msg sig : Persistent (is_sig pk msg sig).
Proof. Admitted.

(* the proof for is_sig_to_pred splits into two cases:
1) the sig came from sign. P clearly holds.
2) an adversary forged the sig.
EUF-CMA guarantees that this only happens if the genuine key holder
signed the same msg in the past. P holds from the orig signing op. *)
Lemma is_sig_to_pred pk P msg sig :
  is_sig_pk pk P -∗ is_sig pk msg sig -∗ P msg.
Proof. Admitted.

End sig_defs.

Section sig_wps.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : cryptoffi.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_SigGenerateKey P :
  (∀ l, Persistent (P l)) →
  {{{ is_pkg_init cryptoffi }}}
  @! cryptoffi.SigGenerateKey #()
  {{{
    (sl_sigPk : cryptoffi.SigPublicKey.t) sigPk ptr_sigSk,
    RET (#sl_sigPk, #ptr_sigSk);
    "Hsl_sigPk" ∷ sl_sigPk ↦* sigPk ∗
    "#His_sig_pk" ∷ is_sig_pk sigPk P ∗
    "#Hown_sig_sk" ∷ own_sig_sk ptr_sigSk sigPk P
 }}}.
Proof. Admitted.

Lemma wp_SigPrivateKey_Sign ptr_sk pk P sl_msg msg d0 :
  {{{
    is_pkg_init cryptoffi ∗
    "#Hown_sig_sk" ∷ own_sig_sk ptr_sk pk P ∗
    "Hsl_msg" ∷ sl_msg ↦*{d0} msg ∗
    "HP" ∷ P msg
  }}}
  ptr_sk @! (go.PointerType cryptoffi.SigPrivateKey) @! "Sign" #sl_msg
  {{{
    sl_sig (sig : list w8), RET #sl_sig;
    "Hsl_msg" ∷ sl_msg ↦*{d0} msg ∗
    "Hsl_sig" ∷ sl_sig ↦* sig ∗
    "#His_sig" ∷ is_sig pk msg sig
  }}}.
Proof. Admitted.

Lemma wp_SigPublicKey_Verify ptr_pk (sl_pk : cryptoffi.SigPublicKey.t) pk
    sl_msg msg sl_sig sig d0 d1 d2 :
  {{{
    is_pkg_init cryptoffi ∗
    "Hptr_pk" ∷ ptr_pk ↦ sl_pk ∗
    "Hsl_sig_pk" ∷ sl_pk ↦*{d0} pk ∗
    "Hsl_msg" ∷ sl_msg ↦*{d1} msg ∗
    "Hsl_sig" ∷ sl_sig ↦*{d2} sig
  }}}
  ptr_pk @! (go.PointerType cryptoffi.SigPublicKey) @! "Verify" #sl_msg #sl_sig
  {{{
    (err : bool), RET #err;
    "Hptr_pk" ∷ ptr_pk ↦ sl_pk ∗
    "Hsl_sig_pk" ∷ sl_pk ↦*{d0} pk ∗
    "Hsl_msg" ∷ sl_msg ↦*{d1} msg ∗
    "Hsl_sig" ∷ sl_sig ↦*{d2} sig ∗
    "Hgenie" ∷
      match err with
      | true => ¬ is_sig pk msg sig
      | false =>
        "#His_sig" ∷ is_sig pk msg sig
      end
  }}}.
Proof. Admitted.

End sig_wps.

Section rand_wps.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : cryptoffi.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

Lemma wp_RandBytes (n : w64) :
  {{{ is_pkg_init cryptoffi }}}
  @! cryptoffi.RandBytes #n
  {{{
    sl_b (b : list w8), RET #sl_b;
    "Hsl_b" ∷ sl_b ↦* b ∗
    "%Hlen_b" ∷ ⌜length b = uint.nat n⌝
  }}}.
Proof. Admitted.

End rand_wps.
End cryptoffi.
