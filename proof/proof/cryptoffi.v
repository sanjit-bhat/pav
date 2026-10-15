From New.generatedproof.github_com.sanjit_bhat.pav Require Import cryptoffi.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

From New.proof.crypto Require Import ed25519.
From New.proof.github_com.sanjit_bhat.pav.cryptoffi Require Import ffi.

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
Local Notation H := crypto_ffi.total_hash_fn.

Fixpoint find_preimage (datas : list (list w8)) (hash : list w8) : option (list w8) :=
  match datas with
  | [] => None
  | d :: datas' => if decide (H d = hash) then Some d else find_preimage datas' hash
  end.

(* [hash_inv_fn] picks the first pre-image hashed during the execution.
[hash_fn] is partial (even tho it's total in the real-world),
so that it exhibits an inverse. *)
Definition hash_inv_fn (hash : list w8) : option (list w8) :=
  find_preimage crypto_ffi.all_hash_data hash.

Definition hash_fn (data : list w8) : option (list w8) :=
  if decide (hash_inv_fn (H data) = Some data) then Some (H data) else None.

Lemma find_preimage_hash datas hash data :
  find_preimage datas hash = Some data →
  H data = hash.
Proof.
  induction datas; simpl; [done|].
  case_decide; [by intros [= <-]|done].
Qed.

Lemma find_preimage_first pre data suf :
  (∀ d, d ∈ pre → H d = H data → d = data) →
  find_preimage (pre ++ data :: suf) (H data) = Some data.
Proof.
  induction pre as [|d pre IH]; intros Hfirst; simpl.
  - by rewrite decide_True.
  - case_decide.
    + f_equal. apply Hfirst; [set_solver|done].
    + apply IH. intros. apply Hfirst; [set_solver|done].
Qed.

Lemma hash_fn_hashed data pre suf :
  crypto_ffi.all_hash_data = pre ++ data :: suf →
  (∀ d, d ∈ pre → H d = H data → d = data) →
  hash_fn data = Some (H data).
Proof.
  intros Hall Hfirst.
  rewrite /hash_fn /hash_inv_fn Hall find_preimage_first // decide_True //.
Qed.

Lemma hash_bij_l data hash :
  hash_fn data = Some hash →
  hash_inv_fn hash = Some data.
Proof. rewrite /hash_fn. case_decide; [|done]. by intros [= <-]. Qed.

Lemma hash_bij_r data hash :
  hash_inv_fn hash = Some data →
  hash_fn data = Some hash.
Proof.
  intros Hinv. pose proof Hinv as <-%find_preimage_hash.
  rewrite /hash_fn decide_True //.
Qed.

Lemma is_hash_len data hash :
  hash_fn data = Some hash →
  Z.of_nat $ length hash = hash_len.
Proof.
  rewrite /hash_fn. case_decide; [|done]. intros [= <-].
  rewrite crypto_ffi.total_hash_fn_len hash_len_unfold //.
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

End hash_defs.

(* downstream proofs only use [hash_bij_l], [hash_bij_r],
[is_hash_len], and [is_hash_len']. *)
#[global] Opaque hash_fn hash_inv_fn.

Section init.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : cryptoffi.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

#[global] Instance : IsPkgInit (iProp Σ) cryptoffi := define_is_pkg_init True%I.
#[global] Instance : GetIsPkgInitWf (iProp Σ) cryptoffi := build_get_is_pkg_init_wf.

Lemma wp_initialize' get_is_pkg_init :
  get_is_pkg_init_prop cryptoffi get_is_pkg_init →
  {{{ own_initializing get_is_pkg_init ∗ crypto_ffi.is_hash_proph_inv }}}
    cryptoffi.initialize' #()
  {{{ RET #(); own_initializing get_is_pkg_init ∗ is_pkg_init cryptoffi }}}.
Proof.
  intros Hinit. wp_start as "[Hown #Hinv]".
  wp_apply (wp_package_init with "[$Hown] HΦ").
  { destruct Hinit as (-> & ?); done. }
  iIntros "Hown". wp_auto.
  wp_apply (ffi.wp_initialize' with "[$Hown $Hinv]") as "(Hown & #?)".
  { naive_solver. }
  wp_apply (ed25519.wp_initialize' with "[$Hown]") as "(Hown & #?)".
  { naive_solver. }
  iFrame. iEval (rewrite is_pkg_init_unfold /=). iFrame "#". done.
Qed.
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
  wp_auto.
  wp_apply (wp_bytes_to_string with "[$Hsl_b_hr]") as "Hsl_b_hr".
  wp_apply (ffi.wp_TrustedHash with "[]") as "%Hhashed".
  wp_apply (wp_string_to_bytes) as "%sl_hash [Hsl_hash Hsl_hash_cap]".
  wp_apply (wp_slice_append with "[$Hsl_b_in $Hsl_b_in_cap $Hsl_hash]")
    as "* (Hsl_b_out & Hsl_b_out_cap & Hsl_hash)".
  iApply "HΦ".
  iSplitL "Hstruct_hr Hsl_b_hr Hsl_b_cap_hr".
  { rewrite /own_Hasher. iFrame. }
  iFrame "Hsl_b_out". iPureIntro.
  destruct Hhashed as (? & ? & ? & ?). by eapply hash_fn_hashed.
Qed.

End hash_wps.

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
    (* TODO: remove iNames. too low-level. *)
    "Hsl_b" ∷ sl_b ↦* b ∗
    "%Hlen_b" ∷ ⌜length b = uint.nat n⌝
  }}}.
Proof. Admitted.

End rand_wps.
End cryptoffi.
