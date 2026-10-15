From New.generatedproof.github_com.sanjit_bhat.pav.cryptoffi Require Import ffi.
From New.proof.github_com.sanjit_bhat.pav Require Import prelude.

Module ffi.
Section proof.
Context `{!heapGS Σ}.
Context {sem : go.Semantics} {package_sem : ffi.Assumptions}.
Collection W := sem + package_sem.
#[local] Set Default Proof Using "W".

#[global] Instance : IsPkgInit (iProp Σ) ffi :=
  define_is_pkg_init crypto_ffi.is_hash_proph_inv.
#[global] Instance : GetIsPkgInitWf (iProp Σ) ffi := build_get_is_pkg_init_wf.

Lemma wp_initialize' get_is_pkg_init :
  get_is_pkg_init_prop ffi get_is_pkg_init →
  {{{ own_initializing get_is_pkg_init ∗ crypto_ffi.is_hash_proph_inv }}}
    ffi.initialize' #()
  {{{ RET #(); own_initializing get_is_pkg_init ∗ is_pkg_init ffi }}}.
Proof.
  intros Hinit. wp_start as "[Hown #Hinv]".
  wp_apply (wp_package_init with "[$Hown] HΦ").
  { destruct Hinit as (-> & ?); done. }
  iIntros "Hown". wp_auto.
  iFrame. iEval (rewrite is_pkg_init_unfold /=). iFrame "#". done.
Qed.

Lemma wp_TrustedHash (data : list w8) :
  {{{ is_pkg_init ffi }}}
    @! ffi.TrustedHash #data
  {{{
    RET #(crypto_ffi.total_hash_fn data);
    ⌜∃ pre suf, crypto_ffi.all_hash_data = pre ++ data :: suf ∧
      ∀ d, d ∈ pre → crypto_ffi.total_hash_fn d = crypto_ffi.total_hash_fn data →
      d = data⌝
  }}}.
Proof.
  wp_start as "_".
  iDestruct (is_pkg_init_access with "[$]") as "Hinv".
  wp_apply (crypto_ffi.wp_Hash with "Hinv").
  by iApply "HΦ".
Qed.

End proof.
End ffi.
