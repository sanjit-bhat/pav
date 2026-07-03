From New.proof Require Import proof_prelude.

Section proof.
Context {PROP : bi}.

Lemma big_sepL2_drop {A B} `{!BiAffine PROP} (n : nat)
    (Φ : nat → A → B → PROP) (l1 : list A) (l2 : list B) :
  ([∗ list] k ↦ y1;y2 ∈ l1;l2, Φ k y1 y2) ⊢
  ([∗ list] k ↦ y1;y2 ∈ drop n l1;drop n l2, Φ (n + k)%nat y1 y2).
Proof.
  iIntros "H".
  rewrite -{1}(take_drop n l1) -{1}(take_drop n l2).
  iDestruct (big_sepL2_length with "H") as %?.
  autorewrite with len in *.
  iDestruct (big_sepL2_app_same_length with "H") as "[_ H]"; [len|].
  destruct (decide (n ≥ length l1)).
  - by rewrite !drop_ge; [|lia..].
  - by replace (length (take n l1)) with n; [|len].
Qed.

(* this helps proving [BlameSpec] when we need to open invs
after learning that a party is good. *)
Lemma fupd_not_prop `{!BiFUpd PROP} P `{Decision P} : (⌜P⌝ ={⊤}=∗ False : PROP) ⊢ |={⊤}=> ¬ ⌜P⌝.
Proof.
  iIntros "H".
  destruct (decide P); [|done].
  by iMod ("H" with "[//]").
Qed.

End proof.

Section map.
Context {PROP : bi} `{!BiAffine PROP} `{Countable K} {A B : Type}.

Lemma fractional_big_sepM2 (m1 : gmap K A) (m2 : gmap K B)
    (Φ : K → A → B → Qp → PROP) :
  (∀ k x y, fractional.Fractional (λ q, Φ k x y q)) →
  fractional.Fractional (λ q, [∗ map] k ↦ x;y ∈ m1;m2, Φ k x y q)%I.
Proof.
  intros HΦ q1 q2. rewrite -big_sepM2_sep.
  apply big_sepM2_proper => ?????. apply HΦ.
Qed.

End map.
