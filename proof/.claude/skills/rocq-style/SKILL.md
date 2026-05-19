---
name: rocq-style
description: Rocq proof style guidelines. Use this before writing or editing Rocq proofs to ensure consistent style.
---

# Rocq proof style

Follow these rules when writing or editing Rocq proofs:
- Write concise proofs in the style of iris / stdpp.
- Don't write long tactic chains (3+ tactics after `;`). They're hard to follow.
- If the same proof pattern appears in multiple branches, extract a helper lemma
    rather than factoring with `;` chains or `all:`.
    Duplication signals a missing abstraction.
- Prefer stdpp tactics like:
    `done`, `naive_solver`, `f_equal`, `trans`, `inv`,
    `destruct_and`, `destruct_or`,
    `case_match`, `case_guard`, `case_decide`,
    `opose`, `odestruct`, `ospecialize`,
    `simplify_eq/=`,  `simplify_option_eq`, `list_simplifier`,
    `simplify_map_eq/=`, `set_solver`.
