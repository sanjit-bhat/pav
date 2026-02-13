---
paths:
  - "**/*.v"
---

# Rocq proof style

- Write concise proofs in the style of stdpp.
- Don't write long tactic chains (3+ tactics after `;`). They're hard to follow.
- If the same proof pattern appears in multiple branches, extract a helper lemma
  rather than factoring with `;` chains or `all:`. Duplication signals a missing abstraction.
- Prefer helpers whose conclusions are directly usable (`exact`, `done`)
  over ones that require post-hoc rewriting in hypotheses.
