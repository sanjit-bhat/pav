Search for Rocq lemmas relevant to a query within a specific file or directory.

Arguments: $ARGUMENTS

Instructions:
1. Parse the arguments. The format is: `<path> <query>` where `<path>` is a file or directory and `<query>` describes what kind of lemmas the user is looking for.
2. Search ONLY within the specified path for lemma/theorem/definition/instance statements. These are declared with keywords like `Lemma`, `Theorem`, `Definition`, `Instance`, `Global Instance`, `Fixpoint`, `Corollary`, `Fact`, `Remark`, `Proposition`, `Property`.
3. Filter results to only those relevant to the user's query.
4. Return the full lemma statements (from the keyword through the final `.` that ends the type signature, before any `Proof` or `Admitted`). Include the file path and line number for each result.
5. Do NOT return proof bodies — only the statement/signature.
6. If the path is a single `.v` file, search just that file. If it's a directory, search all `.v` files recursively within it.
