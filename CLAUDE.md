# Formal verification of the Pav system

- this project formally verifies the pav Key Transparency system,
written in golang.
- it uses the perennial framework, built on iris and stdpp,
which is built on the rocq theorem prover.
- pav, perennial, iris, and stdpp have been added as claude working dirs.

## source organization

- "new" perennial proofs have three main directories:
    - `code/`: Goosed (compiled) golang code.
    - `generatedproof/`: you will never need to read these;
    they're automatically applied.
    - `proof/`: the proof-level interface for a pkg,
    written with Hoare Triples and iris resources.
- inside `proof/`, there's a file for every go pkg.
for larger pkgs, the proof is broken into multiple files in a `{name}_proof` dir.

## rules

- if you aren't confident about something, it's perfectly fine to say that.
there isn't much perennial / iris / rocq code out there to learn from.
- for read-only ops, heavily prefer using your built-in tools
(e.g., Read, Grep) to custom bash commands.
the bash commands have a bad permission model,
whereas the read-only commands are always allowed.

## files to read

- the relevant pav go code for the component you're working on.
- @proof/auditor_proof/auditor.v and @proof/auditor_proof/rpc.v
are a good reference for predicate structure.

## files to skip

- `*_test.go`
- `rpc.go` (RPC stubs)
- `serde/` (serde compiler)
- `*.out.go`, `serde.v` (generated serde code)
