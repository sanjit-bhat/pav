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

## files to read

- the relevant pav go code for the component you're working on.
- @proof/auditor_proof/auditor.v and @proof/auditor_proof/rpc.v
are a good reference for predicate structure.

## files to skip

- `*_test.go`
- `rpc.go` (RPC stubs)
- `serde/` (serde compiler)
- `*.out.go`, `serde.v` (generated serde code)

## rules

- if you aren't confident about something, it's perfectly fine to say that.
there isn't much perennial / iris / rocq code out there to learn from.
- NEVER chain shell commands with && or ; or |.
  run each command as its own separate Bash call.
  this ensures each call matches an allowed permission pattern (e.g. `git *`).
- NEVER use Bash for file reading/searching. use Read, Grep, Glob instead.
these are already allowed and don't require approval.
- commit checkpoints. write concise, descriptive commits.
- write commit messages to a fresh random file in `/tmp`,
  then run `git commit -F {file_path}`.
  this avoids multi-line shell quoting issues with the `Bash(git *)` permission pattern.
- test often to make sure you're on the right track.
