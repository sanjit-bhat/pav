---
name: rocq-build
description: Instructions for building Rocq proofs
---

# Building Rocq proofs

## Setup
Before working on a .v file, build its dependencies:
make -j10 path/to/file.vos

## Workflow
1. `rocq_open` the file
2. `rocq_check_all` to see current state
3. Edit the file to fix errors or fill in proofs
4. `rocq_sync` after every edit (required!)
5. `rocq_check_all` again to see if errors are resolved
6. Repeat 3-5 until clean

## Tips
- Use `rocq_check` at a specific line to see proof goals mid-proof
- Use `rocq_step_forward` / `rocq_step_backward` for fine-grained stepping
- `rocq_check_all` returns both errors and remaining proof goals
- Always sync after editing — the checker reads from disk
