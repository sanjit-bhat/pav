---
name: build
description: Build a Rocq proof file with make
argument-hint: [filepath]
allowed-tools: Bash(make *.vok)
context: fork
---

Build a Rocq proof file:
- Run `make $ARGUMENTS.vok`.
If the argument already ends in `.vok`, don't add it again.
- If rocq doesn't return an error, return "build succeeded".
- If rocq returns an error, give a concise summmary of it.
The file, line number, and core of the error message.
E.g., for unresolved implicit argument failures,
rocq prints many lines for the "environment"; do not include those.
