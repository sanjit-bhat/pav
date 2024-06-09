## TODO

[ ] test: try parsing and type checking generated code to see if it makes sense.
[ ] make stuff functional. remove ctxt. other var refactoring.
[ ] return errs instead of log.Fatal. this'll work better with testing.
[ ] add fixed size []byte support.
[ ] add merkle.Id support. unalias that to []byte.
[x] generate same pkg name as src.
[ ] how does grpc differentiate fixed vs dynamic size byte sl?
[x] 1. add epochTy support. unalias to uint64.
[ ] add bool support.

---

## Planning

How hard would it be to get alias's to work?
File imports some pkg.
pkg.Id is actually an alias to uint64.
How to know that?
Currently we just parse and typecheck a single file.
I think we'd need to parse/typecheck the imports to make this work?
