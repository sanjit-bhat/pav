Proto:
1. Add `settings.json` to automate all the CLI args.
Right now, it's
```bash
protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    rpc/photo_sharing.proto
```