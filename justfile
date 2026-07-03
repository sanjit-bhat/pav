ci: test fmt vet tidy rpc

test:
    go test -skip "Bench" ./...

fmt:
    gofmt -w -s . && git diff --exit-code

vet:
    go vet ./...

tidy:
    go mod tidy && git diff --exit-code go.mod go.sum

rpc:
    go run ./serde --in ktcore/serde.go && git diff --exit-code
    go run ./serde --in merkle/serde.go && git diff --exit-code
    go run ./serde --in auditor/serde.go && git diff --exit-code
