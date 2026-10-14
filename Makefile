.PHONY: test vet fmt lint check

test:                       ## everything, in-process, no network, no Docker
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

lint:
	staticcheck ./...

check: fmt vet test
