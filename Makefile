.PHONY: test test-db vet fmt lint check demo conformance

test:                       ## everything, in-process, no network, no Docker
	go test -race ./...
	cd conformance && go test -race ./...

test-db:                    ## the stores on PostgreSQL and MySQL as well (EASYSSF_POSTGRES_URL, EASYSSF_MYSQL_URL)
	EASYSSF_DATABASE_TESTS=true go test -race ./receiver/sqlstore

vet:
	go vet ./...

fmt:
	gofmt -w .

lint:                       ## golangci-lint (includes staticcheck) and govulncheck, both modules
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run ./...
	cd conformance && go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	cd conformance && go run golang.org/x/vuln/cmd/govulncheck@latest ./...

demo:                       ## the resource server against the in-process test transmitter
	go run ./examples/resource-server -demo

conformance:                ## the four plans of the OpenID conformance suite in Docker, minutes per plan
	cd conformance && EASYSSF_CONFORMANCE_TESTS=true go test -count=1 -run Plan -timeout 60m -v .

check: fmt vet test
