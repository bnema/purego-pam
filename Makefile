export GOPROXY := off
export GOSUMDB := off

.PHONY: check test build race mocks mocks-check vet

check: vet test build mocks-check
	CGO_ENABLED=0 staticcheck ./...

test:
	CGO_ENABLED=0 go test -count=1 ./...

build:
	CGO_ENABLED=0 go build ./...
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ./...

# Go's race detector requires cgo; this is a separate diagnostic build.
race:
	CGO_ENABLED=1 go test -race -count=1 ./...

vet:
	CGO_ENABLED=0 go vet ./...

mocks:
	CGO_ENABLED=0 mockery --config .mockery.yml

mocks-check:
	CGO_ENABLED=0 mockery --config .mockery.yml && git diff --exit-code -- '*_mock_test.go'
