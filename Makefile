.PHONY: build check

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o wgadm .

check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
