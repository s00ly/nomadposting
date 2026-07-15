.PHONY: build test vet format-check license vuln sbom verify

build:
	go build -trimpath -o bin/ivpn-controller ./cmd/ivpn
	go build -trimpath -o bin/ivpn-netbroker ./cmd/netbroker

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

format-check:
	@test -z "$$(gofmt -l ./cmd ./internal)"

license:
	bash ./scripts/check-licenses.sh

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

sbom:
	mkdir -p dist
	go list -m -json all > dist/go-modules.sbom.json

verify: format-check test vet license vuln sbom
