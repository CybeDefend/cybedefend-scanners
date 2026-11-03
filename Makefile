GO ?= go

.PHONY: test vet fmt images integration

test:
	CGO_ENABLED=0 $(GO) test -count=1 ./...

vet:
	$(GO) vet ./...

# Fails when a file is not gofmt-formatted.
fmt:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "$$out"; echo "gofmt: the files above need formatting"; exit 1; fi

# Builds images/<adapter>/Dockerfile as appsec-scanners-<adapter>:dev, for
# every adapter, from the repository root.
ADAPTER_IMAGES := $(patsubst images/%/Dockerfile,%,$(wildcard images/*/Dockerfile))
VERSION ?= dev

images:
	@set -e; for a in $(ADAPTER_IMAGES); do \
		echo "building appsec-scanners-$$a:dev"; \
		docker build -f images/$$a/Dockerfile --build-arg VERSION=$(VERSION) -t appsec-scanners-$$a:dev .; \
	done

integration: images
	CGO_ENABLED=0 $(GO) test -count=1 -tags integration ./test/integration/...
