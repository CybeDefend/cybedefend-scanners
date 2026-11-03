GO ?= go

.PHONY: test vet fmt images integration

test:
	CGO_ENABLED=0 $(GO) test -count=1 ./...

vet:
	$(GO) vet ./...

# Fails when a file is not gofmt-formatted.
fmt:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "$$out"; echo "gofmt: the files above need formatting"; exit 1; fi

# Builds one image per adapter; the adapter tasks add them.
images:

integration: images
	CGO_ENABLED=0 $(GO) test -count=1 -tags integration ./test/integration/...
