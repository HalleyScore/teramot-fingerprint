.PHONY: build test lint fmt tidy check

build:
	go build ./...

test:
	go test -race ./...

# gofmt is the gate CI enforces. Written as a test on captured output rather than the
# `| (! read)` pipeline: that idiom needs bash and prints "read: arg count" under dash.
lint:
	@out="$$(gofmt -l . 2>&1)"; \
	if [ -n "$$out" ]; then \
		echo "gofmt found unformatted files (run 'make fmt'):" >&2; \
		echo "$$out" >&2; \
		exit 1; \
	fi

fmt:
	gofmt -w .

tidy:
	go mod tidy

check: lint
	go vet ./...
	go test -race ./...
