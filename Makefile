# goreleaser removes the `v` prefix when building and this does too
VERSION = 0.6.1

ifdef CIRCLECI
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		LDFLAGS=-linkmode external -extldflags -static
	endif
endif

.PHONY: help
help:  ## Print the help documentation
	@grep -E '^[/a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

bin/setup-new-aws-user: ## Build setup-new-aws-user
	go build -ldflags "$(LDFLAGS) -X main.version=${VERSION}" -o bin/setup-new-aws-user ./cmd/

.PHONY: test
test:
	go test -v ./cmd/...

.PHONY: test_coverage
test_coverage:
	go test -v -coverprofile=coverage.out -covermode=count ./cmd/...
	go tool cover -html=coverage.out

.PHONY: clean
clean:
	rm -f .*.stamp
	rm -rf ./bin
	rm -rf ./dist

.PHONY: goreleaser_check
goreleaser_check: ## Goreleaser check configuration
	goreleaser check

.PHONY: goreleaser_build
goreleaser_build: ## Goreleaser build configuration
	goreleaser build --snapshot --clean

.PHONY: goreleaser_test
goreleaser_test: ## Goreleaser test configuration
	goreleaser --snapshot --skip-publish --clean

default: help
