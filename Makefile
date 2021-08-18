BINDIR        ?= $(CURDIR)/bin
BINNAME       ?= centrify

GOOS          = $(shell go env GOOS)
GOARCH        = $(shell go env GOARCH)
GOBIN         = $(shell go env GOBIN)
ifeq ($(GOBIN),)
GOBIN         = $(shell go env GOPATH)/bin
endif

GORELEASER    = $(GOBIN)/goreleaser
GOTESTSUM     = $(GOBIN)/gotestsum

GIT_TAG       = $(shell git describe --match 'v[0-9]*' --dirty --always --tags)
GIT_COMMIT    = $(shell git rev-parse HEAD)

LDFLAGS       := -w -s
LDFLAGS       += -X github.com/centrify/vault-plugin-auth-hashicorp.pluginVersion=$(GIT_TAG)
LDFLAGS       += -X github.com/centrify/vault-plugin-auth-hashicorp.pluginGitCommit=$(GIT_COMMIT)

TESTCONF      ?=
TESTCONF_FILE ?= ./testconfig.json

GOFMT_FILES   ?= $$(find . -name '*.go' | grep -v vendor)

default: dev

bin: fmtcheck $(GORELEASER) prep
	@echo "==> Cross-compiling..."
	@$(GORELEASER) release --snapshot --skip-publish --rm-dist

	@echo "==> Copying the binary for $(GOOS)/$(GOARCH) to $(BINDIR)/$(BINNAME)..."
	@cp './pkg/vault-plugin-auth-hashicorp_$(GOOS)_$(GOARCH)/centrify' '$(BINDIR)/$(BINNAME)'

dev: fmtcheck prep
	@echo "==> Compiling..."
	@CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o './pkg/$(GOOS)_$(GOARCH)/centrify' \
		./cmd/vault-plugin-auth-hashicorp

	@echo "==> Copying the binary for $(GOOS)/$(GOARCH) to $(BINDIR)/$(BINNAME)..."
	@cp './pkg/$(GOOS)_$(GOARCH)/centrify' '$(BINDIR)/$(BINNAME)'

prep: clean
	@mkdir -p $(BINDIR)

clean:
	@echo "==> Removing old directories..."
	@rm -rf ./pkg

# ---------------------------------------------------------------
# testing

test: fmtcheck $(GOTESTSUM)
ifdef TESTCONF
	@sudo $(GOTESTSUM) --format testname ./... -v -args -config-string="$${TESTCONF}"
else
	@[ -f $(TESTCONF_FILE) ] || (echo "==> Missing configuration file" && exit 1)
	sudo $(GOTESTSUM) --format testname ./... -v -args -config='$(TESTCONF_FILE)'
endif

# ---------------------------------------------------------------
# code style

fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

fmt:
	gofmt -w $(GOFMT_FILES)

# ---------------------------------------------------------------
# dependencies

$(GORELEASER):
	@echo "Installing goreleaser"
	go install github.com/goreleaser/goreleaser@latest

$(GOTESTSUM):
	@echo "Installing gotestsum"
	go install gotest.tools/gotestsum@latest


.PHONY: default bin dev prep clean test fmtcheck fmt
