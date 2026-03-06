PKG?=github.com/smallstep/step-kms-plugin
BINNAME?=step-kms-openbao-plugin
GOLANG_CROSS_VERSION?=v1.25

# Set V to 1 for verbose output from the Makefile
Q=$(if $V,,@)
PREFIX?=
SRC=$(shell find . -type f -name '*.go' -not -path "./vendor/*")
GOOS_OVERRIDE ?=
OUTPUT_ROOT=output/
RELEASE=./.releases

DOCKER_HOST ?= /var/run/docker.sock
DOCKER_SOCK := $(if $(filter unix://%,$(DOCKER_HOST)),$(patsubst unix://%,%,$(DOCKER_HOST)),$(DOCKER_HOST))

#########################################
# Default
#########################################

all: lint test build

ci: test build

.PHONY: all ci

#########################################
# Bootstrapping
#########################################

bootstrap:
	$Q curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin latest
	$Q go install golang.org/x/vuln/cmd/govulncheck@latest
	$Q go install gotest.tools/gotestsum@latest

.PHONY: bootstrap

#################################################
# Determine the type of `push` and `version`
#################################################

# GITHUB Actions
ifdef GITHUB_REF
VERSION ?= $(shell echo $(GITHUB_REF) | sed 's/^refs\/tags\///')
NOT_RC  := $(shell echo $(VERSION) | grep -v -e -rc)
else
VERSION ?= $(shell [ -d .git ] && git describe --tags --always --dirty="-dev")
endif

VERSION := $(shell echo $(VERSION) | sed 's/^v//')
DATE    := $(shell date -u '+%Y-%m-%d %H:%M UTC')

ifdef V
$(info    GITHUB_REF is $(GITHUB_REF))
$(info    VERSION is $(VERSION))
$(info    DATE is $(DATE))
endif

#########################################
# Build
#########################################

LDFLAGS := -ldflags='-s -w -X "$(PKG)/cmd.Version=$(VERSION)" -X "$(PKG)/cmd.ReleaseDate=$(DATE)"'

GOFIPSVERSION=v1.26.0
ifeq ($(shell go env GOVERSION | cut -d\. -f-2), go1.25)
GOFIPSVERSION=v1.0.0
endif

build:
	$Q go build -v -o $(PREFIX)bin/$(BINNAME) $(LDFLAGS) $(PKG)
	@echo "Build Complete!"

build-fips:
	$Q GOFIPS140=$(GOFIPSVERSION) go build -v -tags noyubikey -o $(PREFIX)bin/$(BINNAME) $(LDFLAGS) $(PKG)
	@echo "Build Complete!"

.PHONY: build build-fips

#########################################
# Go generate
#########################################

generate: build
	$Q go generate ./...
	$Q mkdir -p completions
	$Q bin/$(BINNAME) completion bash > completions/bash_completion
	$Q bin/$(BINNAME) completion fish > completions/fish_completion
	$Q bin/$(BINNAME) completion powershell > completions/powershell_completion
	$Q bin/$(BINNAME) completion zsh > completions/zsh_completion

.PHONY: generate

#########################################
# Test
#########################################

test:
	$Q go test -coverprofile=coverage.out ./...

# integration-test runs the OpenBao integration tests.
# Requires a running OpenBao instance with Transit secrets engine enabled.
# Environment variables:
#   OPENBAO_ADDR  - OpenBao server address (default: http://127.0.0.1:8200)
#   OPENBAO_TOKEN - Authentication token (default: dev-root-token)
#
# Quick start with Docker:
#   docker run -d --name openbao-test -p 8200:8200 \
#     -e BAO_DEV_ROOT_TOKEN_ID=dev-root-token \
#     -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
#     --cap-add=IPC_LOCK quay.io/openbao/openbao:latest
#
#   curl -s -X POST http://127.0.0.1:8200/v1/sys/mounts/transit \
#     -H "X-Vault-Token: dev-root-token" -d '{"type":"transit"}'
#
#   make integration-test
integration-test:
	$Q OPENBAO_ADDR=$${OPENBAO_ADDR:-http://127.0.0.1:8200} \
	   OPENBAO_TOKEN=$${OPENBAO_TOKEN:-dev-root-token} \
	   go test -tags integration -v -count=1 ./kms/openbao/ -run TestIntegration

.PHONY: test integration-test

#########################################
# Linting
#########################################

fmt:
	$Q goimports --local github.com/smallstep/step-kms-plugin --local go.step.sm/crypto -l -w $(SRC)

lint: golint govulncheck

golint: SHELL:=/bin/bash
golint:
	$Q LOG_LEVEL=error golangci-lint run --config <(curl -s https://raw.githubusercontent.com/smallstep/workflows/master/.golangci.yml) --timeout=30m

govulncheck:
	$Q govulncheck ./...

.PHONY: fmt lint golint govulncheck

#########################################
# Release
#########################################

release-dev:
	$Q @docker run -it --rm --privileged -e CGO_ENABLED=1 \
		-e GORELEASER_KEY=$(GORELEASER_KEY) \
		-e IS_PRERELEASE=true \
		--entrypoint /bin/bash \
		-v $(DOCKER_SOCK):/var/run/docker.sock:Z \
		-v `pwd`:/go/src/$(PKG):Z \
		-w /go/src/$(PKG) \
		ghcr.io/goreleaser/goreleaser-cross-pro:${GOLANG_CROSS_VERSION}

release-dry-run:
	$Q @docker run --rm --privileged -e CGO_ENABLED=1 \
		-e GORELEASER_KEY=$(GORELEASER_KEY) \
		-e GPG_PRIVATE_KEY_FILE=/dev/null \
		-e IS_PRERELEASE=true \
		--entrypoint /go/src/$(PKG)/docker/build/entrypoint.sh \
		-v $(DOCKER_SOCK):/var/run/docker.sock:Z \
		-v `pwd`:/go/src/$(PKG):Z \
		-w /go/src/$(PKG) \
		ghcr.io/goreleaser/goreleaser-cross-pro:${GOLANG_CROSS_VERSION} \
		release --clean --skip=validate --skip=sign --prepare

release:
	@if [ ! -f ".release-env" ]; then \
		echo "\033[91m.release-env is required for release\033[0m";\
		exit 1;\
	fi
	$Q @docker run --rm --privileged -e CGO_ENABLED=1 --env-file .release-env \
		--entrypoint /go/src/$(PKG)/docker/build/entrypoint.sh \
		-v ./$(GPG_PRIVATE_KEY_FILE):/$(GPG_PRIVATE_KEY_FILE) \
		-v $(DOCKER_SOCK):/var/run/docker.sock \
		-v `pwd`:/go/src/$(PKG) \
		-w /go/src/$(PKG) \
		ghcr.io/goreleaser/goreleaser-cross-pro:${GOLANG_CROSS_VERSION} \
		release --clean --prepare

.PHONY: release-dev release-dry-run release

#########################################
# Install
#########################################

INSTALL_PREFIX?=/usr/

install: $(PREFIX)bin/$(BINNAME)
	$Q install -D $(PREFIX)bin/$(BINNAME) $(DESTDIR)$(INSTALL_PREFIX)bin/$(BINNAME)

uninstall:
	$Q rm -f $(DESTDIR)$(INSTALL_PREFIX)/bin/$(BINNAME)

.PHONY: install uninstall

#########################################
# Clean
#########################################

clean:
ifneq ($(BINNAME),"")
	$Q rm -f bin/$(BINNAME)
endif

.PHONY: clean
