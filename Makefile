BINARY := net-scouter
DIST_DIR := dist
BPF_OBJECT := $(DIST_DIR)/flow.bpf.o
BPF_CLANG ?= clang
BPF_ARCH ?= x86
BPF_CPU ?= v1
GO ?= go
GOARCH ?= amd64
DOCKER ?= docker
ROCKY_IMAGE ?= rockylinux:8.10

.PHONY: build build-linux build-windows build-darwin build-all build-bpf \
	build-release verify-bpf verify-bpf-load verify-rocky-userspace \
	test test-go test-static test-ci check checksums clean

build:
	@mkdir -p $(DIST_DIR)
	$(GO) build -trimpath -o $(DIST_DIR)/$(BINARY) ./cmd/net-scouter

build-linux:
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) $(GO) build -trimpath \
		-o $(DIST_DIR)/$(BINARY)-linux-$(GOARCH) ./cmd/net-scouter

build-windows:
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath \
		-o $(DIST_DIR)/$(BINARY)-windows-amd64.exe ./cmd/net-scouter

build-darwin:
	@mkdir -p $(DIST_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build -trimpath \
		-o $(DIST_DIR)/$(BINARY)-darwin-amd64 ./cmd/net-scouter

build-all: build-linux build-windows build-darwin

build-bpf:
	@mkdir -p $(DIST_DIR)
	$(BPF_CLANG) -O2 -g -target bpf -mcpu=$(BPF_CPU) \
		-D__TARGET_ARCH_$(BPF_ARCH) -Wall -Werror \
		-Ibpf -c bpf/flow.bpf.c -o $(BPF_OBJECT)

build-release: build-linux build-bpf
	$(MAKE) checksums

# Compile only; this target never loads or attaches the object.
verify-bpf: build-bpf

verify-bpf-load:
	./scripts/verify-bpf-load.sh $(BPF_OBJECT)

verify-rocky-userspace:
	@test -x $(DIST_DIR)/$(BINARY)-linux-amd64 || \
		{ echo "build linux/amd64 artifacts first" >&2; exit 1; }
	$(DOCKER) run --rm --platform linux/amd64 \
		--network none --cap-drop ALL --security-opt no-new-privileges \
		-v "$(CURDIR)/$(DIST_DIR):/artifacts:ro" $(ROCKY_IMAGE) \
		/artifacts/$(BINARY)-linux-amd64 check

test-go:
	$(GO) test ./...

test-static:
	./scripts/test-bpf-invariants.sh
	./scripts/test-ci-invariants.sh

test: test-go test-static

test-ci: test build-release

check:
	./scripts/check-kernel.sh

checksums:
	@cd $(DIST_DIR) && if command -v sha256sum >/dev/null 2>&1; then \
		sha256sum $(BINARY)-linux-$(GOARCH) flow.bpf.o > SHA256SUMS; \
	else \
		shasum -a 256 $(BINARY)-linux-$(GOARCH) flow.bpf.o > SHA256SUMS; \
	fi

clean:
	rm -rf $(DIST_DIR)
