ROOT_DIR 		:= $(abspath .)
BIN_DIR			:= bin

TARGET = contract/main.go
WASM = $(BIN_DIR)/main.wasm
BUILD_FLAGS = -gc=custom -scheduler=none -panic=trap -no-debug -target=wasm-unknown

# A2/F8 (MED #36): supply-chain pinning. A bare `:0.41.1` tag is MUTABLE — the
# upstream image owner (or a registry compromise) can re-push it, so a "clean"
# rebuild can silently produce a DIFFERENT WASM and a CID mismatch. The build is
# pinned to the IMMUTABLE content digest of the exact image (an `@sha256:...`
# reference cannot be re-pointed). The tag is kept only as a human-readable
# comment. The digest below is the OCI image-index digest of tinygo/tinygo:0.41.1
# and is the load-bearing reference; verify/refresh it with:
#     docker buildx imagetools inspect tinygo/tinygo:0.41.1 --format '{{.Manifest.Digest}}'
TINYGO_TAG    := tinygo/tinygo:0.41.1
TINYGO_DIGEST := sha256:b216f534ddbf277444407b014a3328b5c1ade403cc397f3ab48a14789bf99d0e
TINYGO_IMAGE  := tinygo/tinygo@$(TINYGO_DIGEST)
WORKDIR      := /work

# For each local path in go.work (use/replace directives), add a Docker volume
# mount so the container can resolve the same relative paths as the host.
# Container path is computed by normalising WORKDIR/relative_path.
GOWORK_EXTRA_MOUNTS := $(if $(wildcard go.work),$(shell \
  awk '($$1=="use"||$$1=="replace") && $$NF~/^(\.|\/|~)/ && $$NF!="." {print $$NF}' go.work 2>/dev/null | \
  while read rel; do \
    host=$$(realpath "$(CURDIR)/$$rel" 2>/dev/null); \
    ctr=$$(python3 -c "import os,sys; print(os.path.normpath(sys.argv[1]))" "$(WORKDIR)/$$rel"); \
    [ -d "$$host" ] && printf -- '-v %s:%s ' "$$host" "$$ctr"; \
  done),)

CACHE_DIR := $(CURDIR)/.cache

# tinygo 0.41+ writes a build cache via $HOME/.cache. With -u <uid>:<gid> and no
# /etc/passwd entry inside the container, $HOME resolves to "/" and the mkdir
# fails with permission denied. Mount a project-local cache dir and point HOME
# at it so caches persist between builds (Go modules, tinygo build cache).
TINYGO_CMD = docker run --rm \
    -u $(shell id -u):$(shell id -g) \
    $(GOWORK_EXTRA_MOUNTS) \
    -v $(CURDIR):$(WORKDIR) \
    -v $(CACHE_DIR):/cache \
    -e HOME=/cache \
    -w $(WORKDIR) \
    $(TINYGO_IMAGE) \
    tinygo

ifeq ($(USE_DOCKER),0)
    TINYGO_CMD = tinygo
endif

FILTER ?= .

RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
ifneq ($(RUN_ARGS),)
  ifeq ($(firstword $(MAKECMDGOALS)),test)
    FILTER := $(firstword $(RUN_ARGS))
  endif
endif
$(eval $(RUN_ARGS):;@:)

all: build

pull-tinygo:
	docker pull $(TINYGO_IMAGE)

MODULE := $(shell head -1 go.mod | awk '{print $$2}')

build:
	@mkdir -p $(BIN_DIR) $(CACHE_DIR); \
	wasm_file="$(WASM)"; \
	dir="$(ROOT_DIR)/$(dir $(TARGET))"; \
	dir="$${dir%/}"; \
	if [ -f "$$wasm_file" ]; then \
		dep_dirs="$$dir"; \
		queue="$$dir"; \
		while [ -n "$$queue" ]; do \
			next_queue=""; \
			for d in $$queue; do \
				for imp in $$(grep -roh '"$(MODULE)/[^"]*"' "$$d"/*.go 2>/dev/null | tr -d '"' | sed 's|$(MODULE)/||' | sort -u); do \
					resolved="$(ROOT_DIR)/$$imp"; \
					case " $$dep_dirs " in \
						*" $$resolved "*) ;; \
						*) [ -d "$$resolved" ] && dep_dirs="$$dep_dirs $$resolved" && next_queue="$$next_queue $$resolved" ;; \
					esac; \
				done; \
			done; \
			queue="$$next_queue"; \
		done; \
		needs_rebuild=0; \
		for dep_dir in $$dep_dirs; do \
			if find "$$dep_dir" -maxdepth 1 -type f -name '*.go' -newer "$$wasm_file" 2>/dev/null | grep -q .; then \
				needs_rebuild=1; \
				break; \
			fi; \
		done; \
		if [ "$$needs_rebuild" -eq 0 ] && \
		   [ ! "$(ROOT_DIR)/go.mod" -nt "$$wasm_file" ] && \
		   [ ! "$(ROOT_DIR)/go.sum" -nt "$$wasm_file" ]; then \
			echo "⏩ $$wasm_file is up to date, skipping"; \
		else \
			echo "Building $$wasm_file ..."; \
			$(TINYGO_CMD) build $(BUILD_FLAGS) -o $$wasm_file $(TARGET); \
		fi; \
	else \
		echo "Building $$wasm_file ..."; \
		$(TINYGO_CMD) build $(BUILD_FLAGS) -o $$wasm_file $(TARGET); \
	fi

strip:
	@for file in $(BIN_DIR)/*.wasm; do \
		case "$$file" in \
			*"-stripped.wasm") \
				continue ;; \
			*) \
				base=$${file%.wasm}; \
				wasm-tools strip -o "$${base}-stripped.wasm" "$$file"; \
				echo "Stripped $$file -> $${base}-stripped.wasm" ;; \
		esac; \
	done

test:
	go test -v -run "$(FILTER)" ./...

clean:
	rm -rf $(BIN_DIR)/*.wasm

.PHONY: all build pull-tinygo strip test clean
