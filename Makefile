RUST_TOOLCHAIN_NIGHTLY = nightly-2026-01-22
SOLANA_CLI_VERSION = v3.1.10
SBF_ARCH = v2
PROGRAM_SO = solana_secp256k1_program.so

nightly = +${RUST_TOOLCHAIN_NIGHTLY}

make-path = $1

rust-toolchain-nightly:
	@echo ${RUST_TOOLCHAIN_NIGHTLY}

solana-cli-version:
	@echo ${SOLANA_CLI_VERSION}

audit:
	cargo audit $(ARGS)

spellcheck:
	cargo spellcheck --code 1 $(ARGS)

clippy-%:
	cargo $(nightly) clippy --manifest-path $(call make-path,$*)/Cargo.toml \
		--all-targets \
		--all-features \
		-- \
		--deny=warnings $(ARGS)

format-check-%:
	cargo $(nightly) fmt --check --manifest-path $(call make-path,$*)/Cargo.toml $(ARGS)

powerset-%:
	cargo $(nightly) hack check \
		--feature-powerset \
		--all-targets \
		--manifest-path $(call make-path,$*)/Cargo.toml \
		$(ARGS)

build-doc-%:
	RUSTDOCFLAGS="--cfg docsrs -D warnings" cargo $(nightly) doc \
		--all-features \
		--no-deps \
		--manifest-path $(call make-path,$*)/Cargo.toml \
		$(ARGS)

build-sbf-%:
	cargo build-sbf --arch $(SBF_ARCH) --manifest-path $(call make-path,$*)/Cargo.toml -- --locked $(ARGS)

test-%:
	@test -f target/deploy/$(PROGRAM_SO) || \
		(echo "SBF artifact not found: run make build-sbf-$* first" >&2; exit 1)
	SBF_OUT_DIR=$(PWD)/target/deploy cargo test \
		--locked \
		--manifest-path $(call make-path,$*)/Cargo.toml \
		$(ARGS)

cu-program: build-sbf-program
	SBF_OUT_DIR=$(PWD)/target/deploy cargo test \
		--locked \
		--manifest-path program/Cargo.toml \
		--test mollusk \
		-- --nocapture

build-sbf-secp256k1: build-sbf-program
build-doc-secp256k1: build-doc-program
clippy-secp256k1: clippy-program
cu-secp256k1: cu-program
format-check-secp256k1: format-check-program
powerset-secp256k1: powerset-program
test-secp256k1: test-program

generate-clients:
	exit 0
