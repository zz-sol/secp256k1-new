RUST_TOOLCHAIN_NIGHTLY = nightly-2026-01-22
SOLANA_CLI_VERSION = v3.1.10
SBF_ARCH = v2

nightly = +${RUST_TOOLCHAIN_NIGHTLY}

make-path = $(if $(filter program secp256k1,$1),program,$1)
make-so = $(if $(filter program secp256k1,$1),solana_secp256k1_program,$1)

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
	@if [ -f target/deploy/$(call make-so,$*).so ]; then \
		SBF_OUT_DIR=$(PWD)/target/deploy cargo test \
			--locked \
			--manifest-path $(call make-path,$*)/Cargo.toml \
			$(ARGS); \
	else \
		cargo test \
			--locked \
			--manifest-path $(call make-path,$*)/Cargo.toml \
			$(ARGS); \
	fi

cu-secp256k1: build-sbf-secp256k1
	SBF_OUT_DIR=$(PWD)/target/deploy cargo test \
		--locked \
		--manifest-path Cargo.toml \
		--test mollusk \
		-- --nocapture

generate-clients:
	exit 0
