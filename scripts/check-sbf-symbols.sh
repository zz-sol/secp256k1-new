#!/usr/bin/env bash
set -euo pipefail

elf="${1:-target/deploy/secp256k1.so}"

if [[ ! -f "$elf" ]]; then
  echo "SBF artifact not found: $elf" >&2
  exit 1
fi

readelf_bin="${LLVM_READELF:-}"
if [[ -z "$readelf_bin" ]]; then
  if command -v llvm-readelf >/dev/null 2>&1; then
    readelf_bin="llvm-readelf"
  else
    sdk_readelf="$HOME/.local/share/solana/install/active_release/bin/platform-tools-sdk/sbf/dependencies/platform-tools/llvm/bin/llvm-readelf"
    if [[ -x "$sdk_readelf" ]]; then
      readelf_bin="$sdk_readelf"
    else
      echo "llvm-readelf not found" >&2
      exit 1
    fi
  fi
fi

allowed_symbols=(
  # Standard Solana runtime memory syscall emitted by SDK/compiler support code.
  sol_memcpy_
)

undefined_symbols="$("$readelf_bin" -s "$elf" \
  | awk '$7 == "UND" && $8 != "" { print $8 }' \
  | sort -u)"

status=0
while IFS= read -r symbol; do
  [[ -z "$symbol" ]] && continue

  allowed=0
  for allowed_symbol in "${allowed_symbols[@]}"; do
    if [[ "$symbol" == "$allowed_symbol" ]]; then
      allowed=1
      break
    fi
  done

  if [[ "$allowed" -eq 0 ]]; then
    echo "Unexpected unresolved SBF symbol: $symbol" >&2
    status=1
  fi
done <<< "$undefined_symbols"

if [[ "$status" -ne 0 ]]; then
  echo "Refusing to publish SBF artifact with unexpected unresolved symbols." >&2
  exit "$status"
fi

echo "SBF unresolved symbol check passed."
