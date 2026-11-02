#!/usr/bin/env bash
# Lint the RTL: GHDL analysis/elaboration of the VHDL, Verilator lint of the full design
# (combined_top + GHDL-translated Keccak). Fails on errors; warnings are reported only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/sim/build/lint"
rm -rf "$BUILD" && mkdir -p "$BUILD" && cd "$BUILD"

echo "== GHDL: VHDL analysis + synthesis of keccak_top"
"$ROOT/sim/ghdl_keccak.sh" keccak_top.v

echo "== Verilator: lint combined_top"
verilator --lint-only -Wall -Wno-fatal --top-module combined_top \
    keccak_top.v $(sed "s|^|$ROOT/|" "$ROOT/sim/files_verilog.f") 2> verilator_lint.log || {
    grep "%Error" verilator_lint.log; exit 1; }
echo "$(grep -c '^%Warning' verilator_lint.log || true) warnings (see $BUILD/verilator_lint.log)"
grep '^%Warning' verilator_lint.log | sed 's/:.*//' | sort | uniq -c | sort -rn || true

echo "== Verilator: lint testbenches"
for tb in keygen sign verify; do
    verilator --lint-only -Wno-fatal -Wno-lint -Wno-style --timing --top-module "tb_${tb}_top" \
        -I"$ROOT/ref_combined/src_tb" keccak_top.v $(sed "s|^|$ROOT/|" "$ROOT/sim/files_verilog.f") \
        "$ROOT/ref_combined/src_tb/tb_${tb}_top.v" 2> "tb_${tb}.log" || { grep "%Error" "tb_${tb}.log"; exit 1; }
    echo "tb_${tb}_top: OK"
done
