#!/usr/bin/env bash
# Run one of the testbenches with open-source tools (used by GitHub Actions).
#
#   sim/run_verilator.sh <keygen|sign|verify> [vector_dir] [-DNAME=VALUE ...]
#
# The VHDL Keccak core is translated to Verilog with GHDL (ghdl --synth), and the
# whole design + testbench is then simulated with Verilator (--binary --timing).
# Requires ghdl and verilator >= 5 on PATH (e.g. from the OSS CAD Suite).
# Exit status is non-zero if any vector fails.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TB="${1:?usage: $0 <keygen|sign|verify> [vector_dir] [-DNAME=VALUE...]}"
VEC="$(cd "${2:-$ROOT/KAT}" && pwd)"
shift $(( $# >= 2 ? 2 : 1 ))

BUILD="$ROOT/sim/build/verilator_${TB}_$(basename "$VEC")"
rm -rf "$BUILD" && mkdir -p "$BUILD" && cd "$BUILD"

"$ROOT/sim/ghdl_keccak.sh" keccak_top.v

verilator --binary --timing -j "$(nproc)" -O2 \
    -Wno-fatal -Wno-lint -Wno-style -Wno-MULTIDRIVEN -Wno-INITIALDLY \
    --top-module "tb_${TB}_top" -I"$ROOT/ref_combined/src_tb" "$@" \
    keccak_top.v $(sed "s|^|$ROOT/|" "$ROOT/sim/files_verilog.f") \
    "$ROOT/ref_combined/src_tb/tb_${TB}_top.v" > verilator.log 2>&1 \
    || { tail -50 verilator.log; exit 1; }

ln -s "$ROOT"/common/zetas.txt .
ln -s "$VEC"/*.txt .
"obj_dir/Vtb_${TB}_top" | tee sim.log | grep -v "completed in"

grep -q "TEST SUMMARY: .* 0 failed" sim.log
