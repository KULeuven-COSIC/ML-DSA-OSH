#!/usr/bin/env bash
# Run one of the testbenches with Vivado xsim.
#
#   sim/run_xsim.sh <keygen|sign|verify> [vector_dir] [extra xvlog args, e.g. -d NUM_TV_87=3]
#
# vector_dir defaults to KAT/. It must contain the testbench's *.txt files
# (same names/format as KAT/). Exit status is non-zero if any vector fails.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TB="${1:?usage: $0 <keygen|sign|verify> [vector_dir] [xvlog args...]}"
VEC="$(cd "${2:-$ROOT/KAT}" && pwd)"
shift $(( $# >= 2 ? 2 : 1 ))

if ! command -v xvlog >/dev/null 2>&1; then
    # Site default (KU Leuven ESAT); override with VIVADO_SETTINGS=/path/to/settings64.sh
    VIVADO_SETTINGS="${VIVADO_SETTINGS:-$(eval echo ~micasusr)/design/scripts/xilinx_vivado_2021.1.rc}"
    # shellcheck disable=SC1090
    source "$VIVADO_SETTINGS" >/dev/null
fi

BUILD="$ROOT/sim/build/xsim_${TB}_$(basename "$VEC")"
rm -rf "$BUILD" && mkdir -p "$BUILD" && cd "$BUILD"
ln -s "$ROOT"/common/zetas.txt .
ln -s "$VEC"/*.txt .

run() { local log=$1; shift; "$@" > "$log" 2>&1 || { grep -i "error" "$log"; exit 1; }; }
run xvhdl.log xvhdl --relax $(sed "s|^|$ROOT/|" "$ROOT/sim/files_vhdl.f")
run xvlog.log xvlog --relax -i "$ROOT/ref_combined/src_tb" "$@" \
    $(sed "s|^|$ROOT/|" "$ROOT/sim/files_verilog.f") \
    "$ROOT/ref_combined/src_tb/tb_${TB}_top.v"
run xelab.log xelab --relax -debug off "tb_${TB}_top" -s sim
xsim sim -R | tee xsim.log | grep -v "^ *$" | grep -iv "^\*\*\*\|^INFO\|^#\|copyright\|^Time resolution\|^start_gui"

grep -q "TEST SUMMARY: .* 0 failed" xsim.log
