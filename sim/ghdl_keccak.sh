#!/usr/bin/env bash
# Translate the VHDL Keccak core (keccak_top and below) to a Verilog netlist with GHDL.
#
#   sim/ghdl_keccak.sh <out.v>
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$(realpath -m "${1:?usage: $0 <out.v>}")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ghdl -a --std=08 -frelaxed -fsynopsys --workdir="$WORK" $(sed "s|^|$ROOT/|" "$ROOT/sim/files_vhdl.f")
ghdl --synth --std=08 -frelaxed -fsynopsys --workdir="$WORK" --out=verilog keccak_top > "$OUT"
