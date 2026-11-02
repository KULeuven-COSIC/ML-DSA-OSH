# ML-DSA-OSH
[![CI](https://github.com/KULeuven-COSIC/ML-DSA-OSH/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/KULeuven-COSIC/ML-DSA-OSH/actions/workflows/ci.yml)

This repository contains the verilog/vhdl sources of an efficient HW implementation of ML-DSA ([FIPS 204](https://doi.org/10.6028/NIST.FIPS.204)). The current design is largely based on the design by [Beckwith et al.](https://eprint.iacr.org/2021/1451), and their [open-source implementation](https://github.com/GMUCERG/Dilithium) of CRYSTALS-Dilithium v3.1.
The design supports all three NIST security levels (II, III and V) and operations (KeyGen, SigGen, SigVer), at runtime: one can perform operations of any configuration on the same hardware instantiation.

## :file_folder: Contents

* [src](ref_combined/src/): verilog/vhdl (design) source files.
* [common](common): definition of ML-DSA parameter sets and twiddle factors.
* [testbench](ref_combined/src_tb/): testbenches for all modes of operation.
* [NIST KAT's](KAT): testvectors for ML-DSA-44, ML-DSA-67 and ML-DSA-87 (KeyGen, SigGen, SigVer).

## :test_tube: Testing

Test vectors, all in the same line-based format as [KAT](KAT) (`SigVer_result`: `1` = reject):

* the NIST KATs in [KAT](KAT);
* [vectors/makehint_boundary](vectors/makehint_boundary): signatures whose computation hits the MakeHint boundary a0 = −γ2, a1 = 0 (found with [model/find_makehint_boundary.py](model/find_makehint_boundary.py); about 1 in 10⁴ signatures, so random KATs miss it);
* the [C2SP Wycheproof](https://github.com/C2SP/wycheproof) ML-DSA verify vectors (pinned commit, downloaded and converted by `make wycheproof`);
* fresh vectors from the [dilithium-py](https://github.com/GiacomoPope/dilithium-py) reference model (`make gen SEED=<n> N=<n>`), including malformed signatures that isolate single Verify checks (z bound, hint encoding, zero hints, ...). See [model/gen_vectors.py](model/gen_vectors.py).

```sh
pip install -r model/requirements.txt
make model                                  # reference model reproduces the NIST KATs
make sim SIM=xsim TB=verify                 # NIST KATs, Vivado xsim (TB = keygen | sign | verify)
make sim SIM=xsim TB=verify VEC=wycheproof  # Wycheproof vectors
make sim SIM=verilator TB=sign VEC=gen      # generated vectors, GHDL + Verilator
make sim TB=sign VEC=makehint               # MakeHint boundary vectors
make lint                                   # GHDL + Verilator lint
```

`SIM=xsim` sources the Vivado settings from `$VIVADO_SETTINGS` if `xvlog` is not on the `PATH`. `SIM=verilator` translates the VHDL Keccak core to Verilog with GHDL and needs `ghdl` and `verilator` (>= 5), e.g. from the [OSS CAD Suite](https://github.com/YosysHQ/oss-cad-suite-build). `tb_sign_top` additionally checks that the z, c·t0 and r0 bound checks see every coefficient of every signing attempt. Failing vectors can be mapped back to their Wycheproof tcId or generator category with `python3 model/report.py <sim.log> <vector dir>`. GitHub Actions runs the model check, lint and all of these vector sets on every push.

## :book: Bibliography

If you use or build upon the code in this repository, please cite our paper using our [citation key](CITATION).

## Licensing

See our [license](LICENSE) and further details of original sources in the accompanying [notice](NOTICE).

