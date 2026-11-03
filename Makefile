# Simulation / verification entry points. Examples:
#   make sim TB=verify                     # NIST KATs with Vivado xsim
#   make sim TB=verify VEC=wycheproof      # Wycheproof verify vectors
#   make sim TB=sign VEC=makehint          # signatures that hit the MakeHint boundary (issue #1)
#   make sim TB=keygen VEC=expanda         # keys whose ExpandA hits reject-reject-accept in one cycle
#   make sim TB=sign VEC=gen SIM=verilator # freshly generated vectors with GHDL + Verilator
#   make lint
#   make model                             # check the Python reference model against the KATs

SIM    ?= xsim
TB     ?= verify
VEC    ?= kat
SEED   ?= 1
N      ?= 1
PYTHON ?= python3

WYCHEPROOF_COMMIT ?= d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9
WYCHEPROOF_URL    := https://raw.githubusercontent.com/C2SP/wycheproof/$(WYCHEPROOF_COMMIT)/testvectors_v1

BUILD := sim/build
VEC_DIR_kat        := KAT
VEC_DIR_makehint   := vectors/makehint_boundary
VEC_DIR_expanda    := vectors/expanda_reject
VEC_DIR_gen        := $(BUILD)/vectors/gen
VEC_DIR_wycheproof := $(BUILD)/vectors/wycheproof
VEC_DIR := $(VEC_DIR_$(VEC))

# number of vectors per level = lines in the first file of the vector set
OP_keygen := KeyGen_seed
OP_sign   := SigGen_sk
OP_verify := SigVer_pk
count = $(shell grep -c . $(VEC_DIR)/$(OP_$(TB))_$(1).txt)
DEFS_xsim      = -d NUM_TV_44=$(call count,44) -d NUM_TV_65=$(call count,65) -d NUM_TV_87=$(call count,87)
DEFS_verilator = -DNUM_TV_44=$(call count,44) -DNUM_TV_65=$(call count,65) -DNUM_TV_87=$(call count,87)

.PHONY: sim lint model vectors gen wycheproof clean

sim: $(if $(filter kat makehint expanda,$(VEC)),,$(VEC_DIR)/SigVer_pk_87.txt)
	sim/run_$(SIM).sh $(TB) $(VEC_DIR) $(DEFS_$(SIM))

lint:
	sim/lint.sh

model:
	cd model && $(PYTHON) check_kat.py ../KAT

vectors: gen wycheproof

# `make gen` always regenerates; `make sim VEC=gen` only generates if missing
gen:
	rm -rf $(VEC_DIR_gen)
	$(MAKE) $(VEC_DIR_gen)/SigVer_pk_87.txt
$(VEC_DIR_gen)/SigVer_pk_87.txt:
	$(PYTHON) model/gen_vectors.py --out $(VEC_DIR_gen) --seed $(SEED) --n $(N)
	$(PYTHON) model/check_kat.py $(VEC_DIR_gen)

wycheproof: $(VEC_DIR_wycheproof)/SigVer_pk_87.txt
$(VEC_DIR_wycheproof)/SigVer_pk_87.txt:
	mkdir -p $(BUILD)/wycheproof_json
	for l in 44 65 87; do curl -sSfL -o $(BUILD)/wycheproof_json/mldsa_$${l}_verify_test.json \
	    $(WYCHEPROOF_URL)/mldsa_$${l}_verify_test.json; done
	$(PYTHON) model/wycheproof_to_tb.py $(BUILD)/wycheproof_json $(VEC_DIR_wycheproof)

clean:
	rm -rf $(BUILD)
