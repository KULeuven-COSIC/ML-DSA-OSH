#!/usr/bin/env python3
"""Convert C2SP Wycheproof ML-DSA verify vectors to the testbench format.

    python3 model/wycheproof_to_tb.py <wycheproof>/testvectors_v1 vectors/wycheproof

Vectors the fixed-size HW interface cannot represent (wrong pk/sig length,
ctx > 255 bytes) are skipped. The expected verdict is taken from Wycheproof and
cross-checked against dilithium-py. tcid_<lvl>.txt maps each line to its tcId.
"""
import json
import os
import sys

import tbvec


def convert(src_dir, out_dir):
    for lvl, scheme in tbvec.LEVELS.items():
        with open(os.path.join(src_dir, f'mldsa_{lvl}_verify_test.json')) as f:
            data = json.load(f)
        vecs, ids, skipped = [], [], 0
        for g in data['testGroups']:
            pk = bytes.fromhex(g['publicKey'])
            for t in g['tests']:
                sig, msg = bytes.fromhex(t['sig']), bytes.fromhex(t['msg'])
                ctx = bytes.fromhex(t.get('ctx', ''))
                if len(pk) != scheme._pk_size() or len(sig) != scheme._sig_size() or len(ctx) > 255:
                    skipped += 1
                    continue
                reject = t['result'] != 'valid'
                assert scheme.verify(pk, msg, sig, ctx) != reject, f'model disagrees on tcId {t["tcId"]}'
                vecs.append(dict(pk=pk, message=msg, mlen=len(msg), ctx=ctx, ctxlen=len(ctx),
                                 signature=sig, result=reject))
                ids.append(f'{t["tcId"]} {t["result"]} {",".join(t["flags"])}')
        tbvec.write(out_dir, 'SigVer', lvl, vecs)
        with open(os.path.join(out_dir, f'tcid_{lvl}.txt'), 'w') as f:
            f.write('\n'.join(ids) + '\n')
        print(f'ML-DSA-{lvl}: {len(vecs)} vectors written, {skipped} skipped (length/ctx)')


if __name__ == '__main__':
    convert(sys.argv[1], sys.argv[2])
