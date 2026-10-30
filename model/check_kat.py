#!/usr/bin/env python3
"""Check that the reference model reproduces a vector directory (default: KAT/).

    python3 model/check_kat.py [vector_dir]

Validates the model and the file format in both directions: KeyGen from seed,
deterministic SigGen (rnd = 0, as the HW does) and every SigVer verdict.
"""
import os
import sys

import tbvec


def main(vec_dir):
    errors = 0
    for lvl, S in tbvec.LEVELS.items():
        counts = {}
        for op in ('KeyGen', 'SigGen', 'SigVer'):
            if not os.path.exists(os.path.join(vec_dir, f'{op}_{tbvec.FIELDS[op][0]}_{lvl}.txt')):
                continue
            vecs = tbvec.read(vec_dir, op, lvl)
            for i, v in enumerate(vecs):
                if op == 'KeyGen':
                    ok = S.key_derive(v['seed']) == (v['pk'], v['sk'])
                elif op == 'SigGen':
                    ok = S.sign(v['sk'], v['message'], v['ctx'], deterministic=True) == v['signature']
                else:
                    ok = S.verify(v['pk'], v['message'], v['signature'], v['ctx']) != v['result']
                if not ok:
                    print(f'ML-DSA-{lvl} {op} #{i}: model disagrees with vector')
                    errors += 1
            counts[op] = len(vecs)
        print(f'ML-DSA-{lvl}: checked {counts}')
    print('FAIL' if errors else 'OK')
    return 1 if errors else 0


if __name__ == '__main__':
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(root, 'KAT')))
