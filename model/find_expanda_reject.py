#!/usr/bin/env python3
"""Search keys whose ExpandA hits two consecutive rejections followed by an accept.

    python3 model/find_expanda_reject.py --out vectors/expanda_reject --per-level 2

rejection_a.v checks three 23-bit candidates per cycle and compacts the accepted ones.
Before the fix, the case lane0 = lane1 = rejected, lane2 = accepted forwarded the zeroed
lane0 instead of lane2, so that coefficient of A became 0. A wrong
A breaks KeyGen (t1), Sign and Verify for the key, independent of the message. Candidates
are rejected with probability (2^23 - q) / 2^23 ~ 1e-3, so this needs two in a row and hits
about 0.2% of ML-DSA-87 keys; the NIST KATs miss it.

Which candidates share a cycle depends on the sampler's SIPO fill level, so this script
selects every key with a reject-reject-accept run (a superset of the failing keys);
the vectors kept in the repo were checked to fail on the old RTL. For each key it writes a
KeyGen vector, a deterministic (rnd = 0) SigGen vector and the matching valid SigVer vector.
"""
import argparse
import hashlib
import random

import tbvec

Q = 8380417


def reject_runs(rho, k, l):
    """(i, j, coefficient index) of every accepted candidate preceded by two rejections in A[i][j]."""
    hits = []
    for i in range(k):
        for j in range(l):
            stream = hashlib.shake_128(rho + bytes([j, i])).digest(168 * 8)
            n, rej = 0, 0
            for off in range(0, len(stream), 3):
                c = int.from_bytes(stream[off:off + 3], 'little') & 0x7FFFFF
                if c >= Q:
                    rej += 1
                    continue
                if rej >= 2:
                    hits.append((i, j, n))
                rej = 0
                n += 1
                if n == 256:
                    break
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--out', required=True)
    ap.add_argument('--per-level', type=int, default=2)
    ap.add_argument('--levels', default='44,65,87')
    ap.add_argument('--seed', type=int, default=0)
    args = ap.parse_args()
    for lvl in map(int, args.levels.split(',')):
        S = tbvec.LEVELS[lvl]
        rng = random.Random(f'{args.seed}-{lvl}')
        found = []
        while len(found) < args.per_level:
            seed = rng.randbytes(32)
            pk, sk = S.key_derive(seed)
            hits = reject_runs(pk[:32], S.k, S.l)
            if not hits:
                continue
            msg = rng.randbytes(rng.randint(1, 64))
            ctx = rng.randbytes(rng.choice([0, rng.randint(1, 32)]))
            sig = S.sign(sk, msg, ctx, deterministic=True)
            assert S.verify(pk, msg, sig, ctx)
            print(f'ML-DSA-{lvl}: seed {seed.hex()} hits A[i][j] coefficient {hits}')
            found.append(dict(seed=seed, pk=pk, sk=sk, message=msg, mlen=len(msg), ctx=ctx,
                              ctxlen=len(ctx), signature=sig, result=False))
        for op in ('KeyGen', 'SigGen', 'SigVer'):
            tbvec.write(args.out, op, lvl, found)


if __name__ == '__main__':
    main()
