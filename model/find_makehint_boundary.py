#!/usr/bin/env python3
"""Search SigGen vectors that hit the MakeHint boundary (a0 = -gamma2, a1 = 0).

    python3 model/find_makehint_boundary.py --out vectors/regression --per-level 1

The HW computes the hint from a0 = w0 - c*s2 + c*t0 and a1 = w1 (the optimised
MakeHint of the pq-crystals reference): hint = a0 > g2 || a0 < -g2 || (a0 == -g2 && a1 != 0).
Before the fix (GitHub issue #1) makehint.v also set a hint at a0 = -g2, a1 = 0. This happens
for roughly 1e-4 of all signatures, so deterministic KATs never exercise it; this script
searches for messages whose (deterministic, rnd = 0) signature does, and appends them as
SigGen vectors. It also reports what a signer with the old predicate would output.
"""
import argparse
import multiprocessing as mp
import os
import random

import tbvec
from dilithium_py.utilities.utils import decompose

Q = 8380417


def centered(x):
    x %= Q
    return x - Q if x > Q // 2 else x


def polys(v):
    return [p for row in v._data for p in row]


def sign_trace(S, sk, mp_, rnd):
    """FIPS 204 Alg. 7 (as dilithium-py), returning the signature and the number of
    coefficients of the final attempt with a0 = -gamma2 and a1 = 0, plus the old-predicate hints."""
    rho, k, tr, s1, s2, t0 = S._unpack_sk(sk)
    s1_hat, s2_hat, t0_hat = s1.to_ntt(), s2.to_ntt(), t0.to_ntt()
    A_hat = S._expand_matrix_from_seed(rho)
    mu = S._h(tr + mp_, 64)
    rho_prime = S._h(k + rnd + mu, 64)
    alpha, kappa = 2 * S.gamma_2, 0
    while True:
        y = S._expand_mask_vector(rho_prime, kappa)
        kappa += S.l
        w = (A_hat @ y.to_ntt()).from_ntt()
        c_tilde = S._h(mu + w.high_bits(alpha).bit_pack_w(S.gamma_2), S.c_tilde_bytes)
        c_hat = S.R.sample_in_ball(c_tilde, S.tau).to_ntt()
        z = y + s1_hat.scale(c_hat).from_ntt()
        if z.check_norm_bound(S.gamma_1 - S.beta):
            continue
        c_s2 = s2_hat.scale(c_hat).from_ntt()
        if (w - c_s2).low_bits(alpha).check_norm_bound(S.gamma_2 - S.beta):
            continue
        c_t0 = t0_hat.scale(c_hat).from_ntt()
        if c_t0.check_norm_bound(S.gamma_2):
            continue
        h = (-c_t0).make_hint(w - c_s2 + c_t0, alpha)
        if h.sum_hint() > S.omega:
            continue
        extra = []
        for i, (wi, cs2i, ct0i) in enumerate(zip(polys(w), polys(c_s2), polys(c_t0))):
            for j in range(256):
                r1, r0 = decompose(wi.coeffs[j], alpha, Q)
                a0 = centered(r0 - cs2i.coeffs[j] + ct0i.coeffs[j])
                if a0 == -S.gamma_2 and r1 == 0:
                    extra.append((i, j))
        return S._pack_sig(c_tilde, z, h), h, c_tilde, z, extra


def search(args):
    lvl, seed, tries = args
    S = tbvec.LEVELS[lvl]
    rng = random.Random(seed)
    pk, sk = S.key_derive(rng.randbytes(32))
    for _ in range(tries):
        msg = rng.randbytes(rng.randint(1, 64))
        ctx = rng.randbytes(rng.choice([0, rng.randint(1, 32)]))
        sig, h, c_tilde, z, extra = sign_trace(S, sk, bytes([0, len(ctx)]) + ctx + msg, bytes(32))
        if extra:
            assert sig == S.sign(sk, msg, ctx, deterministic=True)
            for i, j in extra:  # signature the old predicate would produce (if <= omega hints)
                polys(h)[i].coeffs[j] = 1
            old = S._pack_sig(c_tilde, z, h) if h.sum_hint() <= S.omega else None
            return dict(pk=pk, sk=sk, message=msg, mlen=len(msg), ctx=ctx, ctxlen=len(ctx), signature=sig,
                        n_extra=len(extra),
                        old_verifies=None if old is None else S.verify(pk, msg, old, ctx))
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--out', required=True)
    ap.add_argument('--per-level', type=int, default=1)
    ap.add_argument('--levels', default='44,65,87')
    ap.add_argument('--seed', type=int, default=0)
    args = ap.parse_args()
    with mp.Pool() as pool:
        for lvl in map(int, args.levels.split(',')):
            found, batch = [], 0
            while len(found) < args.per_level:
                jobs = [(lvl, f'{args.seed}-{lvl}-{batch}-{i}', 200) for i in range(os.cpu_count())]
                found += [v for v in pool.map(search, jobs) if v]
                batch += 1
            found = found[:args.per_level]
            for v in found:
                print(f'ML-DSA-{lvl}: {v["n_extra"]} boundary coefficient(s); old-predicate signature '
                      + ('exceeds omega' if v['old_verifies'] is None else
                         'verifies' if v['old_verifies'] else 'FAILS verification'))
            tbvec.write(args.out, 'SigGen', lvl, found)
            tbvec.write(args.out, 'SigVer', lvl, [dict(v, result=False) for v in found])


if __name__ == '__main__':
    main()
