#!/usr/bin/env python3
"""Generate fresh ML-DSA test vectors for the testbenches from the dilithium-py reference model.

    python3 model/gen_vectors.py --out vectors/gen --seed 1 --n 2

Writes KeyGen_*, SigGen_* and SigVer_* files (same format as KAT/) for
ML-DSA-44/65/87, plus desc_<lvl>.txt describing every SigVer line. All
expected verdicts come from dilithium-py's verify(); every constructed
case additionally asserts that the model gives the intended verdict.

SigVer categories (each --n times per level, unless noted):
  valid          hedged signature, random message/context
  tamper         valid signature with a flipped bit in c~, z or the message
  z_bound        real key, signer patched to emit ||z||inf >= gamma1-beta (c~, h consistent)
  forged_*       signatures for a public key with t1 = 0, where c~ can be computed for
                 any z and h (the same trick Wycheproof uses). This isolates single checks:
                 z exactly at gamma1-beta-1 (valid) / gamma1-beta (invalid), zero hints,
                 omega hints, hints only in the last polynomial.
  hint_*         re-encodings of the hint field of a forged valid signature that decode
                 to the same hints or overflow omega: reversed order, repeated index,
                 non-zero padding, non-monotone counts, count > omega (all invalid).
"""
import argparse
import random

import tbvec


def rand_msg_ctx(rng, max_mlen=256):
    msg = rng.randbytes(rng.randint(1, max_mlen))
    ctx = rng.randbytes(rng.choice([0, rng.randint(1, 255)]))
    return msg, ctx


def m_prime(msg, ctx):
    return bytes([0, len(ctx)]) + ctx + msg


def sigver(S, pk, msg, ctx, sig, desc, expect=None):
    ok = S.verify(pk, msg, sig, ctx)
    if expect is not None:
        assert ok == expect, f'model verdict for {desc} is {ok}, expected {expect}'
    return dict(pk=pk, message=msg, mlen=len(msg), ctx=ctx, ctxlen=len(ctx),
                signature=sig, result=not ok, desc=desc)


# ---------------------------------------------------------------------------
# signatures for real keys

def sign_z_violation(S, sk, mp, rnd):
    """FIPS 204 Alg. 7 with the z rejection inverted: returns a signature whose c~ and h
    are consistent but whose z violates ||z||inf < gamma1 - beta."""
    rho, k, tr, s1, s2, t0 = S._unpack_sk(sk)
    s1_hat, s2_hat, t0_hat = s1.to_ntt(), s2.to_ntt(), t0.to_ntt()
    A_hat = S._expand_matrix_from_seed(rho)
    mu = S._h(tr + mp, 64)
    rho_prime = S._h(k + rnd + mu, 64)
    alpha, kappa = 2 * S.gamma_2, 0
    while True:
        y = S._expand_mask_vector(rho_prime, kappa)
        kappa += S.l
        w = (A_hat @ y.to_ntt()).from_ntt()
        c_tilde = S._h(mu + w.high_bits(alpha).bit_pack_w(S.gamma_2), S.c_tilde_bytes)
        c_hat = S.R.sample_in_ball(c_tilde, S.tau).to_ntt()
        z = y + s1_hat.scale(c_hat).from_ntt()
        if not z.check_norm_bound(S.gamma_1 - S.beta):
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
        return S._pack_sig(c_tilde, z, h)


def flip_bit(rng, data, lo, hi):
    pos = rng.randrange(lo, hi)
    out = bytearray(data)
    out[pos] ^= 1 << rng.randrange(8)
    return bytes(out)


# ---------------------------------------------------------------------------
# forged signatures for t1 = 0

def forge(S, rng, msg, ctx, z_coeffs, hints):
    """Valid-by-construction signature (except for deliberate z violations) for the
    public key rho || 0: with t1 = 0, w' = UseHint(h, Az) does not depend on c."""
    rho = rng.randbytes(32)
    pk = rho + bytes(320 * S.k)
    z = S.M.vector([S.R([c % 8380417 for c in poly]) for poly in z_coeffs])
    w = (S._expand_matrix_from_seed(rho) @ z.to_ntt()).from_ntt()
    h = S.M.vector([S.R([1 if j in hp else 0 for j in range(256)]) for hp in hints])
    w1 = h.use_hint(w, 2 * S.gamma_2)
    mu = S._h(S._h(pk, 64) + m_prime(msg, ctx), 64)
    c_tilde = S._h(mu + w1.bit_pack_w(S.gamma_2), S.c_tilde_bytes)
    return pk, S._pack_sig(c_tilde, z, h)


def rand_z(S, rng, bound):
    return [[rng.randint(-bound, bound) for _ in range(256)] for _ in range(S.l)]


def rand_hints(S, rng, total, polys=None):
    polys = polys if polys is not None else list(range(S.k))
    hints = [set() for _ in range(S.k)]
    while sum(map(len, hints)) < total:
        hints[rng.choice(polys)].add(rng.randrange(256))
    return hints


def hint_field(S, sig):
    h = sig[-(S.omega + S.k):]
    return bytearray(h[:S.omega]), bytearray(h[S.omega:])


def with_hint_field(S, sig, idx, cnt):
    return sig[:-(S.omega + S.k)] + bytes(idx) + bytes(cnt)


def hint_mutations(S, rng, sig):
    """Yield (name, sig') re-encodings of the hint field that FIPS 204 Alg. 21 must reject."""
    idx, cnt = hint_field(S, sig)
    total = cnt[-1]
    starts = [0] + list(cnt[:-1])
    multi = [i for i in range(S.k) if cnt[i] - starts[i] >= 2]
    if multi:  # swap two neighbouring indices within one polynomial
        i = rng.choice(multi)
        j = rng.randrange(starts[i], cnt[i] - 1)
        m = idx[:]
        m[j], m[j + 1] = m[j + 1], m[j]
        yield 'hint_reversed', with_hint_field(S, sig, m, cnt)
    nonempty = [i for i in range(S.k) if cnt[i] > starts[i]]
    if total < S.omega and nonempty:  # repeat an index (same decoded hint set)
        i = rng.choice(nonempty)
        m = idx[:cnt[i]] + idx[cnt[i] - 1:cnt[i]] + idx[cnt[i]:S.omega - 1]
        c = bytearray(x + 1 if k >= i else x for k, x in enumerate(cnt))
        yield 'hint_repeated', with_hint_field(S, sig, m, c)
    if total < S.omega:  # non-zero padding byte
        m = idx[:]
        m[rng.randrange(total, S.omega)] = rng.randrange(1, 256)
        yield 'hint_padding', with_hint_field(S, sig, m, cnt)
    if total < S.omega:  # one count lower than its predecessor
        c = cnt[:]
        i = rng.randrange(1, S.k)
        c[i - 1] = c[i] + 1
        yield 'hint_count_decreasing', with_hint_field(S, sig, idx, c)
    c = cnt[:]
    c[-1] = S.omega + 1 + rng.randrange(255 - S.omega)
    yield 'hint_count_gt_omega', with_hint_field(S, sig, idx, c)


# ---------------------------------------------------------------------------

def gen_level(lvl, rng, n):
    S = tbvec.LEVELS[lvl]
    S.random_bytes = rng.randbytes
    keygen, siggen, sv = [], [], []
    zmax = S.gamma_1 - S.beta - 1

    for _ in range(n):
        seed = rng.randbytes(32)
        pk, sk = S.key_derive(seed)
        keygen.append(dict(seed=seed, pk=pk, sk=sk))

        msg, ctx = rand_msg_ctx(rng)
        sig = S.sign(sk, msg, ctx, deterministic=True)  # the HW signs with rnd = 0
        siggen.append(dict(sk=sk, message=msg, mlen=len(msg), ctx=ctx, ctxlen=len(ctx), signature=sig))

        msg, ctx = rand_msg_ctx(rng)
        sig = S.sign(sk, msg, ctx)
        sv.append(sigver(S, pk, msg, ctx, sig, 'valid', True))
        ct = S.c_tilde_bytes
        sv.append(sigver(S, pk, msg, ctx, flip_bit(rng, sig, 0, ct), 'tamper_ctilde', False))
        sv.append(sigver(S, pk, msg, ctx, flip_bit(rng, sig, ct, len(sig) - S.omega - S.k), 'tamper_z', False))
        sv.append(sigver(S, pk, flip_bit(rng, msg, 0, len(msg)), ctx, sig, 'tamper_msg', False))

        msg, ctx = rand_msg_ctx(rng)
        sig = sign_z_violation(S, sk, m_prime(msg, ctx), rng.randbytes(32))
        sv.append(sigver(S, pk, msg, ctx, sig, 'z_bound_real_key', False))

        # forged (t1 = 0) signatures isolating single checks
        for sign in (1, -1):
            for off, ok in ((0, True), (1, False)):
                z = rand_z(S, rng, zmax)
                z[rng.randrange(S.l)][rng.randrange(256)] = sign * (zmax + off)
                msg, ctx = rand_msg_ctx(rng)
                pk_f, sig = forge(S, rng, msg, ctx, z, rand_hints(S, rng, rng.randint(0, S.omega)))
                sv.append(sigver(S, pk_f, msg, ctx, sig, f'forged_z_{"+" if sign > 0 else "-"}gamma1-beta{"" if off else "-1"}', ok))
        z = rand_z(S, rng, zmax)
        z[rng.randrange(S.l)][rng.randrange(256)] = S.gamma_1
        msg, ctx = rand_msg_ctx(rng)
        pk_f, sig = forge(S, rng, msg, ctx, z, rand_hints(S, rng, 3))
        sv.append(sigver(S, pk_f, msg, ctx, sig, 'forged_z_gamma1', False))

        for name, hints in (('forged_zero_hints', rand_hints(S, rng, 0)),
                            ('forged_omega_hints', rand_hints(S, rng, S.omega)),
                            ('forged_last_poly_hints', rand_hints(S, rng, rng.randint(1, S.omega), [S.k - 1])),
                            ('forged_random_hints', rand_hints(S, rng, rng.randint(2, S.omega - 2)))):
            msg, ctx = rand_msg_ctx(rng)
            pk_f, sig = forge(S, rng, msg, ctx, rand_z(S, rng, zmax), hints)
            sv.append(sigver(S, pk_f, msg, ctx, sig, name, True))
            if name == 'forged_random_hints':
                for mname, msig in hint_mutations(S, rng, sig):
                    sv.append(sigver(S, pk_f, msg, ctx, msig, mname, False))
    return keygen, siggen, sv


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--out', required=True)
    ap.add_argument('--seed', type=int, default=0)
    ap.add_argument('--n', type=int, default=1, help='repetitions of every category per level')
    ap.add_argument('--levels', default='44,65,87')
    args = ap.parse_args()

    for lvl in map(int, args.levels.split(',')):
        rng = random.Random(f'{args.seed}-{lvl}')
        keygen, siggen, sv = gen_level(lvl, rng, args.n)
        tbvec.write(args.out, 'KeyGen', lvl, keygen)
        tbvec.write(args.out, 'SigGen', lvl, siggen)
        tbvec.write(args.out, 'SigVer', lvl, sv)
        with open(f'{args.out}/desc_{lvl}.txt', 'w') as f:
            f.write(''.join(f'{v["desc"]} {"reject" if v["result"] else "accept"}\n' for v in sv))
        print(f'ML-DSA-{lvl}: {len(keygen)} KeyGen, {len(siggen)} SigGen, {len(sv)} SigVer vectors')


if __name__ == '__main__':
    main()
