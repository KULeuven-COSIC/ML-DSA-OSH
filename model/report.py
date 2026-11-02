#!/usr/bin/env python3
"""Map testbench failures back to vector descriptions.

    python3 model/report.py <sim.log> <vector_dir>

Uses tcid_<lvl>.txt (Wycheproof) or desc_<lvl>.txt (gen_vectors.py) from
vector_dir when present, and prints a per-category count of failures.
"""
import collections
import os
import re
import sys

NAMES = {'II': 44, 'III': 65, 'V': 87}


def main(log, vec_dir):
    labels = {}
    for lvl in NAMES.values():
        for name in (f'tcid_{lvl}.txt', f'desc_{lvl}.txt'):
            path = os.path.join(vec_dir, name)
            if os.path.exists(path):
                with open(path) as f:
                    labels[lvl] = f.read().splitlines()
    seen, summary = set(), collections.Counter()
    for m in re.finditer(r'\[ML-DSA-(\w+)\.(\w+), KAT #\s*(\d+)[\],]', open(log).read()):
        lvl, op, i = NAMES[m.group(1)], m.group(2), int(m.group(3))
        if (lvl, op, i) in seen:
            continue
        seen.add((lvl, op, i))
        label = labels[lvl][i] if lvl in labels and op == 'Verify' else ''
        print(f'ML-DSA-{lvl} {op} #{i}: {label}')
        summary[(lvl, op, label.split()[-1] if label else '')] += 1
    if summary:
        print('\nfailures per category:')
        for (lvl, op, cat), n in sorted(summary.items()):
            print(f'  ML-DSA-{lvl} {op} {cat}: {n}')


if __name__ == '__main__':
    main(*sys.argv[1:3])
