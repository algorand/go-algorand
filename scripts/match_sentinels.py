#!/usr/bin/env python3
"""
Match captured error messages against known sentinel definitions.
Output sites where ErrorIs could be used instead of ErrorContains.
"""

import json
import sys
from collections import defaultdict

def load_jsonl(path):
    """Load JSON lines file."""
    items = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))
    return items

def main():
    if len(sys.argv) < 3:
        print("Usage: match_sentinels.py <sentinels.jsonl> <error_sites.json>", file=sys.stderr)
        sys.exit(1)

    sentinels_path = sys.argv[1]
    error_sites_path = sys.argv[2]

    # Load sentinels and build message -> sentinel map
    sentinels = load_jsonl(sentinels_path)
    msg_to_sentinel = {}
    for s in sentinels:
        msg = s['msg']
        # Store sentinel info
        if msg not in msg_to_sentinel:
            msg_to_sentinel[msg] = []
        msg_to_sentinel[msg].append({
            'var': s['var'],
            'file': s['file'].lstrip('./'),
            'line': s['line']
        })

    print(f"Loaded {len(sentinels)} sentinels with {len(msg_to_sentinel)} unique messages", file=sys.stderr)

    # Load error sites
    with open(error_sites_path) as f:
        error_sites = json.load(f)

    print(f"Loaded {len(error_sites)} error sites", file=sys.stderr)

    # Find matches
    matches = []
    for site in error_sites:
        lcs = site.get('lcs', '')
        # Check for exact match against sentinel messages
        if lcs in msg_to_sentinel:
            for sentinel in msg_to_sentinel[lcs]:
                matches.append({
                    'test_file': site['file'],
                    'test_line': site['line'],
                    'error_msg': lcs,
                    'sentinel_var': sentinel['var'],
                    'sentinel_file': sentinel['file'],
                    'sentinel_line': sentinel['line'],
                    'recommendation': f"Use require.ErrorIs(t, err, {sentinel['var']}) instead of ErrorContains"
                })

    # Deduplicate and sort
    seen = set()
    unique_matches = []
    for m in matches:
        key = (m['test_file'], m['test_line'], m['sentinel_var'])
        if key not in seen:
            seen.add(key)
            unique_matches.append(m)

    unique_matches.sort(key=lambda x: (x['test_file'], x['test_line']))

    print(f"\nFound {len(unique_matches)} sites where ErrorIs could be used:\n", file=sys.stderr)

    # Output results
    for m in unique_matches:
        print(json.dumps(m))

if __name__ == '__main__':
    main()
