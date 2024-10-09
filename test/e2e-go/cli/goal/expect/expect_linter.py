#!/usr/bin/env python
import sys
import argparse

found_issues = False


def check_expect_blocks(filename, verbose=False):
    with open(filename, 'r') as f:
        lines = f.readlines()

    in_expect_block = False
    brace_count = 0
    block_start_line = None
    current_block = []
    expect_blocks = []

    # Process each line, considering possible strings or comments
    for line_num, line in enumerate(lines, start=1):
        stripped_line = line.strip()

        if not in_expect_block:
            if "expect " in stripped_line and '{' in stripped_line:
                in_expect_block = True
                block_start_line = line_num
                brace_count = stripped_line.count('{') - stripped_line.count('}')
                current_block = [stripped_line]
            elif stripped_line.startswith("#") or stripped_line.startswith("//"):
                continue  # Ignore comment lines outside of expect blocks
        else:
            current_block.append(stripped_line)
            brace_count += stripped_line.count('{') - stripped_line.count('}')

            if brace_count == 0:
                in_expect_block = False
                expect_blocks.append((block_start_line, "\n".join(current_block)))
                current_block = []

    for block_start_line, block in expect_blocks:
        if '#nolint:eof' in block:
            if verbose:
                print(f"{filename}:{block_start_line}: SKIP: 'nolint:eof' comment found, skipping")
            continue

        if 'eof ' not in block:
            # Check for only timeout condition
            actions = block.count('}')
            if block.count('timeout') == actions:
                if verbose:
                    print(f"{filename}:{block_start_line}: OK: only timeout action present")
                continue

            print(f"{filename}:{block_start_line}: Warning: missing 'eof' in expect block")
            global found_issues
            found_issues = True
        elif verbose:
            print(f"{filename}:{block_start_line}: OK: expect block contains 'eof'")

def main():
    parser = argparse.ArgumentParser(description="Check for 'eof' in expect blocks of scripts.")
    parser.add_argument('files', metavar='FILE', type=str, nargs='+', help='Files to check')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    for fname in args.files:
        check_expect_blocks(fname, args.verbose)

    if found_issues:
        sys.exit(1)

if __name__ == "__main__":
    main()
