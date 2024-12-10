#!/usr/bin/python3
#
# Copyright (C) 2019-2024 Algorand, Inc.
# This file is part of go-algorand
#
# go-algorand is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# go-algorand is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.
#

# This script parses the output of a Go test run and reports any tests that have not completed.
# Usage examples:
# go test ./data/ -run TestTxHandler -v --timeout 5s | python3 test/scripts/go-hanging-test.py -t 5 -
# go test ./data/ -run TestTxHandler -v --timeout 5s > tests.txt && python3 test/scripts/go-hanging-test.py tests.txt

import argparse
import time
import re
import select
import sys

def parse_go_test_output(test_output):
    # Dictionary to track the status of each test
    tests = {}

    # Regular expressions to match RUN, PASS, FAIL, etc.
    run_pattern = re.compile(r"^\s*=== RUN\s+(\S+)")
    pass_pattern = re.compile(r"^\s*--- (PASS|FAIL|SKIP):\s+(\S+)")

    # Process each line in the test output
    for line in test_output.splitlines():
        # Check for a test being started
        run_match = run_pattern.match(line)
        if run_match:
            test_name = run_match.group(1)
            tests[test_name] = 'RUN'

        # Check for a test being completed (PASS, FAIL, SKIP)
        pass_match = pass_pattern.match(line)
        if pass_match:
            test_status = pass_match.group(1)
            test_name = pass_match.group(2)
            tests[test_name] = test_status

    # Find tests that are RUN but not completed
    incomplete_tests = [test for test, status in tests.items() if status == 'RUN']

    return incomplete_tests

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("test_output", help="The output of a Go test run")
    ap.add_argument("-t", "--timeout", type=int, default=10, help="Wait for stdin for timeout seconds")
    args = ap.parse_args()

    if args.test_output == "-":
        # Read test output from stdin up to args.timeout seconds
        test_output = ""
        start_time = time.time()
        while True:
            elapsed_time = time.time() - start_time

            # Check if 5 seconds have passed
            if elapsed_time > args.timeout:
                print(f"Timed out after {args.timeout} seconds")
                break

            # Use select to check if stdin has data available
            ready_to_read, _, _ = select.select([sys.stdin], [], [], 1)
            if ready_to_read:
                line = sys.stdin.readline()
                if line:
                    test_output += line
    else:
        with open(args.test_output, "rt", encoding="utf8") as f:
            test_output = f.read()

    incomplete_tests = parse_go_test_output(test_output)
    if incomplete_tests:
        print("Tests that have not completed:")
        for test in incomplete_tests:
            print(test)
    else:
        print("All tests have completed.")


if __name__ == "__main__":
    main()
