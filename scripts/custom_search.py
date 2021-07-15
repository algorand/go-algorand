#!/usr/bin/env python3
# Script that looks for a line without given string immediately following a line containing another given string
# Known caveats: only looks at next line after line containing 'func Test', probably need to look through whole function

import os
import sys
import time
import re
start_time = time.time()

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--path', default='../', help='Path to search for files (includes subfolders, default="../")')
    ap.add_argument('--file-suffix', default='_test.go', help='checks only files with this suffix (default="_test.go")')
    ap.add_argument('--search-string-one', default=r'func\s+\w+\s*\(.*t\s+\*testing\.T.*\)\s*{\s*\n', help=r'searches for line with this regex string first (default="func\s+\w+\s*\(.*t\s+\*testing\.T.*\)\s*{\s*\n')
    ap.add_argument('--search-string-two', default='testpartitioning.PartitionTest(t)', help='searches for second line without this second string (default="testpartitioning.PartitionTest(t)")')
    args = ap.parse_args()

    regex_object = re.compile(args.search_string_one, re.IGNORECASE)

    # Iterate through all files in a given dir and all of it's subdirs
    total_results_found = 0
    for subdir, dirs, files in os.walk(args.path):
        for file in files:
            if file.endswith(args.file_suffix):
                filepath = subdir + os.sep + file
                total_results_found += check_file_for_missing_search_string(filepath, regex_object, args.search_string_two)
    print("==============================")
    print("Finished running parser in {} seconds".format(round(time.time() - start_time, 2)))
    print("{} total things found".format(total_results_found))

def check_file_for_missing_search_string(filepath, regex_object, search_string_two):
    results_found = 0
    with open(filepath, 'r') as openfile:
        found_first_line = False
        for index, line in enumerate(openfile):
            # If previous line had search_string_one
            if found_first_line:
                if search_string_two not in line:
                    print("WARNING: Line {} in file {} is missing '{}' in '{}'".format(index+1, filepath, search_string_two, found_first_line.strip()))
                    results_found += 1
                found_first_line = False

            # If current line has search_string_one
            elif regex_object.match(line):
                found_first_line = line
    return results_found

if __name__ == '__main__':
    main()
