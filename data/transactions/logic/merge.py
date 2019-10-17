#!/usr/bin/env python

import re
import sys

import_re = re.compile(r'^@@\s+(\S+)\s+@@$')

out = sys.stdout

fin = open('README_in.md')
for line in fin:
    m = import_re.match(line)
    if m:
        with open(m.group(1), 'rt') as subf:
            out.write(subf.read())
        continue
    out.write(line)
