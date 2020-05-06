#!/usr/bin/env python3

import json
import sys

ob = json.load(sys.stdin)
json.dump(ob, sys.stdout, indent=2, sort_keys=True)
