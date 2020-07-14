#!/usr/bin/env python3

# Computes a name to use to identify a current test run, based on timestamp:
# D[DD]HHMMSS
# Where D is # days since our epoch date of 5/25/2018 UTC
# and HH is the hour of the day, prefixed with '0' if < 10, MM and SS similarly.
# This mimics the BuildNumber so it can be correlated (ie this is [BuildNumber]MMSS)

from datetime import datetime
import time

epoch = datetime(2018, 5, 25, 0, 0, 0)
d1 = datetime.utcnow()
delta = d1 - epoch

print(f"{delta.days}{d1.hour}-{int(round(time.time() * 1000))}")
