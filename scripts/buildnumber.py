#!/usr/bin/env python3

# Computes a build number that is:
# D[DD]HH
# Where D is # days since our epoch date of 5/25/2018 UTC
# and HH is the hour of the day, prefixed with '0' if < 10
# e.g. if NOW is 5/28/2018 5:30am
#   => 305

from datetime import datetime

epoch = datetime(2018, 5, 25, 0, 0, 0)
d1 = datetime.utcnow()
delta = d1 - epoch
print("%d%02d" % (delta.days, d1.hour))
