#!/usr/bin/env bash

# produce TEAL assembly for a split payment escrow (send to two accounts in a 30/70 split)
algotmpl -d `git rev-parse --show-toplevel`/tools/teal/templates split --rat1 30 --rat2 70 --timeout 60000 --own WO3QIJ6T4DZHBX5PWJH26JLHFSRT7W7M2DJOULPXDTUS6TUX7ZRIO4KDFY --rcv1 W6UUUSEAOGLBHT7VFT4H2SDATKKSG6ZBUIJXTZMSLW36YS44FRP5NVAU7U --rcv2 XCIBIN7RT4ZXGBMVAMU3QS6L5EKB7XGROC5EPCNHHYXUIBAA5Q6C5Y7NEU --minpay 100000 --fee 20000 > split.teal

# compile TEAL assembly to TEAL bytecode
goal clerk compile split.teal
# > split.teal: FNXTOGESLM5QZZMKCN4I44E7GOFQGWQSP56YAFZNTEP2GE25WPDMM5LOJU

# initialize the escrow by sending 10000000 microAlgos into it
goal clerk send --from WO3QIJ6T4DZHBX5PWJH26JLHFSRT7W7M2DJOULPXDTUS6TUX7ZRIO4KDFY --to FNXTOGESLM5QZZMKCN4I44E7GOFQGWQSP56YAFZNTEP2GE25WPDMM5LOJU --amount 10000000 -d .
# > Sent 10000000 MicroAlgos from account WO3QIJ6T4DZHBX5PWJH26JLHFSRT7W7M2DJOULPXDTUS6TUX7ZRIO4KDFY to address FNXTOGESLM5QZZMKCN4I44E7GOFQGWQSP56YAFZNTEP2GE25WPDMM5LOJU, transaction ID: IY4DXO6R2KEALAZCQSE2DSLVVHP6MA727KABYZRFK54R52JRV2NQ. Fee set to 1000
# > Transaction IY4DXO6R2KEALAZCQSE2DSLVVHP6MA727KABYZRFK54R52JRV2NQ still pending as of round 83922
# > Transaction IY4DXO6R2KEALAZCQSE2DSLVVHP6MA727KABYZRFK54R52JRV2NQ committed in round 83924

# build the group transaction that sends the money in a 30/70 split
goal clerk send --from-program split.teal --to W6UUUSEAOGLBHT7VFT4H2SDATKKSG6ZBUIJXTZMSLW36YS44FRP5NVAU7U  --amount 300000  -d . -o test.tx
goal clerk send --from-program split.teal --to XCIBIN7RT4ZXGBMVAMU3QS6L5EKB7XGROC5EPCNHHYXUIBAA5Q6C5Y7NEU  --amount 700000  -d . -o test2.tx
cat test.tx test2.tx > testcmb.tx
goal clerk group -i testcmb.tx -o testgrp.tx

# send the group transaction to the network
goal clerk rawsend -f testgrp.tx -d .
# > Raw transaction ID D4XU5EZQSVUIA577R7JIRZ5RYW75KAYFRCFV4X3Q7WP2KWYOFDAQ issued
# > Raw transaction ID EUSYB64VTZCMON7QOG22CZVNIZFZQF6SROO4M4AUXV2JIVJ4HZ4A issued
# > Transaction D4XU5EZQSVUIA577R7JIRZ5RYW75KAYFRCFV4X3Q7WP2KWYOFDAQ still pending as of round 83929
# > Transaction D4XU5EZQSVUIA577R7JIRZ5RYW75KAYFRCFV4X3Q7WP2KWYOFDAQ committed in round 83931
# > Transaction EUSYB64VTZCMON7QOG22CZVNIZFZQF6SROO4M4AUXV2JIVJ4HZ4A committed in round 83931
