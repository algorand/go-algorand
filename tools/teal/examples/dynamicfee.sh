#!/usr/bin/env bash

# produce TEAL assembly for a delegated logic signature on a dynamic-fee transaction and compile it (note the required lease value)
algotmpl -d `git rev-parse --show-toplevel`/tools/teal/templates dynamic-fee --cls AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ --to NBH2CNQCPV7S2ZOSWVQ7JLFO7W5JERULPSGYUP4ZAEOLSVMTYODHVY37VQ --fv 170500 --lv 171500 --amt 100000 --lease uFVDhjBpkpKQ8sZaau0qsDsf0eW3oXFEn1Ar5o39vkk= > dynamic.teal
goal clerk compile -a EVADN3MAXLTUAZFLJNIN7RD7WCNEPTB37GJMD5OACMVBKTGFXYYFMS5IT4 -s -o dynamic.lsig dynamic.teal -d .

# make the main, unsigned transaction which executes the intended transfer
goal clerk send -o main.tx -f EVADN3MAXLTUAZFLJNIN7RD7WCNEPTB37GJMD5OACMVBKTGFXYYFMS5IT4 -a 100000 -t NBH2CNQCPV7S2ZOSWVQ7JLFO7W5JERULPSGYUP4ZAEOLSVMTYODHVY37VQ --firstvalid 170500 --lastvalid 171500 -x uFVDhjBpkpKQ8sZaau0qsDsf0eW3oXFEn1Ar5o39vkk= --fee 10000 -d .

# make the auxiliary transaction which reimburses the main transaction for its fee
goal clerk send -o aux.tx -f WO3QIJ6T4DZHBX5PWJH26JLHFSRT7W7M2DJOULPXDTUS6TUX7ZRIO4KDFY -a 10000 -t EVADN3MAXLTUAZFLJNIN7RD7WCNEPTB37GJMD5OACMVBKTGFXYYFMS5IT4 -d .

# group and re-split transactions in preparation for signing
cat main.tx aux.tx > testcmd.tx
goal clerk group -i testcmd.tx -o testgrp.tx
goal clerk split -i testgrp.tx -o testraw.tx
# > Wrote transaction 0 to testraw-0.tx
# > Wrote transaction 1 to testraw-1.tx

# sign the first transaction with the delegated logic signature (and the second transaction with the standard signature)
goal clerk sign -L dynamic.lsig -i testraw-0.tx -o testraw-0.stx -d .
goal clerk sign -i testraw-1.tx -o testraw-1.stx -d .
cat testraw-0.stx testraw-1.stx > testraw.stx

# send the group transaction to the network
goal clerk rawsend -f testraw.stx -d .
# > Raw transaction ID NHE46C543JICVB2ZJDJHZVUTPRVNLWVSRPYN55HF2MUSCKZXNUMQ issued
# > Raw transaction ID 6QRBT7IMSKAX47WDRFG37HLEFWYBE27LLFPDOJ2RJ7GIRY7XDT7A issued
# > Transaction NHE46C543JICVB2ZJDJHZVUTPRVNLWVSRPYN55HF2MUSCKZXNUMQ still pending as of round 171348
# > Transaction NHE46C543JICVB2ZJDJHZVUTPRVNLWVSRPYN55HF2MUSCKZXNUMQ committed in round 171350
# > Transaction 6QRBT7IMSKAX47WDRFG37HLEFWYBE27LLFPDOJ2RJ7GIRY7XDT7A committed in round 171350
