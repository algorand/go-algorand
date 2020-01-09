#!/usr/bin/env bash

# produce TEAL assembly for a periodic payment escrow (allow withdrawing 500000 microAlgos every 100 rounds)
algotmpl -d `git rev-parse --show-toplevel`/tools/teal/templates periodic-payment-escrow --dur 95 --amt 500000 --lease uFVDhjBpkpKQ8sZaau0qsDsf0eW3oXFEn1Ar5o39vkk= --period 100 --rcv SKXZDBHECM6AS73GVPGJHMIRDMJKEAN5TUGMUPSKJCQ44E6M6TC2H2UJ3I --fee 100000 --timeout 44000 > periodic.teal

# compile TEAL assembly to TEAL bytecode
goal clerk compile periodic.teal -o periodic.tealc
# > periodic.teal: NBH2CNQCPV7S2ZOSWVQ7JLFO7W5JERULPSGYUP4ZAEOLSVMTYODHVY37VQ

# initialize the escrow by sending 2000000 microAlgos into it
goal clerk send --from SKXZDBHECM6AS73GVPGJHMIRDMJKEAN5TUGMUPSKJCQ44E6M6TC2H2UJ3I --to NBH2CNQCPV7S2ZOSWVQ7JLFO7W5JERULPSGYUP4ZAEOLSVMTYODHVY37VQ --amount 2000000 -d .
# > Sent 2000000 MicroAlgos from account SKXZDBHECM6AS73GVPGJHMIRDMJKEAN5TUGMUPSKJCQ44E6M6TC2H2UJ3I to address NBH2CNQCPV7S2ZOSWVQ7JLFO7W5JERULPSGYUP4ZAEOLSVMTYODHVY37VQ, transaction ID: 2VC7ZSDULHFGWIMHW547MTRKG3ICT3XAEX2YASLBDCCI4D76GWQQ. Fee set to 1000
# > Transaction 2VC7ZSDULHFGWIMHW547MTRKG3ICT3XAEX2YASLBDCCI4D76GWQQ still pending as of round 43411
# > Transaction 2VC7ZSDULHFGWIMHW547MTRKG3ICT3XAEX2YASLBDCCI4D76GWQQ committed in round 43413

# take 500000 microAlgos out of the escrow. notice that the lease and first/last valid must satisfy the TEAL conditions
goal clerk send -a 500000 --to SKXZDBHECM6AS73GVPGJHMIRDMJKEAN5TUGMUPSKJCQ44E6M6TC2H2UJ3I --from-program periodic.teal -x uFVDhjBpkpKQ8sZaau0qsDsf0eW3oXFEn1Ar5o39vkk= --firstvalid 45000 --lastvalid 45095 -d .
# > Sent 500000 MicroAlgos from account NBH2CNQCPV7S2ZOSWVQ7JLFO7W5JERULPSGYUP4ZAEOLSVMTYODHVY37VQ to address SKXZDBHECM6AS73GVPGJHMIRDMJKEAN5TUGMUPSKJCQ44E6M6TC2H2UJ3I, transaction ID: RS7QPTG332HLVQ4K2HRDWICOZLKL7IAGMGFOYRKZD4QOXXBVC2RA. Fee set to 1000
# > Transaction RS7QPTG332HLVQ4K2HRDWICOZLKL7IAGMGFOYRKZD4QOXXBVC2RA still pending as of round 45050
# > Transaction RS7QPTG332HLVQ4K2HRDWICOZLKL7IAGMGFOYRKZD4QOXXBVC2RA committed in round 45052
