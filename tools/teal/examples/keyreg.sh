#!/usr/bin/env bash

# generate the delegate key
dkeygen > delegate.keyregkey
# > QY5UZGE746YGIEQ66UPPWO4Z55SJEZLZJDEXSN6RAHXWYIDTO4KA5RHZUQ

# create and sign delegate logic enabling the delegation of key registration authority to delegate.keyregkey
algotmpl -d `git rev-parse --show-toplevel`/tools/teal/templates delegate-key-registration --fee 100000 --dur 95 --period 100 --expire 10000 --auth QY5UZGE746YGIEQ66UPPWO4Z55SJEZLZJDEXSN6RAHXWYIDTO4KA5RHZUQ --lease uFVDhjBpkpKQ8sZaau0qsDsf0eW3oXFEn1Ar5o39vkk= > delegate.teal
goal clerk compile -a CI3OPSTHUPJNOYDN2EAQDAOVYZNQNJNS5QJD7WGHCX4O6SZAG7EP4TNMC4 -s -o kr.lsig delegate.teal -d .
# at this point, kr.lsig and delegate.keyregkey may act in place of the rootkey for issuing key registration transactions, and the rootkey may be kept offline

# generate participation keys
goal account addpartkey -a CI3OPSTHUPJNOYDN2EAQDAOVYZNQNJNS5QJD7WGHCX4O6SZAG7EP4TNMC4 -d . --roundFirstValid 0 --roundLastValid 100000
# > Participation key generation successful

# create the keyreg transaction and sign it with the delegate logic, along with the key
goal account changeonlinestatus -a CI3OPSTHUPJNOYDN2EAQDAOVYZNQNJNS5QJD7WGHCX4O6SZAG7EP4TNMC4 -x uFVDhjBpkpKQ8sZaau0qsDsf0eW3oXFEn1Ar5o39vkk= --online --firstRound 2600 --validRounds 95 --txfile keyreg.tx -d .
cat keyreg.tx | dsign delegate.keyregkey kr.lsig > keyreg.stx

# send the keyreg transaction to the network
goal clerk rawsend -f keyreg.stx -d .
