# LogicSig

An Algorand transaction may be signed one of three ways:

- by one signature corresponding to the public key that is the Sender address
- by several signatures that are components of a MultiSig address
- by a program that is part of a LogicSig data structure

Standard accounts and MultiSig accounts are covered elsewhere.

LogicSig has four parts:

- Logic: raw program bytes (required)
- Sig: an optional signature of the program bytes
- Msig: an optional MultiSig signature of the program bytes
- Args: an optional array of byte strings the program can use

A LogicSig is valid if one of the following is true:

- Sig is a valid signature of the program by the Sender
- Msig is a valid MultiSig signature of the program by the Sender
- The hash of the program is equal to the Sender address

The first two cases are examples of _delegation_. An account owner can declare that on their behalf the signed logic can authorize transactions. The simplest program might be `int 1` which is effectively `return true`. If an account owner Bob signed this program with their key, anyone with that bit of signed logic could apply it to validate any transaction on behalf of Bob (don't do this). A better program might be "allow a transfer to Alice 100 Algos next Thursday between 18:00 and 19:00 if she presents a secret key".

The third case is an account wholly governed by the program. The program cannot be changed. Once assets have been sent to that account, assets only come out when there is a transaction that approves it. If the account is the hash of the program `int 0` (aka, `return false`), all transactions are rejected and nothing can be gotten out (until someone brute-forces the public key of that account which is considered infeasible). If the account is the hash of the program `int 1` any transaction is approved. In between are a wide variety of checks and contracts possible.

Accounts wholly governed by programs are the root of **escrow accounts**. If two parties share the program source, they can hash it and verify the address of the account governed by the program. Checking the publicly known balance on that account and the logic governing the release of those assets is a key feature of many contracts. A common pattern is the 'time locked hash contract', e.g. "Alice puts 100 Algos into the account and gets it back after some timeout unless Bob claims it by supplying some secret key". Templates for this sort of contract and others are available.


# Tools

Compile with no output, report the address of the program

```
goal clerk compile -n tlhc.teal
```

Compile and write raw program bytecode to file

```
goal clerk compile  tlhc.teal -o /tmp/tlhc.tealc
```

Disassemble raw program bytes file

```
goal clerk compile -D /tmp/tlhc.tealc
```

produces LogicSig signed by default account

```
goal clerk compile  tlhc.teal -o /tmp/tlhc.lsig -s
```

produces LogicSig signed by addr of `-a addr`

```
goal clerk compile  tlhc.teal -o /tmp/tlhc.lsig -s -a LSJY4JD5J626BMJY2NMODBP64WDQP5OS4M6YF2F5BWQUS22I3YJYCXHHIA
```

Disassemble a LogicSig

```
goal clerk compile -D /tmp/tlhc.lsig
```

Unlock a hash contract, send from the escrow account governed by the program. To and CloseRemainderTo must be same (as per program logic), --argb64 unlocks the hash contract

```
goal clerk send -a 1000 -c DFPKC2SJP3OTFVJFMCD356YB7BOT4SJZTGWLIPPFEWL3ZABUFLTOY6ILYE --to DFPKC2SJP3OTFVJFMCD356YB7BOT4SJZTGWLIPPFEWL3ZABUFLTOY6ILYE --from-program tlhc.teal --argb64 "90GwXNJlVYGvgNwUl9eIUW21E/5vRu9/uqaCkw67sQk="
```

Debug a transaction with logic:

```
goal clerk send -a 1000 -c DFPKC2SJP3OTFVJFMCD356YB7BOT4SJZTGWLIPPFEWL3ZABUFLTOY6ILYE --to DFPKC2SJP3OTFVJFMCD356YB7BOT4SJZTGWLIPPFEWL3ZABUFLTOY6ILYE --from-program tlhc.teal --argb64 "90GwXNJlVYGvgNwUl9eIUW21E/5vRu9/uqaCkw67sQk=" -o /tmp/a.stxn
goal clerk dryrun -t /tmp/a.stxn
```

## LogicSic signed by a MultiSig account

For some multisig account, 2 of 3:

```
goal account multisig new -T 2 DFPKC2SJP3OTFVJFMCD356YB7BOT4SJZTGWLIPPFEWL3ZABUFLTOY6ILYE LSJY4JD5J626BMJY2NMODBP64WDQP5OS4M6YF2F5BWQUS22I3YJYCXHHIA YYKRMERAFXMXCDWMBNR6BUUWQXDCUR53FPUGXLUYS7VNASRTJW2ENQ7BMQ
```

Create an lsig with the first signature, add more signatures to it. `-A` is the multisig address, `-a` is the sub-key adding its signature. After the lsig file is created the multisig address is built into it and doesn't need to be specified.

```
goal clerk multisig signprogram -p ~/Documents/tlhc.teal -a YYKRMERAFXMXCDWMBNR6BUUWQXDCUR53FPUGXLUYS7VNASRTJW2ENQ7BMQ -A 5DLEJBZHDG4XTIILEEJ6HSLG2YFGHNDAKIUAFASMFV234CJGEDQYMJ6LMI -o /tmp/tlhca.lsig
goal clerk multisig signprogram -L /tmp/tlhca.lsig -a LSJY4JD5J626BMJY2NMODBP64WDQP5OS4M6YF2F5BWQUS22I3YJYCXHHIA -A 5DLEJBZHDG4XTIILEEJ6HSLG2YFGHNDAKIUAFASMFV234CJGEDQYMJ6LMI
goal clerk multisig signprogram -L /tmp/tlhca.lsig -a DFPKC2SJP3OTFVJFMCD356YB7BOT4SJZTGWLIPPFEWL3ZABUFLTOY6ILYE
```

## Signing logic, applying it

Compile a program, sign it, create a LogicSig file

```
goal clerk compile -a DFPKC2SJP3OTFVJFMCD356YB7BOT4SJZTGWLIPPFEWL3ZABUFLTOY6ILYE -s -o /tmp/p3.lsig program.teal
```

Create a transaction to a file, with the signing account as Sender

```
goal clerk send -o /tmp/tx4 -f DFPKC2SJP3OTFVJFMCD356YB7BOT4SJZTGWLIPPFEWL3ZABUFLTOY6ILYE -a 1000 -t WNZPUHLHS2JGC7LDYUSX2ZDXS7RF37Y7ZNRAHSFRS6MO63JF3S3M27YR7U
```

Apply the logic sig to the transaction, supply arguments. The finished signed transaction can then be sent with `goal clerk rawsend`

```
goal clerk sign -L /tmp/p3.lsig -i /tmp/tx4 -o /tmp/tx4ls --argb64 AA== --argb64 BA== --argb64 CA==
```

Create/send a transaction signed by a LogicSig in one step:

```
goal clerk send -o /tmp/tx4 -f DFPKC2SJP3OTFVJFMCD356YB7BOT4SJZTGWLIPPFEWL3ZABUFLTOY6ILYE -a 1000 -t WNZPUHLHS2JGC7LDYUSX2ZDXS7RF37Y7ZNRAHSFRS6MO63JF3S3M27YR7U -L /tmp/p3.lsig
```
