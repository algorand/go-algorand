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