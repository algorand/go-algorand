#!/usr/bin/env python3

import argparse
import base64
import hashlib
import os
import sys

template = '''txn CloseRemainderTo
addr {to}
==
txn Receiver
addr {to}
==
&&
arg 0
len
int 32
==
&&
arg 0
{hashop}
byte base64 {hash_secret}
==
&&
txn CloseRemainderTo
addr {sender}
==
txn Receiver
addr {sender}
==
&&
txn FirstValid
int {timeout_round}
>
&&
||
txn Fee
int 1000000
<
&&'''

def tlhc(sender, to, timeout_round, hash_secret, hashop='sha256'):
    if isinstance(hash_secret, bytes):
        hash_secret = base64.b64encode(hash_secret).decode()
    return template.format(sender=sender, to=to, timeout_round=timeout_round, hashop=hashop, hash_secret=hash_secret)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-f', '--from', dest='sender', required=True)
    ap.add_argument('-t', '--to', required=True)
    ap.add_argument('-r', '--timeout-round', type=int, required=True)
    ap.add_argument('-H', '--hash', dest='hashop', choices=('sha256','keccack256'), default='sha256')
    ap.add_argument('-o', '--out', default=None, help='file to write teal script source to. default stdout')
    ap.add_argument('-s', '--secret', default=None, help='file to write secret comment to. default stderr')
    args = ap.parse_args()

    secret = os.urandom(32)
    hasher = hashlib.new(args.hashop)
    hasher.update(secret)
    code = tlhc(sender=args.sender, to=args.to, timeout_round=args.timeout_round, hash_secret=hasher.digest(), hashop=args.hashop)
    secretout = sys.stderr
    if args.secret:
        secretout = open(args.secret, 'wt')
    out = sys.stdout
    if args.out:
        out = open(args.out, 'wt')
    secretout.write('// secret base64 {} hex {}\n'.format(base64.b64encode(secret).decode(), base64.b16encode(secret).decode()))
    out.write(code)
    try:
        out.close()
    except Exception as e:
        print(e)
    try:
        secretout.close()
    except Exception as e:
        print(e)
    return

if __name__ == '__main__':
    main()
