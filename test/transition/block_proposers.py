import json
import os

import algosdk
import algosdk.v2client

def token_addr_from_algod(algorand_data):
    if algorand_data and algorand_data.startswith('~'):
        algorand_data = os.path.expanduser(algorand_data)
    algorand_data = os.path.normpath(os.path.abspath(algorand_data))
    addr = open(os.path.join(algorand_data, 'algod.net'), 'rt').read().strip()
    if not addr.startswith('http'):
        addr = 'http://' + addr
    token = open(os.path.join(algorand_data, 'algod.token'), 'rt').read().strip()
    return token, addr

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('algorand_data')
    args = ap.parse_args()

    token,addr = token_addr_from_algod(args.algorand_data)
    algod = algosdk.v2client.algod.AlgodClient(token, addr)
    b2b = algod.block_info(3, response_format='msgpack')
    oprops = {}
    for i in range(1,2000):
        try:
            b2b = algod.block_info(i, response_format='msgpack')
            b2 = algosdk.encoding.msgpack.unpackb(b2b)
            oprop = b2['cert']['prop']['oprop']
            oprops[oprop] = oprops.get(oprop, 0) + 1
        except Exception as e:
            print(e)
            break
    for op,count in oprops.items():
        print('{}\t{}'.format(algosdk.encoding.encode_address(op), count))

if __name__ == '__main__':
    main()
