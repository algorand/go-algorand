#!/usr/bin/env python3
#
# this is the script that runs on a node host started by runNodeHost.py
#
# takes one argument which is base64 encoded json
#
# args = {
#   'phonebook': 'host:port;...',
#   'npn': {'count': int},
#   'relay': {'count': int},
#   'pnode': {'count': int, 'keys':[...]},
# }

import base64
import glob
import json
import logging
import os
import shutil
import subprocess
import sys
import time

logger = logging.getLogger(__name__)

def run(args):
    subprocess.run(args).check_returncode()

def setupDataPaths():
    mr = subprocess.run(['mount'], capture_output=True)
    mr.check_returncode()
    mounts = mr.stdout.decode()
    paths = []
    datai = 0
    for nvmelink in glob.glob('/dev/disk/by-id/nvme-Amazon_EC2_NVMe_Instance_Storage*'):
        devname = os.path.realpath(nvmelink)
        if devname in mounts:
            continue
        run(['sudo', 'mkfs.ext4', devname])
        while True:
            datapath = '/data{}'.format(datai)
            if not os.path.exists(datapath):
                break
            else:
                paths.append(datapath)
            datai += 1
        run(['sudo', 'mkdir', datapath])
        run(['sudo', 'mount', devname, datapath])
        run(['sudo', 'chown', '{}:{}'.format(os.geteuid(), os.getegid()), datapath])
        # TODO: write to /etc/fstab?
        paths.append(datapath)

    while True:
        datapath = '/data{}'.format(datai)
        if not os.path.exists(datapath):
            break
        else:
            paths.append(datapath)
        datai += 1

    if not paths:
        paths = glob.glob('data?')
    if not paths:
        datapath = 'data0'
        os.mkdir(datapath)
        paths = [datapath]
    return paths

# must be the same as runNodeHost.py
target_tarfile = 'runNodeHostPackage.tar.gz'

def main():
    logging.basicConfig(filename='run.log', level=logging.DEBUG)
    args = json.loads(base64.b64decode(sys.argv[1]))
    logger.info('args: %s', json.dumps(args, indent=2))
    phonebook = args.get('phonebook')
    datapaths = setupDataPaths()
    algod = os.path.realpath('algod')
    algokey = os.path.realpath('algokey')
    goal = os.path.realpath('goal')
    if not os.access(algod, os.X_OK):
        sys.stderr.write('{}: not executable\n'.format(algod))
        return 1
    genesis = os.path.realpath('genesis.json')
    if not os.path.exists(genesis):
        sys.stderr.write('missing {}'.format(genesis))
        return 1
    processes = []
    npn = args.get('npn')
    if npn:
        for i in range(npn.get('count',0)):
            name = 'npn{}'.format(i)
            dp = datapaths[i % len(datapaths)]
            datadir = os.path.join(dp, name)
            os.makedirs(datadir, exist_ok=True)
            shutil.copyfile('genesis.json', os.path.join(datadir, 'genesis.json'))
            with open(os.path.join(datadir, 'config.json'), 'wt') as fout:
                json.dump({'Version':16, 'GossipFanout':1, 'DNSBootstrapID':'', 'EnableProfiler':True, 'IncomingConnectionsLimit':0}, fout)
            cmd = [algod, '-g', genesis, '-d', datadir]
            if phonebook:
                cmd += ['-p', phonebook]
            algod_out = open(os.path.join(datadir, 'algod_out'), 'at')
            algod_err = open(os.path.join(datadir, 'algod_err'), 'at')
            proc = subprocess.Popen(cmd, cwd=datadir, stdout=algod_out, stderr=algod_err)
            algod_out.close()
            algod_err.close()
            processes.append(proc)

    # build participating nodes
    partargs = args.get('part')
    if partargs:
        ip = 0
        for privkey_b64, addr_b32 in partargs.get('keys'):
            ip += 1
            name = 'pn{}'.format(ip)
            dp = datapaths[ip % len(datapaths)]
            datadir = os.path.join(dp, name)
            os.makedirs(datadir, exist_ok=True)
            shutil.copyfile('genesis.json', os.path.join(datadir, 'genesis.json'))
            with open(os.path.join(datadir, 'config.json'), 'wt') as fout:
                json.dump({'Version':16, 'GossipFanout':1, 'DNSBootstrapID':'', 'EnableProfiler':True, 'IncomingConnectionsLimit':0}, fout)
            cmd = [algod, '-g', genesis, '-d', datadir]
            if phonebook:
                cmd += ['-p', phonebook]
            algod_out = open(os.path.join(datadir, 'algod_out'), 'at')
            algod_err = open(os.path.join(datadir, 'algod_err'), 'at')
            proc = subprocess.Popen(cmd, cwd=datadir, stdout=algod_out, stderr=algod_err)
            algod_out.close()
            algod_err.close()
            processes.append(proc)

            # wait for `goal node status` to show 'Sync Time: 0.0s' when catchup is done
            while True:
                time.sleep(5)
                status = subprocess.run([goal, '-d', datadir, 'node', 'status'], capture_output=True)
                status.check_returncode()
                if 'Sync Time: 0.0s' in status.stdout.decode():
                    break

            partkeypath = os.path.join(datadir, 'in.partkey')
            subprocess.run([algokey, 'part', 'generate', '--first', '0', '--last', '300000', '--keyfile', partkeypath, '--parent', addr_b32]).check_returncode()
            subprocess.run([goal, '-d', datadir, 'account', 'installpartkey', '--delete-input', '--partkey', partkeypath]).check_returncode()
            online_txn = os.path.join(datadir, 'online.txn')
            online_stxn = os.path.join(datadir, 'online.stxn')
            subprocess.run([goal, '-d', datadir, 'account', 'changeonlinestatus', '-a', addr_b32, '--online', '-t', online_txn]).check_returncode()
            pk_path = os.path.join(datadir, 'pk.pk')
            priv_pub = base64.b64decode(privkey_b64)
            priv = priv_pub[:32]
            with open(pk_path, 'wb') as fout:
                fout.write(priv)
            subprocess.run([algokey, 'sign', '-k', pk_path, '-t', online_txn, '-o', online_stxn]).check_returncode()
            subprocess.run([goal, '-d', datadir, 'clerk', 'rawsend', '-f', online_stxn]).check_returncode()


    # TODO: run relays and participating nodes
    return 0

if __name__ == '__main__':
    sys.exit(main())
