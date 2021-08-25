#!/usr/bin/python3
#
# launch an ec2 instance in the same AZ with the same AMI, run some algod on it
#
# pip install -y boto3

import argparse
import base64
import glob
import json
import logging
import os
import random
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request

# pip install py-algorand-sdk
import algosdk
import algosdk.v2client
import boto3

logger = logging.getLogger(__name__)

# http://169.254.169.254/latest/meta-data/placement/availability-zone
# http://169.254.169.254/latest/meta-data/ami-id
# http://169.254.169.254/latest/meta-data/public-ipv4
# http://169.254.169.254/latest/meta-data/public-hostname
# http://169.254.169.254/latest/meta-data/local-ipv4
# http://169.254.169.254/latest/meta-data/local-hostname

def newerthan(a, b):
    if not os.path.exists(b):
        return True
    return os.path.getmtime(a) > os.path.getmtime(b)

def needsmake(dest, *args):
    for a in args:
        if newerthan(a, dest):
            return True

def tarinfo_about_file(name, path):
    ti = tarfile.TarInfo(name)
    fs = os.stat(path)
    ti.size = fs.st_size
    ti.mtime = fs.st_mtime
    ti.mode = fs.st_mode
    ti.type = tarinfo.REGTYPE

# must be the same as nodeHostTarget.py
target_tarfile = 'runNodeHostPackage.tar.gz'

# deploy file runNodeHostPackage.tar.gz contains:
# ./algod
# ./algokey
# ./goal
# ./genesis.json
# ./nodeHostTarget.py
def ensure_tarfile(algod_data):
    algod_bin = shutil.which('algod')
    algokey_bin = shutil.which('algokey')
    goal_bin = shutil.which('goal')
    genesis_json = os.path.join(algod_data, 'genesis.json')
    target_script = os.path.join(os.path.dirname(__file__), 'nodeHostTarget.py')
    if not needsmake(target_tarfile, algod_bin, goal_bin, genesis_json, target_script):
        return
    out = tarfile.open(target_tarfile, 'w:gz')
    def addfile(name, path):
        ti = out.gettarinfo(path, arcname=name)
        out.addfile(
            ti, #tarinfo_about_file(name, path),
            open(path, 'rb'),
        )
    addfile('algod', algod_bin)
    addfile('algokey', algokey_bin)
    addfile('goal', goal_bin)
    addfile('genesis.json', genesis_json)
    addfile('nodeHostTarget.py', target_script)
    out.close()

def start_remote(args, user, ipaddr, argsb64):
    sshargs = ['-o', 'StrictHostKeyChecking=no']
    if args.i:
        sshargs += ['-i', args.i]
    userataddr = user + '@' + ipaddr
    subprocess.run(['scp'] + sshargs + [target_tarfile, '{}:~/'.format(userataddr)]).check_returncode()
    subprocess.run(['ssh'] + sshargs + [userataddr, 'tar -z -x -f ' + target_tarfile]).check_returncode()
    subprocess.run(['ssh'] + sshargs + [userataddr, 'nohup python3 nodeHostTarget.py {} > outerr 2>&1 &'.format(argsb64)]).check_returncode()

# do a simple GET of a text/plain response
def httpget(url):
    with urllib.request.urlopen(url) as res:
        return res.read().decode().strip()

_instance_data_path = '.instances.json'

def loadInstancesJson():
    if os.path.exists(_instance_data_path):
        with open(_instance_data_path) as fin:
            return json.load(fin)
    return {}

def saveInstancesJson(ob):
    with open(_instance_data_path, 'wt') as fout:
        json.dump(ob, fout)

# record the instances we have launched so that we can clean them up later.
def recordInstanceID(instanceID, ipaddr, extra=None, **kwargs):
    ob = loadInstancesJson()
    instances = ob.get('instances')
    if instances and instanceID in instances:
        return
    rec = {'a':ipaddr}
    if extra is not None:
        rec.update(extra)
    if kwargs:
        rec.update(kwargs)
    if not instances:
        instances = {instanceID:rec}
    else:
        instances[instanceID] = rec
    ob['instances'] = instances
    saveInstancesJson(ob)

def openkmd(algodata):
    kmdnetpath = sorted(glob.glob(os.path.join(algodata,'kmd-*','kmd.net')))[-1]
    kmdnet = open(kmdnetpath, 'rt').read().strip()
    kmdtokenpath = sorted(glob.glob(os.path.join(algodata,'kmd-*','kmd.token')))[-1]
    kmdtoken = open(kmdtokenpath, 'rt').read().strip()
    logger.debug('found kmd %s %s', kmdnet, kmdtoken)
    kmd = algosdk.kmd.KMDClient(kmdtoken, 'http://' + kmdnet)
    return kmd

def openalgod(algodata):
    algodnetpath = os.path.join(algodata,'algod.net')
    algodnet = open(algodnetpath, 'rt').read().strip()
    algodtokenpath = os.path.join(algodata,'algod.token')
    algodtoken = open(algodtokenpath, 'rt').read().strip()
    algod = algosdk.v2client.algod.AlgodClient(algodtoken, 'http://' + algodnet)
    return algod

def db64(d):
    """base64 encode any bytes values in a list/dict, recursively"""
    if isinstance(d, bytes):
        return base64.b64encode(d).decode()
    if isinstance(d, (list, tuple)):
        return [db64(x) for x in d]
    if isinstance(d, dict):
        return {db64(k):db64(v) for k,v in d.items()}
    return d

class TestNodes:
    def __init__(self, args, algod_data):
        self.args = args
        self.algod_data = algod_data
        self._ec2 = None
        self.kmd = None
        self.algod = None
        self.pubw = None
        self.pubwid = None
        self.maxpubaddr = None
        self.maxaddramount = None

        self.config = {}
        self.configpath = os.path.join(self.algod_data, 'config.json')
        try:
            with open(self.configpath, 'rt') as fin:
                self.config = json.load(fin)
        except Exception as e:
            logger.debug('%s: could not read, %s', self.configpath, e)
        listenpath = os.path.join(self.algod_data, 'algod-listen.net')
        with open(listenpath, 'rt') as fin:
            listenstring = fin.read()
        lu = urllib.parse.urlparse(listenstring)
        #self.addr = self.config.get('NetAddress', '0.0.0.0:4160')
        #self.fakeurl = 'ws://' + self.addr
        #pu = urllib.parse.urlparse(self.fakeurl)
        self.relayip = httpget('http://169.254.169.254/latest/meta-data/local-ipv4')
        self.relayhostport = '{}:{}'.format(self.relayip, lu.port)
        self.amiid = httpget('http://169.254.169.254/latest/meta-data/ami-id')
        self.region_name = httpget('http://169.254.169.254/latest/meta-data/placement/region')
        self.currentaz = httpget('http://169.254.169.254/latest/meta-data/placement/availability-zone')
        #sgtext = httpget('http://169.254.169.254/latest/meta-data/security-groups')
        #security_groups = [x.strip() for x in sgtext.splitlines()]
        self.netmacs = [x.strip() for x in httpget('http://169.254.169.254/latest/meta-data/network/interfaces/macs').splitlines()]
        mac = self.netmacs[0]
        if not mac.endswith('/'):
            mac = mac + '/'
        self.subnet_id = httpget('http://169.254.169.254/latest/meta-data/network/interfaces/macs/' + mac + 'subnet-id')
        self.vpc_id = httpget('http://169.254.169.254/latest/meta-data/network/interfaces/macs/' + mac + 'vpc-id')
        self.sg_ids = [x.strip() for x in httpget('http://169.254.169.254/latest/meta-data/network/interfaces/macs/' + mac + 'security-group-ids').splitlines()]

    def ec2(self):
        if self._ec2 is None:
            self._ec2 = boto3.client('ec2', region_name=self.region_name)
        return self._ec2

    def connect(self):
        if self.algod and self.kmd:
            return self.algod, self.kmd

        subprocess.run(['goal', 'kmd', 'start', '-t', '3600','-d', self.algod_data], timeout=5).check_returncode()
        self.kmd = openkmd(self.algod_data)
        self.algod = openalgod(self.algod_data)
        return self.algod, self.kmd

    def get_pub_wallet(self):
        algod, kmd = self.connect()
        if not (self.pubw and self.maxpubaddr):
            # find private test node public wallet and its richest account
            wallets = kmd.list_wallets()
            pubwid = None
            for xw in wallets:
                if xw['name'] == 'unencrypted-default-wallet':
                    pubwid = xw['id']
            pubw = kmd.init_wallet_handle(pubwid, '')
            pubaddrs = kmd.list_keys(pubw)
            pubbalances = []
            maxamount = 0
            maxpubaddr = None
            for pa in pubaddrs:
                pai = algod.account_info(pa)
                if pai['amount'] > maxamount:
                    maxamount = pai['amount']
                    maxpubaddr = pai['address']
            self.pubw = pubw
            self.pubwid = pubwid
            self.maxpubaddr = maxpubaddr
            self.maxaddramount = maxamount
            logger.debug('found rich account %s %d', self.maxpubaddr, self.maxaddramount)
        return self.pubw, self.maxpubaddr

    def re_kmd(self):
        self.kmd = openkmd(self.algod_data)
        self.pubw = self.kmd.init_wallet_handle(self.pubwid, '')
        return self.kmd, self.pubw

    def new_part_account(self):
        "create a key pair and send a bunch of algos to the addr so it can participate"
        privkey_b64, addr_b32 = algosdk.account.generate_account()
        with open(addr_b32 + '.json', 'wt') as fout:
            json.dump({'a':addr_b32, 'p': privkey_b64}, fout)

        pubw, maxpubaddr = self.get_pub_wallet()
        algod, kmd = self.connect()
        params = algod.suggested_params()
        destAmount = int(self.maxaddramount / 30)
        txn = algosdk.transaction.PaymentTxn(sender=maxpubaddr, fee=params.min_fee, first=params.first, last=params.last, gh=params.gh, gen=params.gen, receiver=addr_b32, amt=destAmount, note=os.getrandom(8), flat_fee=True)
        logger.debug('%s -> %s %d', maxpubaddr, addr_b32, destAmount)
        logger.debug('%s', json.dumps(db64(txn.dictify())))
        tries = 3
        stxn = None
        while True:
            try:
                pubw = kmd.init_wallet_handle(self.pubwid, '')
                stxn = kmd.sign_transaction(pubw, '', txn)
                break
            except Exception as e:
                # kmd might have just timed out
                tries -= 1
                if tries <= 0:
                    raise
                logger.warning('kmd sign fail, retrying... (%s)', e)
                kmd, pubw = self.re_kmd()
        txid = algod.send_transaction(stxn)
        logger.info('fund %d %s -> %s', destAmount, maxpubaddr, addr_b32)
        self.maxaddramount -= destAmount

        return privkey_b64, addr_b32

    def launch_instance(self):
        args = self.args
        ensure_tarfile(self.algod_data)
        part_accounts = []
        for i in range(args.num_part):
            privkey_b64, addr_b32 = self.new_part_account()
            part_accounts.append((privkey_b64, addr_b32))
        target_args = {
            'phonebook': self.relayhostport,
            'npn': {'count': args.num_npn},
            'part': {'count': args.num_part, 'keys': part_accounts},
        }
        # base64 encoded json should unambiguously get through any shell interpretation
        argsb64 = base64.b64encode(json.dumps(target_args).encode()).decode()
        logger.debug('remote arg %s', argsb64)
        if args.name:
            tags = [{
                'ResourceType': 'instance',
                'Tags': [{
                    'Key': 'Name',
                    'Value': args.name + '_' + time.strftime('%Y%m%d_%H%M%S', time.gmtime()),
                }, {
                    'Key': 'RNH',
                    'Value': self.relayip,
                }],
            }]
        else:
            tags = []
        kwargs = dict(
            BlockDeviceMappings=[{
                'DeviceName': 'xvdh',
                'Ebs': {
                    'DeleteOnTermination': True,
                    'VolumeSize': 8,
                },
            }],
            ImageId=self.amiid,
            InstanceInitiatedShutdownBehavior='terminate',
            InstanceType=args.instance_type,
            KeyName=args.key_pair,
            MaxCount=1,
            MinCount=1,
            NetworkInterfaces=[{
                'AssociatePublicIpAddress': False,
                'DeleteOnTermination': True,
                'DeviceIndex': 0,
                'Groups': self.sg_ids,
                'SubnetId': self.subnet_id,
            }],
            Placement={'AvailabilityZone': self.currentaz},
            #SecurityGroupIds=sg_ids,
            #SubnetId=subnet_id,
            # TODO: put a script in 'UserData'
            TagSpecifications=tags,
        )
        if args.dry_run or logger.isEnabledFor(logging.DEBUG):
            logger.debug('run_instance %s', json.dumps(kwargs, indent=2))
        if args.dry_run:
            kwargs['DryRun'] = True
        result = self.ec2().run_instances(**kwargs)
        logger.debug('run_instances() => %r', result)
        inst = result['Instances'][0]
        instanceid = inst['InstanceId']

        desc = inst
        start = time.time()
        while True and not args.dry_run:
            if desc['State']['Name'] == 'running':
                break

            now = time.time()
            if now - start > 60:
                sys.stderr.write('instance failed to start within a minute, giving up\n')
                # TODO: terminate instance
                return 1
            time.sleep(2)
            descr = self.ec2().describe_instances(InstanceIds=[instanceid])
            desc = descr['Reservations'][0]['Instances'][0]

        instanceip = desc['PrivateIpAddress']
        extra = None
        if part_accounts:
            extra = {'participants': part_accounts}
        recordInstanceID(instanceid, instanceip, parts=part_accounts)
        if not args.dry_run:
            tries = 0
            while True:
                try:
                    start_remote(args, 'ubuntu', instanceip, argsb64)
                    break
                except:
                    tries += 1
                    if tries > 20:
                        raise
                    time.sleep(3)
        return desc

    def _instances(self):
        "generator for instance description objects"
        fleet = self.ec2().describe_instances(Filters=[{
            'Name': 'tag:RNH',
            'Values': [self.relayip],
        }])
        for res in fleet['Reservations']:
            for xi in res['Instances']:
                yield xi

    def list_instances(self):
        for xi in self._instances():
            state = xi.get('State')
            if state and 'Name' in state:
                state = state['Name']
            print(xi.get('InstanceId'), xi.get('LaunchTime'), state)

    def terminate_instances(self, n=None):
        ids = []
        for desc in self._instances():
            if desc['State']['Name'] == 'running':
                ids.append(desc['InstanceId'])
            if (n is not None) and (len(ids) >= n):
                break
        if len(ids) == 0:
            sys.stderr.write('no instances\n')
            return 1

        some = ids
        if len(some) > 5:
            some = some[:5] + ['...']

        ob = loadInstancesJson()
        instanceMeta = ob.get('instances', {})
        algod, kmd = self.connect()
        pubw, maxpubaddr = self.get_pub_wallet()
        params = algod.suggested_params()
        ichange = False
        for iid in some:
            imeta = instanceMeta.pop(iid, None)
            if not imeta:
                continue
            ichange = True
            for pa in imeta.get('parts', []):
                privkey_b64, addr_b32 = pa
                ai = algod.account_info(addr_b32)
                if ai.get('amount',0) == 0:
                    continue
                txn = algosdk.transaction.PaymentTxn(sender=addr_b32, fee=params.min_fee*10, first=params.first, last=params.last, gh=params.gh, gen=params.gen, receiver=maxpubaddr, close_remainder_to=maxpubaddr, amt=1, flat_fee=True)
                stxn = txn.sign(privkey_b64)
                algod.send_transaction(stxn)
                logger.info('close %s -> %s', addr_b32, maxpubaddr)
        if ichange:
            saveInstancesJson(ob)

        logger.info('terminating %d instances: %s', len(ids), ', '.join(some))
        ret = self.ec2().terminate_instances(InstanceIds=ids, DryRun=self.args.dry_run)
        if self.args.dry_run or logger.isEnabledFor(logging.DEBUG):
            logger.debug('terminate results: %s', json.dumps(ret, indent=2))
        return 0

durationSuffixMultipliers = { 's': 1, 'm': 60, 'h': 3600 }

def parseDuration(x):
    if x is None:
        return None
    lc = x[-1].lower()
    mult = durationSuffixMultipliers.get(lc)
    if mult is not None:
        x = x[:-1]
    else:
        mult = 1
    t = int(x)
    return t * mult

_LOG_FORMAT = '%(asctime)s %(levelname)-8s %(message)s'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--algod', default=None, help='algod data dir to connect to')
    ap.add_argument('--num-npn', default=6, type=int)
    ap.add_argument('--num-part', default=None, type=int)
    ap.add_argument('--instance-type', default='m5ad.4xlarge')
    ap.add_argument('-n', '--num-instances', default=1, type=int, help='number of instances to launch')
    ap.add_argument('--delay', default=None, help='time between instances \d+{,s,m}')
    ap.add_argument('-i', default=None, help='path to ssh key .pem')
    ap.add_argument('--key-pair', default=None, help='aws key pair name to use')
    ap.add_argument('--name', default='heapWatchTest', help='instance name prefix')
    #ap.add_argument('--priv-key', default=None, help='path to key.pem to use')
    ap.add_argument('--dry-run', default=False, action='store_true')
    ap.add_argument('--list-instances', default=False, action='store_true')
    ap.add_argument('--terminate-instances', default=None, const='all', nargs='?', help="an int to terminate some instances, no number or 'all' terminates all")
    ap.add_argument('--verbose', default=False, action='store_true')
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format=_LOG_FORMAT)
    else:
        logging.basicConfig(level=logging.INFO, format=_LOG_FORMAT)

    algod_data = args.algod
    if not algod_data:
        algod_data = os.getenv('ALGORAND_DATA')
    if not algod_data:
        sys.stderr.write('no relay algod specified by -d/--algod/$ALGORAND_DATA\n')
        return 1

    delay = parseDuration(args.delay)

    tn = TestNodes(args, algod_data)

    if args.list_instances:
        tn.list_instances()
        return 0

    if args.terminate_instances is not None:
        tcount = args.terminate_instances
        if tcount == 'all':
            tcount = None
        else:
            tcount = int(tcount)
        return tn.terminate_instances(tcount)

    if not args.key_pair:
        sys.stderr.write('--key-pair required to specify an AWS key pair name\n')
        return 1

    launched = 0
    while launched < args.num_instances:
        tn.launch_instance()
        launched += 1
        if delay is not None:
            time.sleep(delay)

    return 0

if __name__ == '__main__':
    sys.exit(main())
