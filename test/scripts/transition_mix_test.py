#!/usr/bin/env python3
#

import argparse
import atexit
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

# pip install py-algorand-sdk
import algosdk

logger = logging.getLogger(__name__)

scriptdir = os.path.dirname(os.path.realpath(__file__))
repodir =  os.path.join(scriptdir, "..", "..")

_onbranch = 'On branch '

def getbranch(rd):
    result = subprocess.run(['git', 'status', '-b'], cwd=rd, capture_output=True, timeout=3)
    for line in result.stdout.decode().splitlines():
        if line.startswith(_onbranch):
            return line[len(_onbranch):]
    return None

def get_go_env():
    out = {}
    result = subprocess.run(['go', 'env'], capture_output=True)
    for line in result.stdout.decode().splitlines():
        line = line.strip()
        # TODO: is there a better way to parse sh-like k=v (possibly with quoting)?
        k,v = line.split('=', 1)
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        out[k] = v
    return out

def openalgod(algodata):
    algodnetpath = os.path.join(algodata,'algod.net')
    algodnet = open(algodnetpath, 'rt').read().strip()
    algodtokenpath = os.path.join(algodata,'algod.token')
    algodtoken = open(algodtokenpath, 'rt').read().strip()
    algod = algosdk.algod.AlgodClient(algodtoken, 'http://' + algodnet)
    return algod

def xrun(cmd, *args, **kwargs):
    timeout = kwargs.pop('timeout', None)
    kwargs['stdout'] = subprocess.PIPE
    kwargs['stderr'] = subprocess.STDOUT
    try:
        p = subprocess.Popen(cmd, *args, **kwargs)
    except Exception as e:
        logger.error('subprocess failed {!r}'.format(cmd), exc_info=True)
        raise
    try:
        if timeout:
            stdout,stderr = p.communicate(timeout=timeout)
        else:
            stdout,stderr = p.communicate()
    except subprocess.TimeoutExpired as te:
        logger.error('subprocess timed out {!r}'.format(cmd), exc_info=True)
        reportcomms(p, stdout, stderr)
        raise
    except Exception as e:
        logger.error('subprocess exception {!r}'.format(cmd), exc_info=True)
        reportcomms(p, stdout, stderr)
        raise
    if p.returncode != 0:
        cmdr = repr(cmd)
        logger.error('cmd failed {}'.format(cmdr))
        reportcomms(p, stdout, stderr)
        raise Exception('error: cmd failed: {}'.format(cmdr))


def startdaemon(cmd):
    try:
        p = subprocess.Popen(cmd)
        return p
    except Exception as e:
        logger.error('subprocess failed {!r}'.format(cmd), exc_info=True)
        raise

_logging_format = '%(asctime)s :%(lineno)d %(message)s'
_logging_datefmt = '%Y%m%d_%H%M%S'

def main():
    start = time.time()
    ap = argparse.ArgumentParser()
    ap.add_argument('--new-branch', default=None, help='`git checkout {new-branch}` and build', required=True)
    ap.add_argument('--old-branch', default=None, help='`git checkout {new-branch}` and build', required=True)
    ap.add_argument('--keep-temps', default=False, action='store_true', help='if set, keep all the test files')
    ap.add_argument('--verbose', default=False, action='store_true')
    args = ap.parse_args()

    if args.verbose:
        logging.basicConfig(format=_logging_format, datefmt=_logging_datefmt, level=logging.DEBUG)
    else:
        logging.basicConfig(format=_logging_format, datefmt=_logging_datefmt, level=logging.INFO)

    # TODO: default old_branch to the highest git tag like 'v3.5.1-stable'
    # TODO: default new_branch to `master`

    # start with a copy when making env for child processes
    env = dict(os.environ)

    tempdir = os.getenv('TEMPDIR')
    if not tempdir:
        tempdir = tempfile.mkdtemp()
        env['TEMPDIR'] = tempdir
        logger.info('created TEMPDIR %r', tempdir)
        if not args.keep_temps:
            # If we created a tmpdir and we're not keeping it, clean it up.
            # If an outer process specified $TEMPDIR, let them clean it up.
            atexit.register(shutil.rmtree, tempdir, onerror=logger.error)
        else:
            atexit.register(print, 'keeping temps. to clean up:\nrm -rf {}'.format(tempdir))

    curbranch = getbranch(repodir)
    goenv = get_go_env()
    gopath = goenv['GOPATH']
    newbin = os.path.join(tempdir, 'newbin')
    newalgod = os.path.join(newbin , 'algod')
    oldbin = os.path.join(tempdir, 'oldbin')
    oldalgod = os.path.join(oldbin, 'algod')
    os.makedirs(newbin, exist_ok=True)
    os.makedirs(oldbin, exist_ok=True)
    changeBack = False
    if not os.path.exists(newalgod):
        xrun(['git', 'checkout', args.new_branch], cwd=repodir)
        if curbranch and not changeBack:
            changeBack = True
            atexit.register(xrun, ['git', 'checkout', curbranch])
        xrun(['make'], cwd=repodir)
        for bn in ('algod', 'goal', 'kmd'):
            shutil.copy(os.path.join(gopath, 'bin', bn), os.path.join(newbin, bn))
    if not os.path.exists(oldalgod):
        xrun(['git', 'checkout', args.old_branch], cwd=repodir)
        if curbranch and not changeBack:
            changeBack = True
            atexit.register(xrun, ['git', 'checkout', curbranch])
        xrun(['make'], cwd=repodir)
        for bn in ('algod', 'goal', 'kmd'):
            shutil.copy(os.path.join(gopath, 'bin', bn), os.path.join(oldbin, bn))

    netdir = os.path.join(tempdir, 'net')
    env['NETDIR'] = netdir

    shutil.rmtree(netdir, ignore_errors=True)
    xrun(['goal', 'network', 'create', '-r', netdir, '-n', 'tbd', '-t', os.path.join(repodir, 'test/testdata/nettemplates/ThreeNodesEvenDist.json')], timeout=90)

    relaydir = os.path.join(netdir, 'Primary')
    relay = startdaemon([oldalgod, '-d', relaydir])
    time.sleep(0.5)
    with open(os.path.join(relaydir, 'algod-listen.net')) as fin:
        relay_addr = fin.read().strip()

    n1dir = os.path.join(netdir, 'Node1')
    node1 = startdaemon([oldalgod, '-d', n1dir, '-p', relay_addr])
    #~/Algorand/masterbin/algod -d ~/Algorand/tn3/Node1 -p $(cat ~/Algorand/tn3/Primary/algod-listen.net) > ~/Algorand/tn3/Primary/algod.out 2>&1 &

    n2dir = os.path.join(netdir, 'Node2')
    node2 = startdaemon([oldalgod, '-d', n2dir, '-p', relay_addr])
    #~/Algorand/txnsyncbin/algod -d ~/Algorand/tn3/Node2 -p $(cat ~/Algorand/tn3/Primary/algod-listen.net) > ~/Algorand/tn3/Primary/algod.out 2>&1 &

if __name__ == '__main__':
    sys.exit(main())
