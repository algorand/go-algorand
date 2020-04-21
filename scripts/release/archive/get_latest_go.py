#!/usr/bin/env python3

# use just stdlib so we can run with nothing more than `apt-get install -y python3`
import hashlib
import http.client
import json
import os
import re
import shutil
import subprocess
import sys


version_re = re.compile(r'\D+([0-9][.0-9]+)')

def parseversion(x):
    m = version_re.match(x)
    return m.group(1).split('.')

def get():
    # curl 'https://golang.org/dl/?mode=json'
    conn = http.client.HTTPSConnection('golang.org')
    conn.request('GET', '/dl/?mode=json')
    response = conn.getresponse()
    jsblob = response.read()
    # Python <= 3.5 json.loads() doesn't take bytes
    if isinstance(jsblob, bytes):
        jsblob = jsblob.decode('utf-8')
    return json.loads(jsblob)

def loadfile(path):
    # curl -o golang_dl.json 'https://golang.org/dl/?mode=json'
    # DRYRUN=1 python3 get_latest_go.py golang_dl.json
    with open(path) as fin:
        return json.load(fin)

def arch_os():
    result = subprocess.run(['uname', '-a'], stdout=subprocess.PIPE)
    text = result.stdout.decode()
    if 'x86_64' in text:
        arch = 'amd64'
    elif 'aarch64' in text:
        arch = 'arm64'
    else:
        raise Exception('could not guess go arch string from uname -a: {!r}'.format(text))
    if 'Linux' in text:
        os = 'linux'
    elif 'Darwin' in text:
        os = 'darwin'
    else:
        raise Exception('could not guess go os string from uname -a: {!r}'.format(text))
    return arch, os

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--json', help='pre-downloaded json from https://golang.org/dl/?mode=json')
    ap.add_argument('--version-prefix', help='e.g. 1.12 and get the latest 1.12.x')
    args = ap.parse_args()
    if args.json:
        ob = loadfile(args.json)
    else:
        ob = get()
    ob = filter(lambda x: x['stable'], ob)
    if args.version_prefix:
        ob = list(ob)
        filtered_versions = []
        for v in ob:
            m = version_re.match(v['version'])
            if m:
                version_string = m.group(1)
                if version_string.startswith(args.version_prefix):
                    filtered_versions.append(v)
        if not filtered_versions:
            sys.stderr.write('--version-prefix {!r} filtered out all versions: {!r}\n'.format(args.version_prefix, [v['version'] for v in ob]))
            sys.exit(1)
        ob = filtered_versions
    orderedbyversion = sorted([(parseversion(v['version']),v) for v in ob], reverse=True)
    newest = orderedbyversion[0][1]
    go_arch, go_os = arch_os()
    files = list(filter(lambda x: x['arch']==go_arch and x['os']==go_os, newest['files']))
    fname = files[0]['filename']
    sha256 = files[0]['sha256']
    url = 'https://dl.google.com/go/{}'.format(fname)

    # e.g. https://dl.google.com/go/go1.12.5.linux-amd64.tar.gz
    if os.environ.get('DRYRUN'):
        sys.stdout.write('curl -L -O {}\n{}\n'.format(url, sha256))
    else:
        sys.stdout.write('fetching {}\n'.format(url))
        subprocess.run(['curl', '-L', '-O', url])
        fhash = hashlib.sha256()
        with open(fname, 'rb') as fin:
            bb = bytearray(64*1024)
            while True:
                got = fin.readinto(bb)
                if got == 0:
                    break
                fhash.update(bb[:got])
        dldigest = fhash.hexdigest()
        if dldigest != sha256:
            sys.stderr.write('hash mismatch, wanted {} got {}\n'.format(sha256, dldigest))
            os.unlink(fname)
        sys.stdout.write('Done\n')
    return


if __name__ == '__main__':
    main()
