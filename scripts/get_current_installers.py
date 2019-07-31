#!/usr/bin/env python3
#
# pip install boto3
# python3 get_current_installers.py s3://bucket/prefix

import re
import sys

import boto3

def get_stage_release_set(response):
    prefix = None
    they = []
    for x in response['Contents']:
        path = x['Key']
        pre, fname = path.rsplit('/', 1)
        if fname.startswith('tools_') or fname.startswith('install_') or fname.startswith('node_'):
            continue
        if prefix is None:
            prefix = pre
            they.append(x)
        elif prefix == pre:
            they.append(x)
        else:
            break
    return they

# return (bucket,prefix)
def parse_s3_path(path):
    m = re.match(r's3://([^/]+)/(.*)', path)
    if m:
        return m.group(1), m.group(2)
    return None, None

def main():
    bucket, prefix = parse_s3_path(sys.argv[1])
    s3 = boto3.client('s3')
    staging_response = s3.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=100)
    if (not staging_response.get('KeyCount')) or ('Contents' not in staging_response):
        sys.stderr.write('nothing found under {}\n'.format(sys.argv[1]))
        sys.exit(1)
    rset = get_stage_release_set(staging_response)
    for ob in rset:
        okey = ob['Key']
        if okey.endswith('.rpm') or okey.endswith('.deb'):
            _, fname = okey.rsplit('/', 1)
            s3.download_file(bucket, okey, fname)
    return


if __name__ == '__main__':
    main()
