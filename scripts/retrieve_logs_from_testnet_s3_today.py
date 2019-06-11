#!/usr/bin/env python2

import datetime

import boto3
import botocore

bucketname = 'testnet-data'

s3 = boto3.resource('s3')

now = datetime.datetime.now()
day, month, year = now.day, now.month, now.year

bucket = s3.Bucket(bucketname)
keynames = [o.key
            for o in bucket.objects.all()
            if o.last_modified.day == day
            and o.last_modified.month == month
            and o.last_modified.year == year]

for keyname in keynames:
    print 'downloading', keyname
    bucket.download_file(keyname, keyname)
    print 'finished', keyname

