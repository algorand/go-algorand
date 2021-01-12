#!/usr/bin/env python3

# This script builds https://releases.algorand.com/index.html.

import sys
import boto3

staging_bucket = "algorand-dev-deb-repo"
staging_prefix = "http://algorand-dev-deb-repo.s3-website-us-east-1.amazonaws.com/"
key_url = "https://releases.algorand.com/key.pub"
releases_bucket = "algorand-releases"
releases_prefix = "https://releases.algorand.com/"
html_tpl = "html.tpl"
styles_url = "releases_page.css"
tokens = ["stable", "beta", "indexer"]

def get_stage_release_set(response):
    prefix = None
    all = {}
    they = []
    for x in response["Contents"]:
        path = x["Key"]
        pre, fname = path.rsplit("/", 1)
        if fname.startswith("tools_") or fname.startswith("install_") or fname.startswith("pending_"):
            continue
        if prefix is None:
            prefix = pre
            they.append(x)
        elif prefix == pre:
            they.append(x)
        else:
            all[prefix] = they
            prefix = None
            they = [x]
    return all

def release_set_files(rset):
    files = {}
    for x in rset:
        path = x["Key"]
        pre, fname = path.rsplit("/", 1)
        if fname.startswith("hashes_"):
            continue
        didsuf = False
        for suffix in (".asc", ".sig"):
            if fname.endswith(suffix):
                froot = fname[:-len(suffix)]
                fd = files.get(froot)
                if fd is None:
                    fd = {}
                    files[froot] = fd
                fd[suffix] = x
                didsuf = True
                break
        if didsuf:
            continue
        fd = files.get(fname)
        if fd is None:
            fd = {}
            files[fname] = fd
        fd["file"] = path
        fd["Size"] = x["Size"]
    return files

def get_hashes_data(s3, rset):
    text = ""
    for x in rset:
        path = x["Key"]
        pre, fname = path.rsplit("/", 1)
        if fname.endswith(".asc"):
            continue
        if fname.endswith(".sig"):
            continue
        if fname.startswith("hashes"):
            ob = s3.get_object(Bucket=staging_bucket, Key=path)
            text += ob["Body"].read().decode()
    return text

def read_hashes(fin):
    by_fname = {}
    for line in fin:
        if not line:
            continue
        line = line.strip()
        if not line:
            continue
        if line[0] == "#":
            continue
        hashstr, fname = line.split()
        ob = by_fname.get(fname)
        if not ob:
            ob = {}
            by_fname[fname] = ob
        if len(hashstr) == 32:
            ob["md5"] = hashstr
        elif len(hashstr) == 64:
            ob["sha256"] = hashstr
        elif len(hashstr) == 128:
            ob["sha512"] = hashstr
    return by_fname

def objects_by_fname(they):
    out = {}
    for x in they:
        path = x["Key"]
        if path.endswith("/"):
            continue
        parts = path.rsplit("/", 1)
        fname = parts[-1]
        out[fname] = x
    return out

def getContent(url):
    with open(url, "r") as reader:
        content = reader.read()

    return content

def build_page(channels):
    html = getContent(html_tpl).replace("{styles}", getContent(styles_url))

    for n in tokens:
        html = html.replace("".join(["{", n, "}"]), "".join(channels[n]))

    sys.stdout.write(html)

def get_furl(release_files, fname, skey):
    rfpath = release_files.get(fname)
    if rfpath is not None:
        return releases_prefix + rfpath["Key"]
    else:
        return staging_prefix + skey

def main():
    s3 = boto3.client("s3")
    channels = {}

    for channel in ["stable", "beta", "indexer"]:
        staging_response = s3.list_objects_v2(Bucket=staging_bucket, Prefix="releases/" + channel + "/", MaxKeys=100)
        release_sets = get_stage_release_set(staging_response)
        releases_response = s3.list_objects_v2(Bucket=releases_bucket)
        release_files = objects_by_fname(releases_response["Contents"])

        table = []

        for key, rset in release_sets.items():
            hashftext = get_hashes_data(s3, rset)
            fhashes = read_hashes(hashftext.splitlines())
            files = release_set_files(rset)

            for fname, info in files.items():
                if "file" not in info:
                    continue
                furl = get_furl(release_files, fname, info['file'])
                ftext = '<div class="fname"><a href="{}">{}</a></div>'.format(furl, fname)
                sig = info.get(".sig")
                stext = ""
                if sig is not None:
                    sfname = sig["Key"].rsplit("/", 1)[-1]
                    surl = get_furl(release_files, sfname, sig["Key"])
                    stext = '<a href="{}">.sig</a>'.format(surl)
                size = info.get("Size", "")
                hashes = fhashes.get(fname)
                if hashes:
                    for hn in ("md5", "sha256", "sha512"):
                        hv = hashes.get(hn)
                        if hv:
                            ftext += '<div class="hash {}">{}</div>'.format(hn, hv)
                if not hashes and not stext:
                    continue
                tbody = ["<tbody><tr><td>{}</td><td>{}</td><td>{}</td></tr></tbody>".format(ftext, size, stext)]
                table.append("".join(tbody))

            # Only add the spacer *after* every set.
            # It's not readily apparent to me why `indexer` would have a dict with a single
            # item.  This needs additional investigation.
            #
            # For instance, when creating the "indexer" table, the first line was empty b/c
            # it added a spacer.  This was b/c there were two dicts and the first only
            # contained one item, which was useless.
            #
            # For now, just ignore those dicts.
            if len(files.items()) > 1:
                table.append('<tbody><tr class="spacer"><td></td></tr></tbody>')

        channels[channel] = table

    build_page(channels)

if __name__ == "__main__":
    main()

