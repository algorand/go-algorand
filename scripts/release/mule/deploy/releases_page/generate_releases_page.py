#!/usr/bin/env python3

# This script builds https://releases.algorand.com/index.html
#
# For each channel (stable, beta, indexer), we download the file information
# from the staging_bucket. Information from this bucket is used to create an
# html block for each channel which includes all versions found.
#
# The releases_bucket is also read, and if the file exists there, then the
# releases_bucket URL is used instead of the staging_bucket URL.
#
# All the HTML for the channels is combined to form one large release page,
# which can then be published on our releases page.

import sys
import boto3

staging_bucket = "algorand-dev-deb-repo"
staging_prefix = "http://algorand-dev-deb-repo.s3-website-us-east-1.amazonaws.com/"
key_url = "https://releases.algorand.com/key.pub"
releases_bucket = "algorand-releases"
releases_prefix = "https://releases.algorand.com/"
html_tpl = "html.tpl"
# Nit: should be styles_file
styles_url = "releases_page.css"
# May want to call these channels instead
tokens = ["stable", "beta", "indexer"]


def get_stage_release_set(response):
    # Loop through contents of STAGING_BUCKET/releases/CHANNEL/ and return
    # all[prefix] = [file_obj1, file_obj2...]
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
            # Why do the following instead of emptying 'they' altogether?
            they = [x]
    return all


def release_set_files(rset):
    # Take list of file_objs, and return a files dict, keyed by filename
    # value is a dict with keys "file" (full path), "Size", and if
    # present, ".asc" or ".sig"
    files = {}
    for x in rset:
        path = x["Key"]
        pre, fname = path.rsplit("/", 1)
        if fname.startswith("hashes_"):
            continue
        didsuf = False
        for suffix in (".asc", ".sig"):
            # Check if signature file, e.g. node_beta_linux-amd64_2.5.2.tar.gz.sig
            if fname.endswith(suffix):
                # Get base filename, e.g. without '.sig'
                froot = fname[:-len(suffix)]

                fd = files.get(froot)
                if fd is None:
                    fd = {}
                    files[froot] = fd
                # key file dict by suffix, attach whole file object
                fd[suffix] = x
                didsuf = True
                break  # end suffixes loop
        if didsuf:
            continue  # go to next file in rset

        # At this point we are not a sig file, so just attach raw information
        fd = files.get(fname)
        if fd is None:
            fd = {}
            files[fname] = fd
        fd["file"] = path
        fd["Size"] = x["Size"]
    return files


def get_hashes_data(s3, rset):
    # Read all hashes files for a version and return text string
    text = ""
    for x in rset:
        # x here are objects under a specific prefix
        path = x["Key"]
        pre, fname = path.rsplit("/", 1)
        if fname.endswith(".asc"):
            continue
        if fname.endswith(".sig"):
            continue

        # We skip signature files and only process hashes files
        # e.g. hashes_beta_linux_amd64_2.5.2
        # We read and append all of this data in the 'text' string and return
        # it
        if fname.startswith("hashes"):
            ob = s3.get_object(Bucket=staging_bucket, Key=path)
            text += ob["Body"].read().decode()
    return text


def read_hashes(fin):
    # Read the output of get_hashes_data
    by_fname = {}
    for line in fin:
        # Ignore blanks and comments
        if not line:
            continue
        line = line.strip()
        if not line:
            continue
        if line[0] == "#":
            continue

        # E.g.:
        # 7e19496802ca7f3bec68ba580ccb7042
        # algorand-beta-2.5.2-1.x86_64.rpm
        hashstr, fname = line.split()
        ob = by_fname.get(fname)

        # If the filename is not in by_fname, create an empty dict and assign
        # it
        if not ob:
            ob = {}
            by_fname[fname] = ob

        # if 32 chars, it's md5; 64 is sha256, 128 is sha512. Assign to dict
        # under those keys
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
    # read html_tpl and styles_url, make substitutions
    html = getContent(html_tpl).replace("{styles}", getContent(styles_url))

    # Replace each token (channel) from channels
    for n in tokens:
        html = html.replace("".join(["{", n, "}"]), "".join(channels[n]))

    sys.stdout.write(html)


def get_furl(release_files, fname, skey):
    # Pass s3://algorand-releases/ file objects; also the filename and path
    # from s3://algorand-dev-deb-repo.
    #
    # If the filename is in the algorand-releases bucket, use the url from the
    # releases bucket. Otherwise, use the URL from the
    # s3://algorand-dev-deb-repo bucket.
    # 
    # algorand-releases and algorand-dev-deb-repo match:
    # https://releases.algorand.com/[rpath]
    # Else:
    # http://algorand-dev-deb-repo.s3-website-us-east-1.amazonaws.com/[spath]
    rfpath = release_files.get(fname)
    if rfpath is not None:
        return releases_prefix + rfpath["Key"]
    else:
        return staging_prefix + skey


def main():
    s3 = boto3.client("s3")
    channels = {}

    # Should use tokens array instead
    for channel in ["stable", "beta", "indexer"]:
        # Fetch contents of e.g. s3://algorand-dev-deb-repo/releases/beta/
        # Note: MaxKeys will limit to last 100 releases, which is more than
        # enough. Consider dropping this to 2.
        staging_response = s3.list_objects_v2(
            Bucket=staging_bucket,
            Prefix="releases/" + channel + "/", MaxKeys=100)

        # Populate release_sets, e.g.:
        # 'releases/beta/f9fa9a084_2.5.2' => [file_obj1, file_obj2, ...]
        release_sets = get_stage_release_set(staging_response)

        # List everything from the releases bucket s3://algorand-releases/
        releases_response = s3.list_objects_v2(Bucket=releases_bucket)

        # Return dict keyed by filename of file_objs from
        # s3://algorand-releases/
        release_files = objects_by_fname(releases_response["Contents"])

        table = []

        # Loop through all the releases in e.g.
        # s3://algorand-dev-deb-repo/releases/beta/
        for key, rset in release_sets.items():
            # key: releases/beta/f9fa9a084_2.5.2
            # rset: [file_obj1, file_obj2, ...]

            # Scan rset objs and return all the hashes data as a string
            hashftext = get_hashes_data(s3, rset)

            # Create a dict of fhashes[filename] = hash_obj
            # hash_obj[CHECKSUM] = HASH_STRING
            # E.g. hash_obj['md5'] = '7e19496802ca7f3bec68ba580ccb7042'
            fhashes = read_hashes(hashftext.splitlines())

            # Build a dict keyed by filename with value of a dict, keyed by 
            # "file" (full path) and "Size"
            files = release_set_files(rset)

            for fname, info in files.items():
                if "file" not in info:
                    continue

                # Use algorand-releases URL if avail; otherwise
                # algorand-dev-deb-repo URL
                furl = get_furl(release_files, fname, info['file'])

                ftext = '<div class="fname"><a href="{}">{}</a></div>'.format(furl, fname)
                # sig file obj from algorand-dev-deb-repo
                sig = info.get(".sig")
                stext = ""
                if sig is not None:
                    sfname = sig["Key"].rsplit("/", 1)[-1]  # filename
                    # Use algorand-releases URL if available
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
            # It's not readily apparent to me why `indexer` would have a dict
            # with a single item.  This needs additional investigation.
            #
            # For instance, when creating the "indexer" table, the first line
            # was empty b/c it added a spacer.  This was b/c there were two
            # dicts and the first only contained one item, which was useless.
            #
            # For now, just ignore those dicts.
            if len(files.items()) > 1:
                table.append('<tbody><tr class="spacer"><td></td></tr></tbody>')

        channels[channel] = table

    build_page(channels)


if __name__ == "__main__":
    main()
