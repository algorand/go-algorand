#!/usr/bin/env bash
# sign centos rpm from inside docker

set -e
set -x

export HOME=/root
mkdir -p ${HOME}/go
mkdir -p ${HOME}/go/bin
export GOPATH=${HOME}/go
export PATH=${GOPATH}/bin:/usr/local/go/bin:${PATH}

(cd ${HOME} && tar jxf /stuff/gnupg*.tar.bz2)
export PATH="${HOME}/gnupg2/bin:${PATH}"
export LD_LIBRARY_PATH=${HOME}/gnupg2/lib

umask 0077
mkdir -p ~/.gnupg
umask 0022

touch "${HOME}/.gnupg/gpg.conf"
if grep -q no-autostart "${HOME}/.gnupg/gpg.conf"; then
    echo ""
else
    echo "no-autostart" >> "${HOME}/.gnupg/gpg.conf"
fi
rm -f ${HOME}/.gnupg/S.gpg-agent
(cd ~/.gnupg && ln -s /S.gpg-agent S.gpg-agent)

gpg --import /stuff/key.pub
gpg --import /stuff/rpm.pub
rpmkeys --import /stuff/rpm.pub
echo "wat"|gpg -u rpm@algorand.com --clearsign

cat <<EOF>"${HOME}/.rpmmacros"
%_gpg_name Algorand RPM <rpm@algorand.com>
%__gpg ${HOME}/gnupg2/bin/gpg
%__gpg_check_password_cmd true
EOF

cat <<EOF>"${HOME}/rpmsign.py"
import rpm
import sys
rpm.addSign(sys.argv[1], '')
EOF

NEWEST_RPM=$(ls -t /root/subhome/node_pkg/*rpm|head -1)
python2 "${HOME}/rpmsign.py" "${NEWEST_RPM}"

cp -p "${NEWEST_RPM}" /dummyrepo
createrepo --database /dummyrepo
rm -f /dummyrepo/repodata/repomd.xml.asc
gpg -u rpm@algorand.com --detach-sign --armor /dummyrepo/repodata/repomd.xml
