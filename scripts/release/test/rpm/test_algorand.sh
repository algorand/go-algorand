#!/usr/bin/env bash
# shellcheck disable=2012,2045

set -ex

export HOME=/root

cd "${HOME}" && tar jxf "${HOME}"/subhome/gnupg*.tar.bz2
export PATH="${HOME}/gnupg2/bin:${PATH}"
export LD_LIBRARY_PATH=${HOME}/gnupg2/lib

umask 0077
mkdir -p "${HOME}/.gnupg"
umask 0022
touch "${HOME}/.gnupg/gpg.conf"

if grep -q no-autostart "${HOME}/.gnupg/gpg.conf"
then
    echo ""
else
    echo "no-autostart" >> "${HOME}/.gnupg/gpg.conf"
fi

rm -f ${HOME}/.gnupg/S.gpg-agent
cd "${HOME}"/.gnupg && ln -s "${HOME}"/S.gpg-agent S.gpg-agent

gpg --import /root/keys/dev.pub
gpg --import /root/keys/rpm.pub
rpmkeys --import /root/keys/rpm.pub
echo wat | gpg -u rpm@algorand.com --clearsign

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

for rpm in $(ls /root/subhome/node_pkg/*.rpm); do
    if [[ ! "$rpm" =~ devtools ]]; then
        python2 "${HOME}/rpmsign.py" "$rpm"

        cp -p "$rpm" /root/dummyrepo
        createrepo --database /root/dummyrepo
        rm -f /root/dummyrepo/repodata/repomd.xml.asc
        gpg -u rpm@algorand.com --detach-sign --armor /root/dummyrepo/repodata/repomd.xml

        OLDRPM=$(ls -t /root/subhome/node_pkg/*.rpm | head -1)
        if [ -f "${OLDRPM}" ]; then
            yum install -y "${OLDRPM}"
            algod -v

            mkdir -p /root/testnode
            cp -p /var/lib/algorand/genesis/testnet/genesis.json /root/testnode

            goal node start -d /root/testnode
            goal node wait -d /root/testnode -w 120
            goal node stop -d /root/testnode
        fi

        yum-config-manager --add-repo "http://${DC_IP}:8111/algodummy.repo"

        yum install -y algorand

        if [ ! -d /root/testnode ]; then
            mkdir -p /root/testnode
            cp -p /var/lib/algorand/genesis/testnet/genesis.json /root/testnode
        fi

        goal node start -d /root/testnode
        goal node wait -d /root/testnode -w 120
        goal node stop -d /root/testnode
    fi
done

echo CENTOS_DOCKER_TEST_OK

