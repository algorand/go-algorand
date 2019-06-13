Name:          algorand
Version:       @VER@
Release:       1
Summary:       Algorand node software
URL:           https://www.algorand.com
License:       AGPL-3+
Requires:      yum-cron
Requires:      systemd
Requires(pre): shadow-utils

## Skip BuildRequires for now because we are building using rpmbuild
## on an Ubuntu machine.
# BuildRequires: golang >= 1.12

%define SRCDIR go-algorand-rpmbuild
%define _buildshell /bin/bash

%description
This package provides an implementation of the Algorand protocol.

%license
%include %{LICENSE_FILE}

%prep
## Nothing to prep; intended to be built using scripts/build_rpm.sh

%build
## Nothing to prep; intended to be built using scripts/build_rpm.sh

%install
mkdir -p %{buildroot}/usr/bin
for f in algod kmd carpenter msgpacktool algokey catchupsrv goal; do
  install -m 755 ${GOPATH}/bin/${f} %{buildroot}/usr/bin/${f}
done

mkdir -p %{buildroot}/var/lib/algorand
for f in config.json.example system.json; do
  install -m 644 ${REPO_DIR}/installer/${f} %{buildroot}/var/lib/algorand/${f}
done

mkdir -p %{buildroot}/lib/systemd/system
install -m 644 ${REPO_DIR}/installer/algorand.service %{buildroot}/lib/systemd/system/algorand.service

mkdir -p %{buildroot}/etc/cron.hourly
install -m 755 ${REPO_DIR}/installer/rpm/0yum-algorand-hourly.cron %{buildroot}/etc/cron.hourly/0yum-algorand-hourly.cron

mkdir -p %{buildroot}/etc/yum
install -m 644 ${REPO_DIR}/installer/rpm/yum-cron-algorand.conf %{buildroot}/etc/yum/yum-cron-algorand.conf

mkdir -p %{buildroot}/etc/pki/rpm-gpg
install -m 644 ${REPO_DIR}/installer/rpm/RPM-GPG-KEY-Algorand %{buildroot}/etc/pki/rpm-gpg/RPM-GPG-KEY-Algorand

mkdir -p %{buildroot}/usr/lib/algorand/yum.repos.d
install -m 644 ${REPO_DIR}/installer/rpm/algorand.repo %{buildroot}/usr/lib/algorand/yum.repos.d/algorand.repo

mkdir -p %{buildroot}/var/lib/algorand/genesis
if [ "%{RELEASE_GENESIS_PROCESS}" != "x" ]; then
  genesis_dirs=("devnet" "testnet" "mainnet")
  for dir in "${genesis_dirs[@]}"; do
    mkdir -p %{buildroot}/var/lib/algorand/genesis/${dir}
    cp ${REPO_DIR}/installer/genesis/${dir}/genesis.json %{buildroot}/var/lib/algorand/genesis/${dir}/genesis.json
    #${GOPATH}/bin/buildtools genesis ensure -n ${dir} --source ${REPO_DIR}/gen/${dir}/genesis.json --target %{buildroot}/var/lib/algorand/genesis/${dir}/genesis.json --releasedir ${REPO_DIR}/installer/genesis
  done
  cp %{buildroot}/var/lib/algorand/genesis/${DEFAULT_RELEASE_NETWORK}/genesis.json %{buildroot}/var/lib/algorand/genesis.json
else
  cp installer/genesis/${DEFAULTNETWORK}/genesis.json %{buildroot}/var/lib/algorand/genesis.json
  #${GOPATH}/bin/buildtools genesis ensure -n ${DEFAULT_RELEASE_NETWORK} --source ${REPO_DIR}/gen/${DEFAULT_RELEASE_NETWORK}/genesis.json --target %{buildroot}/var/lib/algorand/genesis.json --releasedir ${REPO_DIR}/installer/genesis
fi

%files
/usr/bin/algod
/usr/bin/kmd
/usr/bin/carpenter
/usr/bin/msgpacktool
/usr/bin/algokey
/usr/bin/catchupsrv
/usr/bin/goal
/var/lib/algorand/config.json.example
/var/lib/algorand/system.json
%config(noreplace) /var/lib/algorand/genesis.json
%if %{RELEASE_GENESIS_PROCESS} != "x"
  /var/lib/algorand/genesis/devnet/genesis.json
  /var/lib/algorand/genesis/testnet/genesis.json
  /var/lib/algorand/genesis/mainnet/genesis.json
%endif
/lib/systemd/system/algorand.service
%config(noreplace) /etc/cron.hourly/0yum-algorand-hourly.cron
%config(noreplace) /etc/yum/yum-cron-algorand.conf
/etc/pki/rpm-gpg/RPM-GPG-KEY-Algorand
/usr/lib/algorand/yum.repos.d/algorand.repo

%changelog

## systemd macros from /usr/lib/rpm/macros.d/macros.systemd
## copied here so we don't have to figure out how to install
## this file on an Ubuntu build host.

%define systemd_post() \
if [ $1 -eq 1 ] ; then \
        # Initial installation \
        systemctl preset %{?*} >/dev/null 2>&1 || : \
fi \
%{nil}

%define systemd_preun() \
if [ $1 -eq 0 ] ; then \
        # Package removal, not upgrade \
        systemctl --no-reload disable %{?*} > /dev/null 2>&1 || : \
        systemctl stop %{?*} > /dev/null 2>&1 || : \
fi \
%{nil}

%define systemd_postun_with_restart() \
systemctl daemon-reload >/dev/null 2>&1 || : \
if [ $1 -ge 1 ] ; then \
        # Package upgrade, not uninstall \
        systemctl try-restart %{?*} >/dev/null 2>&1 || : \
fi \
%{nil}

%pre
getent passwd algorand >/dev/null || \
	useradd --system --home-dir /var/lib/algorand --no-create-home algorand >/dev/null
getent group nogroup >/dev/null || \
	groupadd --system nogroup >/dev/null

%post
chown -R algorand /var/lib/algorand
%systemd_post algorand.service

%preun
%systemd_preun algorand.service

%postun
%systemd_postun_with_restart algorand.service
