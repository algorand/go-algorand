Name:          @PKG_NAME@
Version:       @VER@
Release:       1
Summary:       Algorand node software
URL:           https://www.algorand.com
License:       AGPL-3+
Requires:      yum-cron
Requires:      systemd
Requires(pre): shadow-utils

%define SRCDIR go-algorand-rpmbuild
%define _buildshell /bin/bash

%description
This package provides an implementation of the Algorand protocol.

%license
%include %{LICENSE_FILE}

%prep
## Nothing to prep; intended to be built using scripts/release/mule/package/{OS_TYPE}/{ARCH}/rpm/package.sh

%build
## Nothing to prep; intended to be built using scripts/release/mule/package/{OS_TYPE}/{ARCH}/rpm/package.sh

%install
mkdir -p %{buildroot}/usr/bin
# NOTE: keep in sync with scripts/build_deb.sh bin_files
# NOTE: keep in sync with %files section below
for f in algocfg algod algoh algokey ddconfig.sh diagcfg goal kmd node_exporter; do
  install -m 755 ${ALGO_BIN}/${f} %{buildroot}/usr/bin/${f}
done

mkdir -p %{buildroot}/var/lib/algorand
chmod 775 %{buildroot}/var/lib/algorand
for f in config.json.example system.json; do
  install -m 644 ${REPO_DIR}/installer/${f} %{buildroot}/var/lib/algorand/${f}
done

mkdir -p %{buildroot}/lib/systemd/system
install -m 644 ${REPO_DIR}/installer/algorand.service %{buildroot}/lib/systemd/system/algorand.service
install -m 644 ${REPO_DIR}/installer/algorand@.service %{buildroot}/lib/systemd/system/algorand@.service

mkdir -p %{buildroot}/etc/cron.hourly
install -m 755 ${REPO_DIR}/installer/rpm/algorand/0yum-algorand-hourly.cron %{buildroot}/etc/cron.hourly/0yum-algorand-hourly.cron

mkdir -p %{buildroot}/etc/yum
install -m 644 ${REPO_DIR}/installer/rpm/algorand/yum-cron-algorand.conf %{buildroot}/etc/yum/yum-cron-algorand.conf

mkdir -p %{buildroot}/etc/pki/rpm-gpg
install -m 644 ${REPO_DIR}/installer/rpm/RPM-GPG-KEY-Algorand %{buildroot}/etc/pki/rpm-gpg/RPM-GPG-KEY-Algorand

mkdir -p %{buildroot}/usr/lib/algorand/yum.repos.d
install -m 644 ${REPO_DIR}/installer/rpm/algorand/algorand.repo %{buildroot}/usr/lib/algorand/yum.repos.d/algorand.repo

mkdir -p %{buildroot}/var/lib/algorand/genesis
if [ "%{RELEASE_GENESIS_PROCESS}" != "x" ]; then
  genesis_dirs=("devnet" "testnet" "mainnet" "betanet")
  for dir in "${genesis_dirs[@]}"; do
    mkdir -p %{buildroot}/var/lib/algorand/genesis/${dir}
    cp ${REPO_DIR}/installer/genesis/${dir}/genesis.json %{buildroot}/var/lib/algorand/genesis/${dir}/genesis.json
    #${GOPATH}/bin/buildtools genesis ensure -n ${dir} --source ${REPO_DIR}/gen/${dir}/genesis.json --target %{buildroot}/var/lib/algorand/genesis/${dir}/genesis.json --releasedir ${REPO_DIR}/installer/genesis
  done
  cp %{buildroot}/var/lib/algorand/genesis/${DEFAULT_RELEASE_NETWORK}/genesis.json %{buildroot}/var/lib/algorand/genesis.json
else
  cp ${REPO_DIR}/installer/genesis/${DEFAULT_RELEASE_NETWORK}/genesis.json %{buildroot}/var/lib/algorand/genesis.json
  #${GOPATH}/bin/buildtools genesis ensure -n ${DEFAULT_RELEASE_NETWORK} --source ${REPO_DIR}/gen/${DEFAULT_RELEASE_NETWORK}/genesis.json --target %{buildroot}/var/lib/algorand/genesis.json --releasedir ${REPO_DIR}/installer/genesis
fi

%files
/usr/bin/algocfg
/usr/bin/algod
/usr/bin/algoh
/usr/bin/algokey
/usr/bin/ddconfig.sh
/usr/bin/diagcfg
/usr/bin/goal
/usr/bin/kmd
/usr/bin/node_exporter
/var/lib/algorand/config.json.example
%config(noreplace) /var/lib/algorand/system.json
%config(noreplace) /var/lib/algorand/genesis.json
%if %{RELEASE_GENESIS_PROCESS} != "x"
  /var/lib/algorand/genesis/devnet/genesis.json
  /var/lib/algorand/genesis/testnet/genesis.json
  /var/lib/algorand/genesis/betanet/genesis.json
  /var/lib/algorand/genesis/mainnet/genesis.json
%endif
/lib/systemd/system/algorand.service
/lib/systemd/system/algorand@.service
%config(noreplace) /etc/cron.hourly/0yum-algorand-hourly.cron
%config(noreplace) /etc/yum/yum-cron-algorand.conf
/etc/pki/rpm-gpg/RPM-GPG-KEY-Algorand
/usr/lib/algorand/yum.repos.d/algorand.repo

%changelog

%pre
getent passwd algorand >/dev/null || \
	useradd --system --home-dir /var/lib/algorand --no-create-home algorand >/dev/null

%post
chown -R algorand:algorand /var/lib/algorand
%systemd_post algorand

%preun
%systemd_preun algorand
%systemd_preun algorand@*

%postun
%systemd_postun_with_restart algorand
%systemd_postun_with_restart algorand@*

