Name:          @PKG_NAME@
Version:       @VER@
Release:       1
Summary:       Algorand tools software
URL:           https://www.algorand.com
License:       AGPL-3+
Requires:      @REQUIRED_ALGORAND_PKG@ >= @VER@

%define SRCDIR go-algorand-rpmbuild
%define _buildshell /bin/bash

%description
This package provides development tools for the Algorand blockchain.

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
for f in carpenter catchupsrv msgpacktool tealcut tealdbg; do
  install -m 755 ${ALGO_BIN}/${f} %{buildroot}/usr/bin/${f}
done

mkdir -p %{buildroot}/etc/pki/rpm-gpg
install -m 644 ${REPO_DIR}/installer/rpm/RPM-GPG-KEY-Algorand %{buildroot}/etc/pki/rpm-gpg/RPM-GPG-KEY-Algorand

mkdir -p %{buildroot}/usr/lib/algorand/yum.repos.d
install -m 644 ${REPO_DIR}/installer/rpm/algorand-devtools/algorand-devtools.repo %{buildroot}/usr/lib/algorand/yum.repos.d/algorand-devtools.repo

%files
/usr/bin/carpenter
/usr/bin/catchupsrv
/usr/bin/msgpacktool
/usr/bin/tealcut
/usr/bin/tealdbg
/etc/pki/rpm-gpg/RPM-GPG-KEY-Algorand
/usr/lib/algorand/yum.repos.d/algorand-devtools.repo

