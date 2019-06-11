#!/bin/bash
# build centos rpm from inside docker
#
# mount src from outside
# --mount type=bind,src=${GOPATH}/src,dst=/root/go/src
#
# mount golang install from outside
# --mount type=bind,src=/usr/local/go,dst=/usr/local/go 
#
# output copied to /root/subhome/node_pkg
# --mount type=bind,src=${HOME},dst=/root/subhome

set -e
set -x

export HOME=/root
mkdir -p ${HOME}/go
mkdir -p ${HOME}/go/bin
export GOPATH=${HOME}/go
export PATH=${GOPATH}/bin:/usr/local/go/bin:${PATH}

go install golang.org/x/lint/golint
go install github.com/golang/dep/cmd/dep
go install golang.org/x/tools/cmd/stringer
go install github.com/go-swagger/go-swagger/cmd/swagger


cd ${GOPATH}/src/github.com/algorand/go-algorand

# definitely rebuild libsodium which could link to external C libraries
if [ -f ${GOPATH}/src/github.com/algorand/go-algorand/crypto/libsodium-fork/Makefile ]; then
    (cd ${GOPATH}/src/github.com/algorand/go-algorand/crypto/libsodium-fork && make distclean)
fi
rm -rf ${GOPATH}/src/github.com/algorand/go-algorand/crypto/lib
make ${GOPATH}/src/github.com/algorand/go-algorand/crypto/lib/libsodium.a

make build

RPMTMP=$(mktemp -d 2>/dev/null || mktemp -d -t "rpmtmp")
trap "rm -rf ${RPMTMP}" 0
scripts/build_rpm.sh ${RPMTMP}
cp -p ${RPMTMP}/*/*.rpm /root/subhome/node_pkg
