#!/usr/bin/env bash
set -e

. /etc/os-release
DISTRIB=$ID

ARCH_DEPS="boost boost-libs expect jq autoconf shellcheck sqlite python-virtualenv"
UBUNTU_DEPS="libtool libboost-math-dev expect jq autoconf shellcheck sqlite3 python3-venv"
FEDORA_DEPS="boost-devel expect jq autoconf ShellCheck sqlite python-virtualenv"

if [ "${DISTRIB}" = "arch" ]; then
    pacman -S --refresh --needed --noconfirm $ARCH_DEPS
elif [ "${DISTRIB}" = "fedora" ]; then
    dnf -y install $FEDORA_DEPS
else
    apt-get update
    apt-get -y install $UBUNTU_DEPS
fi
