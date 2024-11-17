#!/usr/bin/env bash
set -e

. /etc/os-release
DISTRIB=$ID

ARCH_DEPS="expect jq autoconf shellcheck sqlite python-virtualenv"
UBUNTU_DEPS="libtool expect jq autoconf automake shellcheck sqlite3 python3-venv build-essential"
FEDORA_DEPS="expect jq autoconf ShellCheck sqlite python-virtualenv"
OPENSUSE_TUMBLEWEED_DEPS="make gcc-c++ python3 glibc-devel-static libtool expect jq autoconf ShellCheck sqlite3 python312-virtualenv"

case $DISTRIB in
    "arch" | "manjaro")
        pacman -S --refresh --needed --noconfirm $ARCH_DEPS
        ;;
    "fedora")
        dnf -y install $FEDORA_DEPS
        ;;
    "opensuse-tumbleweed")
        zypper --non-interactive install $OPENSUSE_TUMBLEWEED_DEPS
        ;;
    *)
        apt-get update
        apt-get -y install $UBUNTU_DEPS
        ;;
esac
