#!/usr/bin/env bash

# build_environment.sh - Describe the toolchain behind a release build, as JSON.
#
# Syntax:   build_environment.sh build|package
#
# Outputs:  JSON on stdout.
#           build:   the runner, the Go toolchain settings, and the C toolchain
#                    (compiler, assembler, linker, autotools) plus the static
#                    libraries and startup files the external linker pulls into
#                    the binaries, and our libsodium.a. Each file is listed with
#                    its sha256 and, where dpkg or pacman owns it, the package
#                    name and version.
#           package: the runner and the nFPM binary used to make .deb/.rpm files.
#
# Usage:    Run from the repository root after `make` (build) or once nFPM is on
#           PATH (package). The release workflows attest this output for each
#           platform's artifacts with the in-toto predicate type
#           https://github.com/algorand/go-algorand/build-environment/v1, so a
#           rebuild can recreate the same toolchain and check it by hash.
#
# Requires: jq

set -euo pipefail

if [ "$#" -ne 1 ] || { [ "$1" != build ] && [ "$1" != package ]; }; then
    echo "Syntax: build_environment.sh build|package" >&2
    exit 1
fi

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# Prints "<package>\t<version>" for the package that owns a file, or nothing.
owner() {
    local pkg
    if command -v dpkg-query >/dev/null 2>&1; then
        pkg=$(dpkg -S "$1" 2>/dev/null | grep -v '^diversion' | head -1 | cut -d: -f1 || true)
        if [ -n "${pkg}" ]; then
            printf '%s\t%s\n' "${pkg}" "$(dpkg-query -W -f='${Version}' "${pkg}")"
        fi
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Qo "$1" 2>/dev/null | sed -n 's/.* is owned by \([^ ]*\) \(.*\)$/\1\t\2/p'
    fi
}

# Prints a JSON object describing one file; skips names that do not resolve.
entry() {
    local name=$1 path=$2 own pkg="" ver=""
    # MinGW compilers report Windows paths (D:/...); MSYS2 tools need POSIX ones.
    if [[ "${path}" =~ ^[A-Za-z]:[/\\] ]] && command -v cygpath >/dev/null 2>&1; then
        path=$(cygpath -u "${path}")
    fi
    if [[ "${path}" != /* ]]; then
        path=$(command -v "${path}" 2>/dev/null) || return 0
    fi
    [ -e "${path}" ] || return 0
    # Package databases record real paths, not the symlinks and ../ segments
    # that tool lookups return. On MSYS2 they also record the .exe suffix.
    path=$(realpath "${path}")
    if [ -e "${path}.exe" ]; then
        path="${path}.exe"
    fi
    own=$(owner "${path}")
    if [ -n "${own}" ]; then
        pkg=${own%%$'\t'*}
        ver=${own#*$'\t'}
    fi
    jq -n --arg name "${name}" --arg path "${path}" --arg sha256 "$(sha256 "${path}")" \
        --arg package "${pkg}" --arg version "${ver}" \
        '{name: $name, path: $path, sha256: $sha256}
         + (if $package == "" then {} else {package: $package, version: $version} end)'
}

runner_json() {
    local os
    if [ -r /etc/os-release ]; then
        os=$(. /etc/os-release && echo "${PRETTY_NAME}")
    elif command -v sw_vers >/dev/null 2>&1; then
        os="macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion))"
    else
        os=$(uname -s)
    fi
    # ImageOS and ImageVersion are set on GitHub-hosted runners and identify
    # the runner image release, whose software list GitHub publishes. Linux
    # release builds run in a container instead, named by BUILD_CONTAINER_IMAGE;
    # its apt sources show which archive snapshot the toolchain came from.
    jq -n --arg image_os "${ImageOS:-}" --arg image_version "${ImageVersion:-}" \
        --arg container_image "${BUILD_CONTAINER_IMAGE:-}" \
        --arg apt_sources "$(cat /etc/apt/sources.list.d/*.sources /etc/apt/sources.list 2>/dev/null |
            sed -n -e 's/^URIs: *//p' -e 's/^deb  *\(\[[^]]*\]  *\)\{0,1\}\([^ ]*\).*/\2/p' | sort -u)" \
        --arg os "${os}" --arg kernel "$(uname -srm)" \
        '{image_os: $image_os, image_version: $image_version, container_image: $container_image,
          apt_sources: ($apt_sources | split("\n") | map(select(. != ""))), os: $os, kernel: $kernel}'
}

if [ "$1" = package ]; then
    nfpm=$(command -v nfpm)
    jq -n --argjson runner "$(runner_json)" \
        --arg path "${nfpm}" --arg sha256 "$(sha256 "${nfpm}")" \
        --arg buildinfo "$(go version -m "${nfpm}")" \
        '{runner: $runner, nfpm: {path: $path, sha256: $sha256, buildinfo: $buildinfo}}'
    exit 0
fi

CC=$(go env CC)
CXX=$(go env CXX)

# gcc reports bare names for programs found on PATH and absolute paths for its
# own internals; clang does the same for ld. Names a compiler does not know
# (cc1 under clang) come back unchanged and are skipped by entry().
tool_entries() {
    entry cc "${CC}"
    entry cxx "${CXX}"
    entry cc1 "$(${CC} -print-prog-name=cc1)"
    entry cc1plus "$(${CXX} -print-prog-name=cc1plus)"
    entry as "$(${CC} -print-prog-name=as)"
    entry ld "$(${CC} -print-prog-name=ld)"
    entry make make
    entry autoconf autoconf
    entry automake automake
    if command -v glibtoolize >/dev/null 2>&1; then
        entry libtoolize glibtoolize
    else
        entry libtoolize libtoolize
    fi
}

# Files the external linker reads for a static release link, as reported by
# -Wl,--trace on Linux. macOS links its system libraries dynamically, so the
# SDK version recorded below stands in for them there.
case "$(go env GOOS)" in
    windows)
        LINK_INPUTS=(crt2.o crtbegin.o crtend.o libgcc.a libgcc_eh.a libstdc++.a libmingw32.a
            libmingwex.a libmoldname.a libmsvcrt.a libucrt.a libwinpthread.a libpthread.a) ;;
    linux)
        LINK_INPUTS=(crt1.o crti.o crtn.o crtbeginT.o crtend.o libc.a libm.a libmvec.a libpthread.a
            libdl.a libgcc.a libgcc_eh.a libstdc++.a) ;;
    *)
        LINK_INPUTS=() ;;
esac

link_entries() {
    local name path
    # The +"..." form keeps bash 3.2 (macOS /bin/bash) from rejecting an empty
    # array as unbound under set -u.
    for name in ${LINK_INPUTS[@]+"${LINK_INPUTS[@]}"}; do
        path=$(${CC} -print-file-name="${name}")
        # An unknown name comes back unchanged rather than as a path.
        [ "${path}" != "${name}" ] || continue
        entry "${name}" "${path}"
        # glibc's libm.a is a linker script naming the archives that hold the code.
        if head -c 64 "${path}" | grep -q 'GNU ld script'; then
            for path in $(grep -o '/[^ )]*\.a' "${path}"); do
                entry "$(basename "${path}")" "${path}"
            done
        fi
    done
}

libsodium_entries() {
    local lib
    for lib in crypto/libs/*/*/lib/libsodium.a; do
        [ -e "${lib}" ] || continue
        jq -n --arg path "${lib}" --arg sha256 "$(sha256 "${lib}")" '{path: $path, sha256: $sha256}'
    done
}

platform_json() {
    if command -v xcodebuild >/dev/null 2>&1; then
        jq -n --arg xcode "$(xcodebuild -version | tr '\n' ' ' | sed 's/ *$//')" \
            --arg sdk_version "$(xcrun --show-sdk-version)" \
            --arg sdk_build "$(xcrun --show-sdk-build-version)" \
            --arg compiler "$(${CC} --version | head -1)" \
            --arg homebrew "$(brew list --versions autoconf automake libtool gnu-tar 2>/dev/null || true)" \
            '{xcode: $xcode, sdk_version: $sdk_version, sdk_build: $sdk_build,
              compiler: $compiler, homebrew: ($homebrew | split("\n") | map(select(. != "")))}'
    else
        jq -n --arg compiler "$(${CC} --version | head -1)" '{compiler: $compiler}'
    fi
}

jq -n --argjson runner "$(runner_json)" \
    --argjson go "$(go env -json GOVERSION GOOS GOARCH GOAMD64 GOARM64 CC CXX CGO_ENABLED CGO_CFLAGS CGO_LDFLAGS GOFLAGS GOTOOLCHAIN GOMODCACHE)" \
    --argjson platform "$(platform_json)" \
    --argjson tools "$(tool_entries | jq -s .)" \
    --argjson link_inputs "$(link_entries | jq -s 'unique_by(.path)')" \
    --argjson libsodium "$(libsodium_entries | jq -s .)" \
    '{runner: $runner, go: $go} + $platform
     + {tools: $tools, link_inputs: $link_inputs, libsodium: $libsodium}'
