# Specification: Release Artifacts

## Overview

This document details all artifacts produced by the release process.

## Artifact Matrix

### Linux amd64

| Artifact | Description |
|----------|-------------|
| `algorand_{channel}_linux-amd64_{version}.deb` | Main node package (Debian/Ubuntu) |
| `algorand-devtools_{channel}_linux-amd64_{version}.deb` | Developer tools package (Debian/Ubuntu) |
| `algorand-{version}-1.x86_64.rpm` | Main node package (RHEL/Fedora) |
| `algorand-devtools-{version}-1.x86_64.rpm` | Developer tools package (RHEL/Fedora) |
| `node_{channel}_linux-amd64_{version}.tar.gz` | Node tarball (bin, data, genesis) |
| `install_{channel}_linux-amd64_{version}.tar.gz` | Bootstrap installer (updater only) |
| `tools_{channel}_linux-amd64_{version}.tar.gz` | Additional tools tarball |
| `hashes_{channel}_linux_amd64_{version}` | SHA256 checksums |

### Linux arm64

| Artifact | Description |
|----------|-------------|
| `algorand_{channel}_linux-arm64_{version}.deb` | Main node package (Debian/Ubuntu) |
| `algorand-devtools_{channel}_linux-arm64_{version}.deb` | Developer tools package (Debian/Ubuntu) |
| `algorand-{version}-1.aarch64.rpm` | Main node package (RHEL/Fedora) |
| `algorand-devtools-{version}-1.aarch64.rpm` | Developer tools package (RHEL/Fedora) |
| `node_{channel}_linux-arm64_{version}.tar.gz` | Node tarball (bin, data, genesis) |
| `install_{channel}_linux-arm64_{version}.tar.gz` | Bootstrap installer (updater only) |
| `tools_{channel}_linux-arm64_{version}.tar.gz` | Additional tools tarball |
| `hashes_{channel}_linux_arm64_{version}` | SHA256 checksums |

### macOS (darwin universal)

| Artifact | Description |
|----------|-------------|
| `node_{channel}_darwin-universal_{version}.tar.gz` | Node tarball (universal binary) |
| `install_{channel}_darwin-universal_{version}.tar.gz` | Bootstrap installer (universal) |
| `tools_{channel}_darwin-universal_{version}.tar.gz` | Additional tools tarball (universal) |
| `hashes_{channel}_darwin_universal_{version}` | SHA256 checksums |

### Metadata

| Artifact | Description |
|----------|-------------|
| `sbom.spdx.json` | Software Bill of Materials (SPDX format) |

## Package Contents

### algorand (main package)

**Binaries** (`/usr/bin/`):
- `algod` - Node daemon
- `goal` - CLI tool
- `kmd` - Key management daemon
- `algokey` - Key utility
- `algocfg` - Configuration tool
- `algoh` - Host utility
- `diagcfg` - Diagnostics configuration
- `node_exporter` - Prometheus metrics exporter

**Libraries** (`/usr/lib/algorand/`):
- `updater` - Auto-update binary
- `find-nodes.sh` - Node discovery script

**Data** (`/var/lib/algorand/`):
- `config.json.example` - Example configuration
- `system.json` - System configuration
- `genesis.json` - Default genesis (varies by channel)
- `genesis/devnet/genesis.json`
- `genesis/testnet/genesis.json`
- `genesis/mainnet/genesis.json`
- `genesis/betanet/genesis.json`
- `genesis/alphanet/genesis.json`

**Systemd** (`/lib/systemd/system/`):
- `algorand.service`
- `algorand@.service`

### algorand-devtools

**Binaries** (`/usr/bin/`):
- `carpenter` - Log analysis tool
- `tealdbg` - TEAL debugger
- `msgpacktool` - MessagePack utility

### Tarball Types

#### node_* tarball

Contains everything needed to run a node:
```
bin/
├── algod
├── goal
├── kmd
├── algokey
├── algocfg
├── algoh
├── diagcfg
├── node_exporter
├── updater
├── update.sh
├── find-nodes.sh
├── systemd-setup.sh
├── algorand@.service.template
├── sudoers.template
├── COPYING
└── genesisfiles/
    ├── devnet/genesis.json
    ├── testnet/genesis.json
    ├── mainnet/genesis.json
    ├── betanet/genesis.json
    └── alphanet/genesis.json
data/
├── config.json.example
└── genesis.json (default for channel)
test-utils/
├── algotmpl
└── COPYING
```

#### install_* tarball

Minimal bootstrap installer:
```
updater
update.sh
```

#### tools_* tarball

Additional development and operations tools:
```
algons
carpenter
coroner
dispenser
netgoal
nodecfg
pingpong
loadgenerator
dsign
catchpointdump
block-generator
sysctl.sh
sysctl-all.sh
COPYING
```

## Channel-Specific Behavior

### Default Genesis

The default `genesis.json` copied to package root varies by channel:

| Channel | Default Genesis |
|---------|-----------------|
| `nightly` | `devnet/genesis.json` |
| `beta` | `betanet/genesis.json` |
| `stable` | `mainnet/genesis.json` |

### Package Naming

The channel is embedded in package names:
- `.deb`: `algorand_{channel}_linux-{arch}_{version}.deb`
- `.rpm`: `algorand-{version}-1.{arch}.rpm` (channel not in name, but in repo)
- Tarballs: `node_{channel}_{os}-{arch}_{version}.tar.gz`

### APT Configuration

Packages include unattended-upgrades configuration:
```
/etc/apt/apt.conf.d/51algorand-upgrades
```

Content:
```
Unattended-Upgrade::Allowed-Origins {
    "Algorand:{channel}";
};
```

## Signing

### Current (GPG)

- `.deb` files: GPG detached signature (`.sig`)
- `.rpm` files: RPM signature + GPG detached signature (`.sig`)
- Tarballs: GPG detached signature (`.sig`)
- Hash files: GPG clearsign (`.asc`) + detached (`.sig`)

### Target (GitHub Attestations)

- All artifacts: Sigstore-based attestation
- Verification: `gh attestation verify <file> --owner algorand`

## Hash File Format

The `hashes_*` files contain:
```
<sha256sum>  <filename>
<sha256sum>  <filename>
...
```

Example:
```
a1b2c3d4...  algorand_stable_linux-amd64_4.5.0.deb
e5f6g7h8...  algorand-devtools_stable_linux-amd64_4.5.0.deb
i9j0k1l2...  node_stable_linux-amd64_4.5.0.tar.gz
```

## SBOM Format

SBOM is generated in SPDX JSON format using Syft:
```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "go-algorand",
  "packages": [
    {
      "name": "github.com/algorand/go-algorand",
      "versionInfo": "4.5.0",
      ...
    },
    // All Go module dependencies
  ]
}
```

## Storage Locations

### GitHub Releases

All artifacts attached to the release:
```
https://github.com/algorand/go-algorand/releases/tag/v{version}-{channel}
```

### S3

```
s3://{bucket}/{channel}/{version}/
├── linux/
│   ├── amd64/
│   │   ├── *.deb
│   │   ├── *.rpm
│   │   └── *.tar.gz
│   └── arm64/
│       ├── *.deb
│       ├── *.rpm
│       └── *.tar.gz
└── darwin/
    └── universal/
        └── *.tar.gz
```

### Nightly Latest

```
s3://{bucket}/nightly/latest/
```

Symlink/copy to most recent nightly build.
