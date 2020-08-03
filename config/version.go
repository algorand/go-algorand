// Copyright (C) 2019-2020 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package config

import (
	"fmt"
	"strconv"
)

// Do NOT remove or rename these constants - they are inspected by build tools
// to generate the build tag and update package name

// We are intending to follow the principles set forth by the Semantic Versioning Specification
// https://semver.org/

// VersionMajor is the Major semantic version number (#.y.z) - changed when first public release (0.y.z -> 1.y.z)
// and when backwards compatibility is broken.
const VersionMajor = 2

// VersionMinor is the Minor semantic version number (x.#.z) - changed when backwards-compatible features are introduced.
// Not enforced until after initial public release (x > 0).
const VersionMinor = 1

// Version is the type holding our full version information.
type Version struct {

	// Algorand's major version number
	Major int

	// Algorand's minor version number
	Minor int

	// Algorand's Build Number
	BuildNumber int

	// Suffix for any metadata
	Suffix string

	// Hash of commit the build is based on
	CommitHash string

	// Branch the build is based on
	Branch string

	// Branch-derived release channel the build is based on
	Channel string

	// DataDirectory for the current instance
	DataDirectory string
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.BuildNumber)
}

// AsUInt64 returns the version struct in integer form
func (v Version) AsUInt64() (versionInfo uint64) {
	versionInfo = uint64(v.Major)
	versionInfo <<= 16
	versionInfo |= uint64(v.Minor)
	versionInfo <<= 16
	versionInfo |= uint64(v.BuildNumber)
	return
}

// func (v Version) GetSuffix() string {
// 	return v.Suffix
// }

// GetCommitHash returns the commit ID for the build's source
func (v Version) GetCommitHash() string {
	return v.CommitHash
}

func convertToInt(val string) int {
	if val == "" {
		return 0
	}
	value, _ := strconv.ParseInt(val, 10, 0)
	return int(value)
}

var currentVersion = Version{
	Major:         VersionMajor,
	Minor:         VersionMinor,
	BuildNumber:   convertToInt(BuildNumber), // set using -ldflags
	Suffix:        "",
	CommitHash:    CommitHash,
	Branch:        Branch,
	Channel:       Channel,
	DataDirectory: "",
}

// GetCurrentVersion retrieves a copy of the current global Version structure (for the application)
func GetCurrentVersion() Version {
	return currentVersion
}

// FormatVersionAndLicense prints current version and license information
func FormatVersionAndLicense() string {
	version := GetCurrentVersion()
	return fmt.Sprintf("%d\n%s.%s [%s] (commit #%s)\n%s\n", version.AsUInt64(), version.String(),
		version.Channel, version.Branch, version.GetCommitHash(), GetLicenseInfo())
}

// SetCurrentVersion allows replacing the current global Version structure (for the application)
func SetCurrentVersion(version Version) {
	currentVersion = version
}

// UpdateVersionDataDir is a convenience method for setting the data dir on the global Version struct
// Used by algod and algoh to set built-time ephemeral version component e.g. data directory
func UpdateVersionDataDir(dataDir string) {
	v := GetCurrentVersion()
	v.DataDirectory = dataDir
	SetCurrentVersion(v)
}

// GetAlgorandVersion retrieves the current version formatted as a simple version string (Major.Minor.BuildNumber)
func GetAlgorandVersion() string {
	return currentVersion.String()
}

// GetLicenseInfo retrieves the current license information
func GetLicenseInfo() string {
	return "go-algorand is licensed with AGPLv3.0\nsource code available at https://github.com/algorand/go-algorand"
}
