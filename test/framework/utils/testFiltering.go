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

package utils

import (
	"testing"
	"runtime"
)

// SkipTestOnPlatform skips tests when running on particular platform(s)
// This utility is temporary and will be removed once the arm64 and Darwin failures are resolved. 
func SkipTestOnPlatform(t *testing.T, ubuntuAMD64, arm64, macOSAMD64 bool ) {

	if runtime.GOOS == "darwin" && macOSAMD64 {
		t.Skip()
	} else if runtime.GOOS == "linux" && runtime.GOARCH == "arm64" && arm64 {
		t.Skip()
	} else if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" && ubuntuAMD64 {
		t.Skip()
	}
}
