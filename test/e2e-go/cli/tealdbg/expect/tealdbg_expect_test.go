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
package expect

import (
	"testing"

	"github.com/algorand/go-algorand/test/framework/fixtures"
)

// TestTealdbgWithExpect processes all expect script files with suffix Test.exp within the test/e2e-go/cli/tealdbg/expect directory
func TestTealdbgWithExpect(t *testing.T) {
	et := fixtures.MakeExpectTest(t)
	et.Run()
}
