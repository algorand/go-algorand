// Copyright (C) 2019-2021 Algorand, Inc.
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

package goal

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/algorand/go-algorand/test/framework/fixtures"
)

var fixture fixtures.GoalFixture

func TestMain(m *testing.M) {
	listMode := false
	flag.Parse()
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "test.list" {
			listMode = true
		}
	})
	if !listMode {
		fixture.SetupShared("GoalTests", filepath.Join("nettemplates", "TwoNodes50Each.json"))
		fixture.RunAndExit(m)
	} else {
		os.Exit(m.Run())
	}
}
