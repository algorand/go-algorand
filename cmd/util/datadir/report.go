// Copyright (C) 2019-2024 Algorand, Inc.
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

package datadir

// TODO: eliminate duplication (copied from cmd/algocfg/report.go)

import (
	"fmt"
	"os"
)

func reportInfof(format string, args ...interface{}) {
	fmt.Printf(format+"\n", args...)
}

func reportErrorln(args ...interface{}) {
	fmt.Fprintln(os.Stderr, args...)
	os.Exit(1)
}

// TODO: Replace all report functions with the higher grade ones from cmd/algo

func reportErrorf(format string, args ...interface{}) {
	reportErrorln(fmt.Sprintf(format, args...))
}
