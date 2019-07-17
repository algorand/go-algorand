// Copyright (C) 2019 Algorand, Inc.
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

package main

import "github.com/spf13/cobra"

const (
	stdoutFilenameValue = "-"
	stdinFileNameValue  = "-"
)

// validateNoPosArgsFn is a reusable cobra positional argument validation function
// for generating proper error messages when commands see unexpected arguments when they expect no args.
// We don't use cobra.NoArgs directly, in case we want to customize behavior later.
var validateNoPosArgsFn = cobra.NoArgs
