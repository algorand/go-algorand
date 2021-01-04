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

package codes

const (
	// ExitCodeKMDLogError is returned if we can't open the log file
	ExitCodeKMDLogError = 2
	// ExitCodeKMDError is the catch-all exit code for most kmd errors
	ExitCodeKMDError = 3
	// ExitCodeKMDAlreadyRunning is returned if an instance of kmd is
	// already running in the given data directory
	ExitCodeKMDAlreadyRunning = 4
)
