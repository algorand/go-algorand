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

package node

import (
	"fmt"
)

// Catchpoint already in progress error

// CatchpointAlreadyInProgressError indicates that the requested catchpoint is already running
type CatchpointAlreadyInProgressError struct {
	catchpoint string
}

// MakeCatchpointAlreadyInProgressError creates the error
func MakeCatchpointAlreadyInProgressError(catchpoint string) *CatchpointAlreadyInProgressError {
	return &CatchpointAlreadyInProgressError{
		catchpoint: catchpoint,
	}
}

// Error satisfies builtin interface `error`
func (e *CatchpointAlreadyInProgressError) Error() string {
	return fmt.Sprintf("the requested catchpoint '%s' is already in progress, suppressing error", e.catchpoint)
}

// Catchpoint unable to start error

// CatchpointUnableToStartError indicates that the requested catchpoint cannot be started
type CatchpointUnableToStartError struct {
	catchpointRunning   string
	catchpointRequested string
}

// MakeCatchpointUnableToStartError creates the error
func MakeCatchpointUnableToStartError(catchpointRunning, catchpointRequested string) *CatchpointUnableToStartError {
	return &CatchpointUnableToStartError{
		catchpointRunning:   catchpointRunning,
		catchpointRequested: catchpointRequested,
	}
}

// Error satisfies builtin interface `error`
func (e *CatchpointUnableToStartError) Error() string {
	return fmt.Sprintf(
		"unable to start catchpoint catchup for '%s' - already catching up '%s'",
		e.catchpointRequested,
		e.catchpointRunning)
}
