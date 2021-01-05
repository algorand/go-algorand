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

package server

import (
	"fmt"
)

var errDataDirRequired = fmt.Errorf("WalletServerConfig.DataDir is required")
var errSessionManagerRequired = fmt.Errorf("WalletServerConfig.SessionManager must be initialized")
var errLogRequired = fmt.Errorf("WalletServerConfig.Log is required")

// ErrAlreadyRunning is returned if we failed to start kmd because we couldn't
// acquire its file lock. We export this so that the kmd cli can return a
// different exit code for this situation
var ErrAlreadyRunning = fmt.Errorf("failed to lock kmd.lock; is an instance of kmd already running in this data directory?")
