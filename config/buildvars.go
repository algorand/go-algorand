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

package config

/* Build time variables set through -ldflags */

// BuildNumber is the monotonic build number, currently based on the date and hour-of-day.
// It will be set to a build number by the build tools (for 'production' builds for now)
var BuildNumber string

// CommitHash is the git commit id in effect when the build was created.
// It will be set by the build tools (for 'production' builds for now)
var CommitHash string

// Branch is the git branch in effect when the build was created.
// It will be set by the build tools
var Branch string

// Channel is the computed release channel based on the Branch in effect when the build was created.
// It will be set by the build tools
var Channel string

// DefaultDeadlock is the default setting to use for EnableDeadlockDetection.  It's computed for the build
// based on the current branch being built - intending to disable deadlock detection in 'production' builds.
var DefaultDeadlock string
