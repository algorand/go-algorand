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

package nodecontrol

import (
	"fmt"
)

var errKMDDataDirNotAbs = fmt.Errorf("kmd data dir must be absolute path")
var errKMDExitedEarly = fmt.Errorf("kmd exited before we could contact it")

type errAlgodExitedEarly struct {
	innerError error
}

func (e *errAlgodExitedEarly) Error() string {
	if e.innerError == nil {
		return "node exited before we could contact it"
	}
	return fmt.Sprintf("node exited with an error code, check node.log for more details : %v", e.innerError)
}

func (e *errAlgodExitedEarly) Unwrap(err error) error {
	return e.innerError
}
