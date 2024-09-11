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

package prefetcher

import (
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
)

// GroupTaskError indicates the group index of the unfulfilled resource
type GroupTaskError struct {
	err            error
	GroupIdx       int64
	Address        *basics.Address
	CreatableIndex basics.CreatableIndex
	CreatableType  basics.CreatableType
}

// Error satisfies builtin interface `error`
func (err *GroupTaskError) Error() string {
	return fmt.Sprintf("prefetch failed for groupIdx %d, address: %s, creatableIndex %d, creatableType %d, cause: %v",
		err.GroupIdx, err.Address, err.CreatableIndex, err.CreatableType, err.err)
}

// Unwrap provides access to the underlying error
func (err *GroupTaskError) Unwrap() error {
	return err.err
}
