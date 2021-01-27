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

package transactions

import (
	"fmt"

	"github.com/algorand/go-algorand/data/basics"
)

// MinFeeError defines an error type which could be returned from the method WellFormed
type MinFeeError string

func (err MinFeeError) Error() string {
	return string(err)
}

func makeMinFeeErrorf(format string, args ...interface{}) MinFeeError {
	return MinFeeError(fmt.Sprintf(format, args...))
}

// TxnDeadError defines an error type which indicates a transaction is outside of the
// round validity window.
type TxnDeadError struct {
	Round      basics.Round
	FirstValid basics.Round
	LastValid  basics.Round
}

func (err TxnDeadError) Error() string {
	return fmt.Sprintf("txn dead: round %d outside of %d--%d", err.Round, err.FirstValid, err.LastValid)
}
