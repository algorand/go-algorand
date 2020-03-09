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

package transactions

import (
	"reflect"
	"testing"
)

func TestApplicationCallFieldsNotChanged(t *testing.T) {
	af := ApplicationCallTxnFields {}
	s := reflect.ValueOf(&af).Elem()

	if s.NumField() != 9 {
		t.Errorf("You added or removed a field from ApplicationCallTxnFields. " +
			 "Please ensure you have updated the Empty() method and then " +
			 "fix this test")
	}
}
