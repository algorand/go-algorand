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

package linttest

import (
	"fmt"
)

type myStruct struct {
	d int32
	e float64
	f bool
}

func (m *myStruct) willError() error {
	return fmt.Errorf("an error occurred")
}

func doSomething() {
	m := myStruct{d: 2, e: 2.0}
	err := m.willError()
	if err != nil {
		fmt.Printf("error")
	}

	var x myStruct
	x = myStruct{f: true}
	x.f = false
}

func init() {
	//doSomething()
}
