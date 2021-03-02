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

package txnsync

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBeta(t *testing.T) {
	beta0 := beta(0)
	beta10000 := beta(10000)
	require.GreaterOrEqual(t, int64(beta0), int64(100*time.Millisecond))
	require.LessOrEqual(t, int64(beta10000), int64(20*time.Millisecond))
	for i := 50; i < 20000; i += 50 {
		prev := beta(i - 50)
		cur := beta(i)
		require.LessOrEqualf(t, int64(cur), int64(prev), fmt.Sprintf("beta(%d) < beta(%d)", i, i-50))
	}

}
