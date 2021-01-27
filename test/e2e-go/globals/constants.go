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

package globals

import (
	"time"

	"github.com/algorand/go-algorand/gen"
)

// MaxTimePerRound is the upper bound of expected time per round
const MaxTimePerRound = time.Duration(10 * time.Second)

// TotalMoney is the total number of tokens in the system
// This needs to be identical to the value in gen/generate.go
const TotalMoney uint64 = gen.TotalMoney
