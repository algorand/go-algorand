// Copyright (C) 2019-2025 Algorand, Inc.
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

package pools

import (
	"errors"
)

// ErrStaleBlockAssemblyRequest returned by AssembleBlock when requested block number is older than the current transaction pool round
// i.e. typically it means that we're trying to make a proposal for an older round than what the ledger is currently pointing at.
var ErrStaleBlockAssemblyRequest = errors.New("AssembleBlock: requested block assembly specified a round that is older than current transaction pool round")

// ErrPendingQueueReachedMaxCap indicates the current transaction pool has reached its max capacity
var ErrPendingQueueReachedMaxCap = errors.New("TransactionPool.checkPendingQueueSize: transaction pool has reached capacity")

// ErrNoPendingBlockEvaluator indicates there is no pending block evaluator to accept a new tx group
var ErrNoPendingBlockEvaluator = errors.New("TransactionPool.ingest: no pending block evaluator")
