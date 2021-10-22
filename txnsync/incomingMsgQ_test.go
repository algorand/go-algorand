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
/*	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/algorand/msgp/msgp"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/crypto"
	"github.com/algorand/go-algorand/data/pooldata"
	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/test/partitiontest"*/
)

func (imq *incomingMessageQueue) fillMessageQueue(msg incomingMessage) {
	imq.enqueuedPeersMu.Lock()
	for i := 0; i < maxPeersCount; i++ {
		imq.enqueuedMessages[i] = msg
	}
	imq.firstMessage = 1
	imq.lastMessage = 0
	imq.enqueuedPeersCond.Signal()
	imq.enqueuedPeersMu.Unlock()

	// reading this channel would fill up the staging "msg" in messagePump
	<-imq.getIncomingMessageChannel()

	// take the lock again, and update the indices.
	imq.enqueuedPeersMu.Lock()
	imq.firstMessage = 1
	imq.lastMessage = 0
	imq.enqueuedPeersMu.Unlock()
}
