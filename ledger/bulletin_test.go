// Copyright (C) 2019-2023 Algorand, Inc.
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

package ledger

import (
	"testing"
	"time"

	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/test/partitiontest"
	"github.com/stretchr/testify/require"
)

const epsilon = 5 * time.Millisecond

func TestBulletin(t *testing.T) {
	partitiontest.PartitionTest(t)

	bul := makeBulletin()

	bul.committedUpTo(1)
	<-bul.Wait(1) // Should finish immediately
	<-bul.Wait(1) // Should finish immediately

	select {
	case <-bul.Wait(2):
		t.Errorf("<-Wait(2) finished early")
		t.FailNow()
	default:
		// Correct
	}

	bul.committedUpTo(2)

	select {
	case <-bul.Wait(2):
		// Correct
	case <-time.After(epsilon):
		t.Errorf("<-Wait(2) finished late")
	}

	eventSequence := make(chan string, 3)
	go func() {
		<-bul.Wait(3)
		eventSequence <- "A: Finished waiting on 3"
	}()
	go func() {
		<-bul.Wait(3)
		eventSequence <- "B: Finished waiting on 3"
	}()
	go func() {
		time.Sleep(epsilon)
		eventSequence <- "Notifying 3"
		bul.committedUpTo(3)
	}()

	<-bul.Wait(3)
	e1, e2, e3 := <-eventSequence, <-eventSequence, <-eventSequence
	if e1 != "Notifying 3" {
		t.Errorf("Wrong order: %v, %v, %v", e1, e2, e3)
	}

	select {
	case <-bul.Wait(5):
		t.Errorf("<-Wait(5) finished early")
		t.FailNow()
	default:
		// Correct
	}

	bul.committedUpTo(7)

	select {
	case <-bul.Wait(6):
		// Correct
	case <-time.After(epsilon):
		t.Errorf("<-Wait(6) finished late")
	}

	go func() {
		time.Sleep(epsilon)
		bul.committedUpTo(20)
	}()
	select {
	case <-bul.Wait(10):
		// Correct
	case <-time.After(time.Second):
		t.Errorf("<-Wait(10) finished late")
	}
}

func TestCancelWait(t *testing.T) {
	bul := makeBulletin()

	// Calling Wait before CancelWait
	waitCh := bul.Wait(5)
	bul.CancelWait(5)
	bul.committedUpTo(5)
	select {
	case <-waitCh:
		t.Errorf("<-Wait(5) should have been cancelled")
	case <-time.After(epsilon):
		// Correct
	}
	require.NotContains(t, bul.pendingNotificationRequests, basics.Round(5))

	// CancelWait is called before Wait
	bul.CancelWait(6)
	select {
	case <-bul.Wait(6):
		t.Errorf("<-Wait(6) should have been cancelled")
	case <-time.After(epsilon):
		// Correct
	}
	require.Contains(t, bul.pendingNotificationRequests, basics.Round(6))
	require.Equal(t, bul.pendingNotificationRequests[basics.Round(6)].count, 1)
	bul.CancelWait(6)
	require.NotContains(t, bul.pendingNotificationRequests, basics.Round(6))

	// Two Waits, one cancelled
	waitCh1 := bul.Wait(7)
	waitCh2 := bul.Wait(7)
	require.EqualValues(t, waitCh1, waitCh2)
	bul.CancelWait(7)
	select {
	case <-waitCh1:
		t.Errorf("<-Wait(7) should not be notified yet")
	case <-time.After(epsilon):
		// Correct
	}
	// Still one waiter
	require.Contains(t, bul.pendingNotificationRequests, basics.Round(7))
	require.Equal(t, bul.pendingNotificationRequests[basics.Round(7)].count, 1)

	bul.committedUpTo(7)
	select {
	case <-waitCh1:
		// Correct
	case <-time.After(epsilon):
		t.Errorf("<-Wait(7) should have been notified")
	}
	require.NotContains(t, bul.pendingNotificationRequests, basics.Round(7))

	// Wait followed by Cancel for a round that already completed
	waitCh = bul.Wait(5)
	bul.CancelWait(5)
	require.NotContains(t, bul.pendingNotificationRequests, basics.Round(5))
	select {
	case <-waitCh:
		// Correct
	case <-time.After(epsilon):
		t.Errorf("<-Wait(5) should have been notified right away")
	}
}
