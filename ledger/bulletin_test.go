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

package ledger

import (
	"testing"
	"time"
)

const epsilon = 5 * time.Millisecond

func TestBulletin(t *testing.T) {
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
