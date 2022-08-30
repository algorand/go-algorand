// Copyright (C) 2019-2022 Algorand, Inc.
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

package logic

import (
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
)

const frameNonsense = `
 double:
  proto 1 1
  pushn 1						// one return value
  frame_dig -1
  int 2
  *
  frame_bury 0
  retsub
  pushint 2
  popn 1
`

const frameCompiled = "f00101f301f1ff240bf200898102f401"

func TestPushPopN(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// These two are dumbs uses of pushn, and should perhaps be banned
	testAccepts(t, "pushn 0; int 1", fpVersion)
	testAccepts(t, "pushn 1; !", fpVersion)

	// These two are equally dumbs uses of popn, and should perhaps be banned
	testAccepts(t, "int 1; popn 0", fpVersion)
	testAccepts(t, "int 1; dup; popn 1;", fpVersion)

	testAccepts(t, "pushn 2; pop; !", fpVersion)
	testAccepts(t, "pushn 3; !; assert; !; assert; !", fpVersion)
	testPanics(t, "pushn 2", fpVersion)

	testAccepts(t, "int 1; int 1; int 1; popn 2", fpVersion)
	testAccepts(t, "int 1; int 0; popn 1", fpVersion)
	testPanics(t, "int 1; int 0; popn 2", fpVersion)
	testProg(t, "int 1; int 0; popn 3", LogicVersion, Expect{1, "popn 3 expects 3..."})
	testPanics(t, notrack("int 1; int 0; popn 3"), fpVersion)

	testAccepts(t, `pushn 250; pushn 250; pushn 250; pushn 250;
                    popn 250;  popn 250;  popn 250;  popn 249; !`,
		fpVersion)
	testPanics(t, `pushn 250; pushn 250; pushn 250; pushn 251
                   popn 250;  popn 250;  popn 250;  popn 250; !`,
		fpVersion)
}

func TestPushPopNTyping(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	testProg(t, "pushn 2; +", LogicVersion)
	testProg(t, "pushn 2; concat", LogicVersion, Expect{1, "...wanted type []byte..."})

	testProg(t, "popn 1", LogicVersion, Expect{1, "...expects 1 stack argument..."})
}

func TestSimpleFrame(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testAccepts(t, `
        int 3
        int 4
        callsub hyp
        int 5
        ==
        return
      hyp:
        proto 2 1
        pushn 1					// room for the return value
        frame_dig -1
        frame_dig -1
        *
        frame_dig -2
        frame_dig -2
        *
        +
        sqrt
        frame_bury 0				// place return value
        retsub
`, fpVersion)
}

func TestProtoChecks(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()
	// We should report an unlabeled `proto` at assembly time.  For bonus
	// points, it should be illegal even if labeled, if the label was not in a
	// deadcode region.
	testPanics(t, "proto 0 0; int 1", fpVersion)
	testAccepts(t, "callsub a; a: proto 0 0; int 1", fpVersion)
}

func TestVoidSub(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testAccepts(t, `
        b main
     a: proto 0 0
        int 4	// junk local should get cleared
        retsub
  main: callsub a
        int 1	// would fail because of two stack items unless 4 cleared
`, fpVersion)

	testPanics(t, `
        b main
     a: int 4	// junk local should not get cleared (no "proto")
        retsub
  main: callsub a
        int 1	// fails because two items on stack
`, 4) // test back to retsub introduction
}

func TestForgetReturn(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testAccepts(t, `
        b main
     a: proto 0 1
        int 5 // Just placing on stack is a fine way to return
        retsub
  main: callsub a
        int 5
        ==
`, fpVersion)

	testPanics(t, `
        b main
     a: proto 0 1
        // Oops. No return value
        retsub
  main: callsub a
        !
`, fpVersion)

	testPanics(t, `
        b main
     a: proto 0 3
        pushn 2	// only 2. need 3
        retsub
  main: callsub a
        !
`, fpVersion)

	// Extra is fine. They are "locals", and they are cleared
	testAccepts(t, `
        b main
     a: proto 0 3
        pushn 4	// height grows by 4. only needed 3
        retsub
  main: callsub a // returns 3 zeros
        +; +; !
`, fpVersion)
}

func TestFrameAccess(t *testing.T) {
	testAccepts(t, `
        b main
   add: proto 2 1
        frame_dig -1
        frame_dig -2
        +
        retsub
  main: int 8
        int 2
        callsub add
        int 10
        ==
`, fpVersion)

	testAccepts(t, `
        b main
  ijsum:
        proto 2 1
        pushn 2					// room for sum and one "local", a loop variable

        frame_dig -2			// first arg
        frame_bury 1			// initialize loop var
   loop:
        // test for loop exit
        frame_dig 1				// loop var
        frame_dig -1			// second arg
        >
        bnz break

        // add loop var into sum
        frame_dig 1
        frame_dig 0				// the sum, to be returned
        +
        frame_bury 0

        // inc the loop var
        frame_dig 1
        int 1
        +
        frame_bury 1
        b loop
  break:
        retsub					// sum is sitting in frame_dig 0, which will end up ToS

  main: int 2
        int 8
        callsub ijsum
        int 35					// 2+3+4+5+6+7+8
        ==
`, fpVersion)

	testPanics(t, `
        b main
   add: proto 2 1
        frame_dig -1
        frame_dig -3
        +
        retsub
  main: int 8
        int 2
        callsub add
        int 10
        ==
`, fpVersion, "frame_dig -3 in sub with 2")

	testPanics(t, `
        b main
   add: proto 2 1
        frame_dig -1
        int 5
        frame_bury -3
        +
        retsub
  main: int 8
        int 2
        callsub add
        int 10
        ==
`, fpVersion, "frame_bury -3 in sub with 2")

	testPanics(t, `
        b main
   add: proto 2 1
        frame_dig 0				// return slot. but wasn't allocated
        retsub
  main: int 8
        int 2
        callsub add
        int 1
        return
`, fpVersion, "frame_dig above stack")

	testPanics(t, `
        b main
   add: proto 2 1
        pushn 3					// allocate return slot plus two locals
        frame_dig 3				// but look beyond
        retsub
  main: int 8
        int 2
        callsub add
        int 1
        return
`, fpVersion, "frame_dig above stack")

	// Note that at the moment of frame_bury, the stack IS big enough, because
	// the 4 would essentially be written over itself. But because frame_bury
	// pops, we consider this to be beyond the stack.
	testPanics(t, `
        b main
   add: proto 2 1
        pushn 3					// allocate return slot plus two locals
        int 4
        frame_bury 3				// but put "beyond"
        retsub
  main: int 8
        int 2
        callsub add
        int 1
        return
`, fpVersion, "frame_bury above stack")
}
