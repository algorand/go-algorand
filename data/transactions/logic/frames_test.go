// Copyright (C) 2019-2024 Algorand, Inc.
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
  return						// proto subs must appear in deadcode
 double:
  proto 1 2
  frame_dig -1
  int 2
  *
  frame_bury 0
  retsub
  pushint 2
  popn 1
  dupn 4
  bury 9
`

const frameCompiled = "438a01028bff240b8c00898102460147044509"

func TestDupPopN(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// These two are equally dumbs uses of popn, and should perhaps be banned
	testAccepts(t, "int 1; popn 0", fpVersion)
	testAccepts(t, "int 1; dup; popn 1;", fpVersion)

	testAccepts(t, "int 1; int 1; int 1; popn 2", fpVersion)
	testAccepts(t, "int 1; int 0; popn 1", fpVersion)
	testPanics(t, "int 1; int 0; popn 2", fpVersion)
	testProg(t, "int 1; int 0; popn 3", LogicVersion, exp(1, "popn 3 expects 3..."))
	testPanics(t, notrack("int 1; int 0; popn 3"), fpVersion)

	testAccepts(t, `int 7; dupn 250; dupn 250; dupn 250; dupn 249;
	               popn 250;  popn 250;  popn 250;  popn 249; int 7; ==`,
		fpVersion)
	// We could detect this in assembler if we checked pgm.stack > maxStackDepth
	// at each step. But it seems vanishly unlikely to have a detetectable
	// instance of this bug in real code.
	testPanics(t, `int 1; dupn 250; dupn 250; dupn 250; dupn 250
	              popn 250;  popn 250;  popn 250;  popn 250; !`,
		fpVersion, "stack overflow")
}

func TestDupPopNTyping(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testProg(t, "int 8; dupn 2; +; pop", LogicVersion)
	testProg(t, "int 8; dupn 2; concat; pop", LogicVersion, exp(1, "...wanted type []byte..."))

	testProg(t, "popn 1", LogicVersion, exp(1, "...expects 1 stack argument..."))
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
        dupn 1					// room for the return value
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
	// We normally report a non-deadcode `proto` at assembly time.  But it still
	// must fail at evaluation.
	testPanics(t, notrack("proto 0 0; int 1"), fpVersion, "proto was executed without a callsub")
	testAccepts(t, "callsub a; a: proto 0 0; int 1", fpVersion)

	// the assembler could detect this, since we know stack height, but it's
	// rare to KNOW the height, and hard to get the knowledge to the right place
	testPanics(t, `
    callsub toodeep
toodeep:
    proto 10 1
    int 1
    return
`, fpVersion, "callsub to proto that requires 10 args")

	// the assembler could detect this, since sub is one basic block
	testPanics(t, `
    int 5; int 10; callsub eatsargs
    int 1; return
eatsargs:
    proto 2 1
    +
    retsub
`, fpVersion, "retsub executed with stack below frame")

	// the assembler could detect this, since sub is one basic block
	testPanics(t, `
    int 5; int 10; callsub donothing
    int 1; return
donothing:						// does not leave return value above args
    proto 2 1
    retsub
`, fpVersion, "retsub executed with no return values on stack")

	// the assembler could detect this, since sub is one basic block
	testPanics(t, `
    int 5; int 10; callsub only1
    int 1; return
only1:						// leaves only 1 return val
    proto 2 2
    dup2; +
    retsub
`, fpVersion, "retsub executed with 1 return values on stack")

	testAccepts(t, `
    int 5; int 10; callsub fine
    int 1; return
fine:
    proto 2 2
    dup2
    retsub
`, fpVersion)

	testAccepts(t, `
    int 5; int 10; callsub extra
    int 1; return
extra:
    proto 2 2
    dup2; dup2
    retsub
`, fpVersion)

	// the assembler could potentially complain about the stack going below fp,
	// since the sub is one basic block.
	testAccepts(t, `
 int 10
 int 20
 callsub main
 int 1; return
main:
 proto 2 1
 +           // This consumes the top arg. We could complain in assembly if checked stack height against pgm.fp
 dup; dup	 // But the dup;dup restores it, so it _evals_ fine.
 retsub
`, fpVersion)

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
`, fpVersion, "retsub executed with no return values on stack")

	testPanics(t, `
        b main
     a: proto 0 3
        int 1; int 2	// only 2. need 3
        retsub
  main: callsub a
        !
`, fpVersion, "retsub executed with 2 return values on stack")

	// Extra is fine. They are "locals", and they are cleared
	testAccepts(t, `
        b main
     a: proto 0 3
        int 7; dupn 3	// height grows by 4. only needed 3
        retsub
  main: callsub a // returns 3 7s
        +; +; int 21; ==
`, fpVersion)
}

func TestFrameAccess(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

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
        int 0; int 0			// room for sum and one "local", a loop variable

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

	testPanics(t, notrack(`
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
`), fpVersion, "frame_dig -3 in sub with 2")

	testPanics(t, notrack(`
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
`), fpVersion, "frame_bury -3 in sub with 2")

	source := `
        b main
   add: proto 2 1
        frame_dig 0				// return slot. but wasn't allocated
        retsub
  main: int 8
        int 2
        callsub add
        int 1
        return
`
	testProg(t, source, fpVersion, exp(4, "frame_dig above stack"))
	testPanics(t, notrack(source), fpVersion, "frame_dig above stack")

	source = `
        b main
   add: proto 2 1
        int 0; dupn 2			// allocate return slot plus two locals
        frame_dig 3				// but look beyond
        retsub
  main: int 8
        int 2
        callsub add
        int 1
        return
`
	testProg(t, source, fpVersion, exp(5, "frame_dig above stack"))
	testPanics(t, notrack(source), fpVersion, "frame_dig above stack")

	// Note that at the moment of frame_bury, the stack IS big enough, because
	// the 4 would essentially be written over itself. But because frame_bury
	// pops, we consider this to be beyond the stack.
	source = `
        b main
   add: proto 2 1
        int 0; dupn 2				// allocate return slot plus two locals
        int 4
        frame_bury 3				// but put "beyond"
        retsub
  main: int 8
        int 2
        callsub add
        int 1
        return
`
	testProg(t, source, fpVersion, exp(6, "frame_bury above stack"))
	testPanics(t, notrack(source), fpVersion, "frame_bury above stack")
}

func TestFrameAccesAtStart(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testPanics(t, "frame_dig 1", fpVersion, "frame_dig with empty callstack")
	testPanics(t, "int 7; frame_bury 1", fpVersion, "frame_bury with empty callstack")
}

func TestFrameAccessAboveStack(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := `
     int 1
     callsub main
main:
     proto 1 1
     pop						// argument popped
     frame_dig -1				// but then frame_dig used to get at it
`
	testProg(t, source, fpVersion, exp(7, "frame_dig above stack"))
	testPanics(t, notrack(source), fpVersion, "frame_dig above stack")

	testAccepts(t, `
     int 2
     callsub main
     int 1; ==; return
main:
     proto 1 1
     int 7
     frame_dig 0; int 7; ==;
     frame_bury 0;
     retsub
`, fpVersion)

	// almost the same but try to use a "local" slot without pushing first
	source = `
     int 2
     callsub main
     int 1; ==; return
main:
     proto 1 1
     int 7
     frame_dig 1; int 7; ==;
     frame_bury 1;
     retsub
`
	testProg(t, source, fpVersion, exp(8, "frame_dig above stack"))
	testPanics(t, notrack(source), fpVersion)
}

func TestFrameAccessBelowStack(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := `
     int 1
     callsub main
main:
     proto 1 1
     frame_dig -10				// digging down below arguments
`
	testProg(t, source, fpVersion, exp(6, "frame_dig -10 in sub with 1 arg..."))
	testPanics(t, notrack(source), fpVersion, "frame_dig -10 in sub with 1 arg")

	testPanics(t, `
     int 1
     callsub main
main:
     frame_dig -10				// digging down below arguments
`, fpVersion, "frame_dig below stack")

	source = `
     int 1
     callsub main
main:
     proto 1 15
     frame_bury -10				// burying down below arguments
`
	testProg(t, source, fpVersion, exp(6, "frame_bury -10 in sub with 1 arg..."))
	testPanics(t, notrack(source), fpVersion, "frame_bury -10 in sub with 1 arg")

	// Without `proto`, frame_bury can't be checked by assembler, but still panics
	source = `
     int 1
     callsub main
main:
     frame_bury -10				// burying down below arguments
`
	testPanics(t, source, fpVersion, "frame_bury below stack")

}

// TestDirectDig is an example of using dig instead of frame_dig, notice that
// the offset needs to account for the added stack height of second call.
func TestDirectDig(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	source := `
     int 3
     int 5
     callsub double_both
     +
     int 16; ==; return
double_both:
     proto 2 2
     dig 1; int 2; *			// dig for first arg
     dig 1; int 2; *			// dig for second
     retsub
`
	testProg(t, source, fpVersion)
	testAccepts(t, source, fpVersion)
}
