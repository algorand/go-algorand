package teal

import (
	"fmt"
	"testing"
)

//TODO: add more tests
const DebugMode = false

func TestMemorySegment_Snapshot(t *testing.T) {
	var want string

	m := NewMemorySegment(5)
	m.AllocateAt(2, NewUInt(22))
	m.SaveSnapshot()
	before := m.String()
	barr := NewByteArray(4)
	barr.Set(0, 7)
	m.AllocateAt(0, barr)

	t.Run("InitialSetup",
		func(t *testing.T) {
			want = "Memory Segment: (maxSize:5)\n[0, *teal.ByteArray)]--->[7 0 0 0]\n[1, <nil>)]---><nil>\n[2, *teal.UInt)]--->22\n[3, <nil>)]---><nil>\n[4, <nil>)]---><nil>"
			//if we put t.Error inside check() we won't be able to see the correct line number anymore
			if s := check(m.String(), want, t); s != "pass" {
				t.Error(s)
			}
		})

	t.Run("RestoringOnMainArray",
		func(t *testing.T) {
			m.RestoreSnapshot()
			if s := check(m.String(), before, t); s != "pass" {
				t.Error(s)
			}
			m.AllocateAt(4, NewUInt(3))
			m.RestoreSnapshot()
			if s := check(m.String(), before, t); s != "pass" {
				t.Error(s)
			}
		})

	t.Run("CompactAndExpand",
		func(t *testing.T) {
			m.DiscardSnapshot()
			want = "Memory Segment: (maxSize:5)\n[0, <nil>)]---><nil>\n[1, <nil>)]---><nil>\n[2, *teal.UInt)]--->22"
			if s := check(m.String(), want, t); s != "pass" {
				t.Error(s)
			}
			m.SaveSnapshot()
			m.AllocateAt(4, barr)
			m.DiscardSnapshot()
			want = "Memory Segment: (maxSize:5)\n[0, <nil>)]---><nil>\n[1, <nil>)]---><nil>\n[2, *teal.UInt)]--->22\n[3, <nil>)]---><nil>\n[4, *teal.ByteArray)]--->[7 0 0 0]"
			if s := check(m.String(), want, t); s != "pass" {
				t.Error(s)
			}
		})

	t.Run("RestoringMultipleUpdates",
		func(t *testing.T) {
			m.SaveSnapshot()
			barr.Set(0, 3)
			m.SaveSnapshot()
			before = m.String()
			barr.Set(0, 5)
			barr.Set(2, 6)
			barr.Set(2, 10)
			m.compact()
			i, _ := m.Get(2)
			i.(*UInt).SetValue(45)
			m.Delete(2)
			want = "Memory Segment: (maxSize:5)\n[0, <nil>)]---><nil>\n[1, <nil>)]---><nil>\n[2, <nil>)]---><nil>\n[3, <nil>)]---><nil>\n[4, *teal.ByteArray)]--->[5 0 10 0]"
			if s := check(m.String(), want, t); s != "pass" {
				t.Error(s)
			}
			m.AllocateAt(2, NewUInt(42))
			m.AllocateAt(0, NewUInt(11))
			i, _ = m.Get(0)
			i.(*UInt).SetValue(15)
			i.(*UInt).SetValue(16)
			want = "Memory Segment: (maxSize:5)\n[0, *teal.UInt)]--->16\n[1, <nil>)]---><nil>\n[2, *teal.UInt)]--->42\n[3, <nil>)]---><nil>\n[4, *teal.ByteArray)]--->[5 0 10 0]"
			if s := check(m.String(), want, t); s != "pass" {
				t.Error(s)
			}
			m.RestoreSnapshot()
			if s := check(m.String(), before, t); s != "pass" {
				t.Error(s)
			}
		})

	/*
		t.Run("RestoringOnMainArray",
			func(t *testing.T) {
			})
	*/

}

func TestMemorySegment_AllocateAt(t *testing.T) {
	var err error
	m := NewMemorySegment(0)

	err = m.AllocateAt(0, NewUInt(6))
	if _, ok := err.(*OutOfBoundsError); !ok {
		t.Errorf("Invalid error in 0 size memory: (%T: %v)", err, err)
	}
	m = NewMemorySegment(5)
	m.DiscardSnapshot()
	err = m.AllocateAt(5, NewUInt(5))
	if _, ok := err.(*OutOfBoundsError); !ok {
		t.Errorf("Invalid error: (%T: %v)", err, err)
	}
	want := "Memory Segment: (maxSize:5)"
	if s := check(m.String(), want, t); s != "pass" {
		t.Error(s)
	}
	m.AllocateAt(2, NewUInt(12))
	want = "Memory Segment: (maxSize:5)\n[0, <nil>)]---><nil>\n[1, <nil>)]---><nil>\n[2, *teal.UInt)]--->12\n[3, <nil>)]---><nil>\n[4, <nil>)]---><nil>"
	if s := check(m.String(), want, t); s != "pass" {
		t.Error(s)
	}
	m.DiscardSnapshot()
	err = m.AllocateAt(2, NewUInt(12))
	if err != ErrCellNotEmpty {
		t.Errorf("Invalid error: (%T: %v)", err, err)
	}
	m.AllocateAt(0, NewUInt(7))
	want = "Memory Segment: (maxSize:5)\n[0, *teal.UInt)]--->7\n[1, <nil>)]---><nil>\n[2, *teal.UInt)]--->12"
	if s := check(m.String(), want, t); s != "pass" {
		t.Error(s)
	}
}

func TestMemorySegment_Get(t *testing.T) {
	var err error
	m := NewMemorySegment(0)

	_, err = m.Get(0)
	if _, ok := err.(*OutOfBoundsError); !ok {
		t.Errorf("Invalid error in 0 size memory: (%T: %v)", err, err)
	}
	m = NewMemorySegment(8)
	barr := NewByteArray(3)
	barr.Set(2, 12)
	m.AllocateAt(2, barr)
	m.DiscardSnapshot()
	_, err = m.Get(0)
	if err != ErrCellIsEmpty {
		t.Errorf("Invalid error: (%T: %v)", err, err)
	}
	_, err = m.Get(3)
	if err != ErrCellIsEmpty {
		t.Errorf("Invalid error after compaction: (%T: %v)", err, err)
	}
	temp, _ := m.Get(2)
	_, err = temp.(*ByteArray).Get(3)
	if _, ok := err.(*OutOfBoundsError); !ok {
		t.Errorf("Invalid error: (%T: %v)", err, err)
	}
	if b, _ := barr.Get(2); b != 12 {
		t.Errorf("Error in getting values of a ByteArray. we got: %v we wanted %v", b, 12)
	}
}

func check(got, want string, t *testing.T) string {
	if myPrint(got) != want {
		return fmt.Sprintf("\nWhile running [%v]:\nwe want:\n%v\nbut we got:\n%v", t.Name(), want, got)
	}
	return "pass"
}

func myPrint(str string) string {
	if DebugMode {
		fmt.Printf("%v\n============\n", str)
	}
	return str
}
