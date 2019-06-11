package deadlock

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/petermattis/goid"
)

// Opts control how deadlock detection behaves.
// Options are supposed to be set once at a startup (say, when parsing flags).
var Opts = struct {
	// Mutex/RWMutex would work exactly as their sync counterparts
	// -- almost no runtime penalty, no deadlock detection if Disable == true.
	Disable bool
	// Would disable lock order based deadlock detection if DisableLockOrderDetection == true.
	DisableLockOrderDetection bool
	// Waiting for a lock for longer than DeadlockTimeout is considered a deadlock.
	// Ignored is DeadlockTimeout <= 0.
	DeadlockTimeout time.Duration
	// OnPotentialDeadlock is called each time a potential deadlock is detected -- either based on
	// lock order or on lock wait time.
	OnPotentialDeadlock func()
	// Will keep MaxMapSize lock pairs (happens before // happens after) in the map.
	// The map resets once the threshold is reached.
	MaxMapSize int
	// Will dump stacktraces of all goroutines when inconsistent locking is detected.
	PrintAllCurrentGoroutines bool
	mu                        *sync.Mutex // Protects the LogBuf.
	// Will print deadlock info to log buffer.
	LogBuf io.Writer
}{
	DeadlockTimeout: time.Second * 30,
	OnPotentialDeadlock: func() {
		os.Exit(2)
	},
	MaxMapSize: 1024 * 64,
	mu:         &sync.Mutex{},
	LogBuf:     os.Stderr,
}

type lockID uint64

var counterMu sync.Mutex
var currID = lockID(1)

type identifiable interface {
	id() lockID
}

// A Mutex is a drop-in replacement for sync.Mutex.
// Performs deadlock detection unless disabled in Opts.
type Mutex struct {
	muId lockID
	mu   sync.Mutex
}

func (m *Mutex) id() lockID {
	return m.muId
}

// Lock locks the mutex.
// If the lock is already in use, the calling goroutine
// blocks until the mutex is available.
//
// Unless deadlock detection is disabled, logs potential deadlocks to Opts.LogBuf,
// calling Opts.OnPotentialDeadlock on each occasion.
func (m *Mutex) Lock() {
	counterMu.Lock()
	if m.muId == 0 {
		m.muId = currID
		currID++
	}
	counterMu.Unlock()
	lock(m.mu.Lock, m, false)
}

// Unlock unlocks the mutex.
// It is a run-time error if m is not locked on entry to Unlock.
//
// A locked Mutex is not associated with a particular goroutine.
// It is allowed for one goroutine to lock a Mutex and then
// arrange for another goroutine to unlock it.
func (m *Mutex) Unlock() {
	m.mu.Unlock()
	if !Opts.Disable {
		postUnlock(m)
	}
}

// An RWMutex is a drop-in replacement for sync.RWMutex.
// Performs deadlock detection unless disabled in Opts.
type RWMutex struct {
	muId lockID
	mu   sync.RWMutex
}

func (m *RWMutex) id() lockID {
	return m.muId
}

// Lock locks rw for writing.
// If the lock is already locked for reading or writing,
// Lock blocks until the lock is available.
// To ensure that the lock eventually becomes available,
// a blocked Lock call excludes new readers from acquiring
// the lock.
//
// Unless deadlock detection is disabled, logs potential deadlocks to Opts.LogBuf,
// calling Opts.OnPotentialDeadlock on each occasion.
func (m *RWMutex) Lock() {
	counterMu.Lock()
	if m.muId == 0 {
		m.muId = currID
		currID++
	}
	counterMu.Unlock()

	lock(m.mu.Lock, m, false)
}

// Unlock unlocks the mutex for writing.  It is a run-time error if rw is
// not locked for writing on entry to Unlock.
//
// As with Mutexes, a locked RWMutex is not associated with a particular
// goroutine.  One goroutine may RLock (Lock) an RWMutex and then
// arrange for another goroutine to RUnlock (Unlock) it.
func (m *RWMutex) Unlock() {
	m.mu.Unlock()
	if !Opts.Disable {
		postUnlock(m)
	}
}

// RLock locks the mutex for reading.
//
// Unless deadlock detection is disabled, logs potential deadlocks to Opts.LogBuf,
// calling Opts.OnPotentialDeadlock on each occasion.
func (m *RWMutex) RLock() {
	counterMu.Lock()
	if m.muId == 0 {
		m.muId = currID
		currID++
	}
	counterMu.Unlock()

	lock(m.mu.RLock, m, true)
}

// RUnlock undoes a single RLock call;
// it does not affect other simultaneous readers.
// It is a run-time error if rw is not locked for reading
// on entry to RUnlock.
func (m *RWMutex) RUnlock() {
	m.mu.RUnlock()
	if !Opts.Disable {
		postUnlock(m)
	}
}

// RLocker returns a Locker interface that implements
// the Lock and Unlock methods by calling RLock and RUnlock.
func (m *RWMutex) RLocker() sync.Locker {
	return (*rlocker)(m)
}

func preLock(skip int, p identifiable, gid int64, checkRecursiveLocking bool) {
	lo.preLock(skip, p, gid, checkRecursiveLocking)
}

func postLock(skip int, p identifiable, gid int64) {
	lo.postLock(skip, p, gid)
}

func postUnlock(p identifiable) {
	lo.postUnlock(p)
}

func checkRecursiveLocking(skip int, p identifiable, gid int64) {
	lo.checkRecursiveLocking(skip, p, gid)
}

func checkLockOrdering(skip int, p identifiable, gid int64) {
	lo.checkLockOrdering(skip, p, gid)
}

func lock(lockFn func(), ptr identifiable, preLockCheckRecursiveLocking bool) {
	if Opts.Disable {
		lockFn()
		return
	}
	// grab the current goroutine identifier
	gid := goid.Get()
	preLock(4, ptr, gid, preLockCheckRecursiveLocking)
	if Opts.DeadlockTimeout <= 0 {
		lockFn()
	} else {
		ch := make(chan struct{})
		go func() {
			lockFn()
			close(ch)
		}()
		for {
			t := time.NewTimer(Opts.DeadlockTimeout)
			defer t.Stop()
			select {
			case <-t.C:
				if !preLockCheckRecursiveLocking {
					checkRecursiveLocking(4, ptr, gid)
				}
				checkLockOrdering(4, ptr, gid)
				lo.mu.Lock()

				prev, ok := lo.cur[ptr.id()]
				if !ok {
					lo.mu.Unlock()
					break // Nobody seems to be holding the lock, try again.
				}
				Opts.mu.Lock()
				fmt.Fprintln(Opts.LogBuf, header)
				fmt.Fprintln(Opts.LogBuf, "Previous place where the lock was grabbed")
				fmt.Fprintf(Opts.LogBuf, "goroutine %v lock %p\n", prev.gid, ptr)
				printStack(Opts.LogBuf, prev.stack)
				fmt.Fprintln(Opts.LogBuf, "Have been trying to lock it again for more than", Opts.DeadlockTimeout)
				fmt.Fprintf(Opts.LogBuf, "goroutine %v lock %p\n", gid, ptr)
				printStack(Opts.LogBuf, callers(2))
				stacks := stacks()
				grs := bytes.Split(stacks, []byte("\n\n"))
				for _, g := range grs {
					if goid.ExtractGID(g) == prev.gid {
						fmt.Fprintln(Opts.LogBuf, "Here is what goroutine", prev.gid, "doing now")
						Opts.LogBuf.Write(g)
						fmt.Fprintln(Opts.LogBuf)
					}
				}
				lo.other(ptr)
				if Opts.PrintAllCurrentGoroutines {
					fmt.Fprintln(Opts.LogBuf, "All current goroutines:")
					Opts.LogBuf.Write(stacks)
				}
				fmt.Fprintln(Opts.LogBuf)
				if buf, ok := Opts.LogBuf.(*bufio.Writer); ok {
					buf.Flush()
				}
				Opts.mu.Unlock()
				lo.mu.Unlock()
				Opts.OnPotentialDeadlock()
				<-ch
				postLock(4, ptr, gid)
				return
			case <-ch:
				postLock(4, ptr, gid)
				return
			}
		}
	}
	postLock(4, ptr, gid)
}

type lockOrder struct {
	mu    sync.Mutex
	cur   map[lockID]stackGID // stacktraces + gids for the locks currently taken.
	order map[beforeAfter]ss  // expected order of locks.
}

type stackGID struct {
	stack []uintptr
	gid   int64
}

type beforeAfter struct {
	before lockID
	after  lockID
}

type ss struct {
	before []uintptr
	after  []uintptr
}

var lo = newLockOrder()

func newLockOrder() *lockOrder {
	return &lockOrder{
		cur:   map[lockID]stackGID{}, // maps each lock identifier to the stack that was acquired after the lock was taken.
		order: map[beforeAfter]ss{},
	}
}

func (l *lockOrder) postLock(skip int, p identifiable, gid int64) {
	stack := callers(skip)
	l.mu.Lock()
	l.cur[p.id()] = stackGID{stack, gid}
	l.mu.Unlock()
}

func (l *lockOrder) printRecursiveLocking(currentGoRoutineID int64, otherLockID lockID, currentStack []uintptr, otherStack []uintptr, p identifiable) {
	Opts.mu.Lock()
	fmt.Fprintln(Opts.LogBuf, header, "Recursive locking:")
	fmt.Fprintf(Opts.LogBuf, "current goroutine %d lock %x\n", currentGoRoutineID, otherLockID)
	printStack(Opts.LogBuf, currentStack)
	fmt.Fprintln(Opts.LogBuf, "Previous place where the lock was grabbed (same goroutine)")
	printStack(Opts.LogBuf, otherStack)
	l.other(p)
	if buf, ok := Opts.LogBuf.(*bufio.Writer); ok {
		buf.Flush()
	}
	Opts.mu.Unlock()
	Opts.OnPotentialDeadlock()
}

func (l *lockOrder) printLockOrdering(currentGoRoutineID int64, otherLockID lockID, currentStack []uintptr, otherStack []uintptr, p identifiable, s ss) {
	Opts.mu.Lock()
	fmt.Fprintln(Opts.LogBuf, header, "Inconsistent locking. saw this ordering in one goroutine:")
	fmt.Fprintln(Opts.LogBuf, "happened before")
	printStack(Opts.LogBuf, s.before)
	fmt.Fprintln(Opts.LogBuf, "happened after")
	printStack(Opts.LogBuf, s.after)
	fmt.Fprintln(Opts.LogBuf, "in another goroutine: happened before")
	printStack(Opts.LogBuf, otherStack)
	fmt.Fprintln(Opts.LogBuf, "happened after")
	printStack(Opts.LogBuf, currentStack)
	l.other(p)
	fmt.Fprintln(Opts.LogBuf)
	if buf, ok := Opts.LogBuf.(*bufio.Writer); ok {
		buf.Flush()
	}
	Opts.mu.Unlock()
	Opts.OnPotentialDeadlock()
}

func (l *lockOrder) checkRecursiveLocking(skip int, p identifiable, gid int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	lockID := p.id()
	for otherLockID, otherLockStack := range l.cur {
		if otherLockStack.gid != gid { // We want locks taken in the same goroutine only.
			continue
		}
		if otherLockID == lockID {
			// we want to wait up to Opt.DeadlockTimeout before giving up.
			stack := callers(skip)
			l.printRecursiveLocking(gid, otherLockID, stack, otherLockStack.stack, p)
		}
	}
}
func (l *lockOrder) checkLockOrdering(skip int, p identifiable, gid int64) {
	if Opts.DisableLockOrderDetection {
		return
	}

	lockID := p.id()
	l.mu.Lock()
	defer l.mu.Unlock()
	for otherLockID, otherLockStack := range l.cur {
		if otherLockStack.gid != gid { // We want locks taken in the same goroutine only.
			continue
		}
		if otherLockID == lockID {
			// we want to wait up to Opt.DeadlockTimeout before giving up.
			// we will do this testing during the lock() function.
			continue
		}

		if s, ok := l.order[beforeAfter{lockID, otherLockID}]; ok {
			stack := callers(skip)
			l.printLockOrdering(gid, otherLockID, stack, otherLockStack.stack, p, s)
		}
	}
}

func (l *lockOrder) storeLockOrder(skip int, p identifiable, gid int64) {
	if Opts.DisableLockOrderDetection {
		return
	}

	stack := callers(skip)
	lockID := p.id()
	l.mu.Lock()
	defer l.mu.Unlock()
	for otherLockID, otherLockStack := range l.cur {
		if otherLockStack.gid != gid { // We want locks taken in the same goroutine only.
			continue
		}
		if otherLockID == lockID {
			// we want to wait up to Opt.DeadlockTimeout before giving up.
			// we will do this testing during the lock() function.
			continue
		}

		l.order[beforeAfter{otherLockID, lockID}] = ss{otherLockStack.stack, stack}
		if len(l.order) == Opts.MaxMapSize { // Reset the map to keep memory footprint bounded.
			l.order = map[beforeAfter]ss{}
		}
	}
}

func (l *lockOrder) preLock(skip int, p identifiable, gid int64, checkRecursiveLocking bool) {
	if Opts.DeadlockTimeout <= 0 || checkRecursiveLocking {
		l.checkRecursiveLocking(skip, p, gid)
		l.checkLockOrdering(skip, p, gid)
	}

	l.storeLockOrder(skip, p, gid)
}

func (l *lockOrder) pruneLockOrder(p identifiable) {
	prunedBa := make([]beforeAfter, 0)
	for ba := range l.order {
		if ba.after == p.id() {
			// remove this entry.
			prunedBa = append(prunedBa, ba)
		}
	}
	for _, ba := range prunedBa {
		delete(l.order, ba)
	}
}

func (l *lockOrder) postUnlock(p identifiable) {
	l.mu.Lock()
	delete(l.cur, p.id())
	l.pruneLockOrder(p)
	l.mu.Unlock()
}

type rlocker RWMutex

func (r *rlocker) Lock()   { (*RWMutex)(r).RLock() }
func (r *rlocker) Unlock() { (*RWMutex)(r).RUnlock() }

// Under lo.mu Locked.
func (l *lockOrder) other(ptr identifiable) {
	empty := true
	for k := range l.cur {
		if k == ptr.id() {
			continue
		}
		empty = false
	}
	if empty {
		return
	}
	fmt.Fprintln(Opts.LogBuf, "Other goroutines holding locks:")
	for k, pp := range l.cur {
		if k == ptr.id() {
			continue
		}
		fmt.Fprintf(Opts.LogBuf, "goroutine %v lock %x\n", pp.gid, k)
		printStack(Opts.LogBuf, pp.stack)
	}
	fmt.Fprintln(Opts.LogBuf)
}

const header = "POTENTIAL DEADLOCK:"
