package deadlock

import (
	"log"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var _ = log.Println

func restore() func() {
	opts := Opts
	return func() {
		Opts = opts
	}
}

func TestNoDeadlocks(t *testing.T) {
	defer restore()()
	Opts.DeadlockTimeout = time.Millisecond * 5000
	var a RWMutex
	var b Mutex
	var c RWMutex
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 5; k++ {
				func() {
					a.Lock()
					defer a.Unlock()
					func() {
						b.Lock()
						defer b.Unlock()
						func() {
							c.RLock()
							defer c.RUnlock()
							time.Sleep(time.Duration((1000 + rand.Intn(1000))) * time.Millisecond / 200)
						}()
					}()
				}()
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 5; k++ {
				func() {
					a.RLock()
					defer a.RUnlock()
					func() {
						b.Lock()
						defer b.Unlock()
						func() {
							c.Lock()
							defer c.Unlock()
							time.Sleep(time.Duration((1000 + rand.Intn(1000))) * time.Millisecond / 200)
						}()
					}()
				}()
			}
		}()
	}
	wg.Wait()
}

func TestHardDeadlock(t *testing.T) {
	defer restore()()
	Opts.DisableLockOrderDetection = true
	Opts.DeadlockTimeout = time.Millisecond * 20
	var deadlocks uint32
	Opts.OnPotentialDeadlock = func() {
		atomic.AddUint32(&deadlocks, 1)
	}
	var mu Mutex
	mu.Lock()
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		mu.Lock()
		defer mu.Unlock()
	}()
	select {
	case <-ch:
	case <-time.After(time.Millisecond * 100):
	}
	if atomic.LoadUint32(&deadlocks) != 1 {
		t.Fatalf("expected 1 deadlock, detected %d", deadlocks)
	}
	log.Println("****************")
	mu.Unlock()
	<-ch
}

func TestRWMutex(t *testing.T) {
	defer restore()()
	Opts.DeadlockTimeout = time.Millisecond * 20
	var deadlocks uint32
	Opts.OnPotentialDeadlock = func() {
		atomic.AddUint32(&deadlocks, 1)
	}
	var a RWMutex
	a.RLock()
	go func() {
		// We detect a potential deadlock here.
		a.Lock()
		defer a.Unlock()
	}()
	time.Sleep(time.Millisecond * 100) // We want the Lock call to happen.
	ch := make(chan struct{})
	go func() {
		// We detect a potential deadlock here.
		defer close(ch)
		a.RLock()
		defer a.RUnlock()
	}()
	select {
	case <-ch:
		t.Fatal("expected a timeout")
	case <-time.After(time.Millisecond * 50):
	}
	a.RUnlock()
	if atomic.LoadUint32(&deadlocks) != 2 {
		t.Fatalf("expected 2 deadlocks, detected %d", deadlocks)
	}
	<-ch
}

func TestLockDuplicate(t *testing.T) {
	defer restore()()
	Opts.DeadlockTimeout = 0
	var deadlocks uint32
	Opts.OnPotentialDeadlock = func() {
		atomic.AddUint32(&deadlocks, 1)
	}
	var a RWMutex
	var b Mutex
	go func() {
		a.RLock()
		a.Lock()
		a.RUnlock()
		a.Unlock()
	}()
	go func() {
		b.Lock()
		b.Lock()
		b.Unlock()
		b.Unlock()
	}()
	time.Sleep(time.Second * 1)
	if atomic.LoadUint32(&deadlocks) != 2 {
		t.Fatalf("expected 2 deadlocks, detected %d", deadlocks)
	}
}

func TestDeadlockRecursiveFail(t *testing.T) {
	defer restore()()
	deadlockDetected := 0
	Opts.DeadlockTimeout = time.Millisecond * 100
	Opts.OnPotentialDeadlock = func() {
		deadlockDetected = 1
		panic(nil)
	}
	mu := Mutex{}
	defer func() {
		if r := recover(); r == nil {
			// code paniced as expected.
		}
		mu.Unlock()
	}()

	mu.Lock()
	mu.Lock()
	if deadlockDetected == 0 {
		t.Fail()
	}
}

func TestLockOrderDetectionFail(t *testing.T) {
	defer restore()()
	deadlockDetected := 0
	Opts.DeadlockTimeout = time.Millisecond * 100
	Opts.OnPotentialDeadlock = func() {
		deadlockDetected = 1
		panic(nil)
	}
	c := make(chan struct{})
	d := make(chan struct{})
	mu1 := Mutex{}
	mu2 := Mutex{}

	mu1.Lock()
	go func() {
		defer func() {
			if r := recover(); r == nil {
				// code paniced as expected.
			}
			close(d)
		}()
		mu2.Lock()
		close(c)
		// this *should* fail, panicing.
		mu1.Lock()
	}()
	<-c
	<-d
	if deadlockDetected == 0 {
		t.Fail()
	}
	mu2.Unlock()
	mu1.Unlock()
}

func TestLockOrderDetectionSuccess(t *testing.T) {
	c := make(chan struct{})
	d := make(chan struct{})
	mu1 := Mutex{}
	mu2 := Mutex{}
	mu1.Lock()
	mu2.Lock()
	go func() {
		mu2.Lock()
		mu1.Lock()
		close(d)
	}()
	time.Sleep(time.Millisecond * 100)
	go func() {
		mu1.Unlock()
		mu2.Unlock()
		close(c)
	}()
	<-c
	<-d
	mu1.Unlock()
	mu2.Unlock()
}

func TestDeadlockRecursiveSuccess(t *testing.T) {
	mu := Mutex{}
	mu2 := Mutex{}
	mu.Lock()
	go func() {
		mu2.Lock()
		mu.Unlock()
	}()
	mu.Lock()
	mu2.Unlock()
	mu.Unlock()
}

func TestRWMutexDoubleRLockFail(t *testing.T) {
	defer restore()()
	var deadlocks uint32
	Opts.OnPotentialDeadlock = func() {
		atomic.AddUint32(&deadlocks, 1)
	}
	var a RWMutex
	d := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r == nil {
				// code paniced as expected.
			}
			close(d)
		}()
		a.RLock()
		a.RLock()
	}()
	<-d
	if atomic.LoadUint32(&deadlocks) != 1 {
		t.Fatalf("expected 1 deadlocks, detected %d", deadlocks)
	}
}
