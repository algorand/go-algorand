package agreement

import (
	"testing"

	"github.com/algorand/go-algorand/util/timers"
	"github.com/algorand/go-deadlock"
	"github.com/stretchr/testify/assert"
)

func TestClockManagerSerialization(t *testing.T) {
	cm := makeClockManager(&timers.Monotonic{})
	//clock := timers.MakeMonotonicClock(time.Date(2015, 1, 2, 5, 6, 7, 8, time.UTC))
	rnd := makeRoundRandomBranch(350)
	//cm.m[rnd] = clock
	cm.setZero(rnd)

	enc := cm.Encode()

	cm2 := makeClockManager(&timers.Monotonic{})
	cm3, err := cm2.Decode(enc)
	assert.NoError(t, err)
	cm.mu, cm3.mu = deadlock.Mutex{}, deadlock.Mutex{}
	assert.Equal(t, cm, cm3)
}
