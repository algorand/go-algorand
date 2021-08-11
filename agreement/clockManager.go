package agreement

import (
	"sort"
	"time"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/timers"
	"github.com/algorand/go-deadlock"
)

// clockManager managers multiple clocks used by different pipelined rounds.
// XXX garbage-collect old rounds
type clockManager struct {
	mu deadlock.Mutex
	m  map[round]timers.Clock
	zm map[round]time.Time // XXX mostly just to support testing with testingClock

	t0 timers.Clock
}

func makeClockManager(t0 timers.Clock) *clockManager {
	return &clockManager{m: make(map[round]timers.Clock), zm: make(map[round]time.Time), t0: t0}
}

func (cm *clockManager) setZero(r round) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.zm[r] = time.Now().UTC()
	cm.m[r] = cm.t0.Zero()
}

// nextDeadlineCh returns a timeout channel that will fire when the earliest Deadline among all of
// the rounds described in externalDemuxSignals has occurred. It also returns the corresponding
// round (including speculative branch) this timeout channel corresponds to.
func (cm *clockManager) nextDeadlineCh(es []externalDemuxSignals) (<-chan time.Time, round) {
	if len(es) == 0 {
		return nil, roundZero
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()

	sort.Slice(es, func(i, j int) bool {
		ti := cm.zm[es[i].CurrentRound].Add(es[i].Deadline)
		tj := cm.zm[es[j].CurrentRound].Add(es[j].Deadline)
		//ti := cm.m[es[i].CurrentRound].GetTimeout(es[i].Deadline)
		//tj := cm.m[es[j].CurrentRound].GetTimeout(es[j].Deadline)
		return ti.Before(tj)
	})
	r := es[0].CurrentRound
	c, ok := cm.m[r]
	if !ok {
		// no rezeroAction has set up this clock yet
		// XXX this should probably only happen at service bootstrap or in tests
		logging.Base().Warnf("clockManager.nextDeadlineCh making new clock for round %+v", r)
		cm.zm[r] = time.Now().UTC()
		c = cm.t0.Zero()
		cm.m[r] = c
	}
	return c.TimeoutAt(es[0].Deadline), r
}

// nextFastDeadlineCh returns a timeout channel that will fire when the earliest FastRecoveryDeadline among all of
// the rounds described in externalDemuxSignals has occurred. It also returns the corresponding
// round (including speculative branch) this timeout channel corresponds to.
func (cm *clockManager) nextFastDeadlineCh(es []externalDemuxSignals) (<-chan time.Time, round) {
	if len(es) == 0 {
		return nil, roundZero
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()

	sort.Slice(es, func(i, j int) bool {
		ti := cm.zm[es[i].CurrentRound].Add(es[i].FastRecoveryDeadline)
		tj := cm.zm[es[j].CurrentRound].Add(es[j].FastRecoveryDeadline)
		//ti := cm.m[es[i].CurrentRound].GetTimeout(es[i].FastRecoveryDeadline)
		//tj := cm.m[es[j].CurrentRound].GetTimeout(es[j].FastRecoveryDeadline)
		return ti.Before(tj)
	})
	return cm.m[es[0].CurrentRound].TimeoutAt(es[0].FastRecoveryDeadline), es[0].CurrentRound
}

type clockManagerSerialized struct {
	Clocks []struct{ R, C, Z []byte }
}

func (cm *clockManager) Decode(data []byte) (*clockManager, error) {
	var s clockManagerSerialized
	err := protocol.DecodeReflect(data, &s)
	if err != nil {
		logging.Base().Errorf("clockManager decode error: %v", err)
		return nil, err
	}
	m := make(map[round]timers.Clock)
	zm := make(map[round]time.Time)
	for _, rc := range s.Clocks {
		var r round
		err := protocol.DecodeReflect(rc.R, &r)
		if err != nil {
			return nil, err
		}
		clk, err := cm.t0.Decode(rc.C)
		if err != nil {
			return nil, err
		}
		var zero time.Time
		err = protocol.DecodeReflect(rc.Z, &zero)
		if err != nil {
			return nil, err
		}
		m[r] = clk
		zm[r] = zero
	}
	return &clockManager{m: m, zm: zm, t0: cm.t0}, err
}

func (cm *clockManager) Encode() []byte {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var s clockManagerSerialized
	for r, c := range cm.m {
		s.Clocks = append(s.Clocks, struct{ R, C, Z []byte }{
			R: protocol.EncodeReflect(r),
			C: c.Encode(),
			Z: protocol.EncodeReflect(cm.zm[r]),
		})
	}
	return protocol.EncodeReflect(&s)
}
