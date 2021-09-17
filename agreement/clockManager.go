package agreement

import (
	"fmt"
	"sort"
	"time"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
	"github.com/algorand/go-algorand/util/timers"
	"github.com/algorand/go-deadlock"
)

// clockManager managers multiple clocks used by different pipelined rounds.
type clockManager struct {
	mu deadlock.Mutex
	m  map[round]timers.Clock

	factory timers.ClockFactory
}

func makeClockManager(factory timers.ClockFactory) *clockManager {
	return &clockManager{m: make(map[round]timers.Clock), factory: factory}
}

func (cm *clockManager) setZero(r round) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.m[r] = cm.factory.Zero(r)
}

func (cm *clockManager) gc(es []externalDemuxSignals) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	active := make(map[round]struct{})
	for _, e := range es {
		active[e.CurrentRound] = struct{}{}
	}
	for r, clk := range cm.m {
		_, isactive := active[r]
		if !isactive {
			clk.GC()
			delete(cm.m, r)
		}
	}
}

// nextDeadlineCh returns a timeout channel that will fire when the earliest Deadline among all of
// the rounds described in externalDemuxSignals has occurred. It also returns the corresponding
// round (including speculative branch) this timeout channel corresponds to.
func (cm *clockManager) nextDeadlineCh(es []externalDemuxSignals) (<-chan struct{}, round) {
	if len(es) == 0 {
		return nil, roundZero
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()

	sort.Slice(es, func(i, j int) bool {
		ti := cm.m[es[i].CurrentRound].GetTimeout(es[i].Deadline)
		tj := cm.m[es[j].CurrentRound].GetTimeout(es[j].Deadline)
		return ti.Before(tj)
	})
	r := es[0].CurrentRound
	c, ok := cm.m[r]
	if !ok {
		// no rezeroAction has set up this clock yet
		panic(fmt.Sprintf("clockManager.nextDeadlineCh: no clock for round %+v\n", r))
	}
	return c.TimeoutAt(es[0].Deadline), r
}

// nextPipelineDelayCh returns a timeout channel that will fire when the earliest PipelineDelay among all of
// the rounds described in externalDemuxSignals has occurred. It also returns the corresponding
// round (including speculative branch) this timeout channel corresponds to.
func (cm *clockManager) nextPipelineDelayCh(es []externalDemuxSignals) (<-chan struct{}, round) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	sort.Slice(es, func(i, j int) bool {
		ti := cm.m[es[i].CurrentRound].GetTimeout(es[i].PipelineDelay)
		tj := cm.m[es[j].CurrentRound].GetTimeout(es[j].PipelineDelay)
		return ti.Before(tj)
	})

	i := 0
	for i < len(es) && es[i].PipelineDelay == 0 {
		i++
	}
	if i >= len(es) {
		return nil, roundZero
	}
	r := es[i].CurrentRound
	c, ok := cm.m[r]
	if !ok {
		// no rezeroAction has set up this clock yet
		panic(fmt.Sprintf("clockManager.nextPipelineDelayCh: no clock for round %+v\n", r))
	}
	return c.TimeoutAt(es[i].Deadline), r
}

// nextFastDeadlineCh returns a timeout channel that will fire when the earliest FastRecoveryDeadline among all of
// the rounds described in externalDemuxSignals has occurred. It also returns the corresponding
// round (including speculative branch) this timeout channel corresponds to.
func (cm *clockManager) nextFastDeadlineCh(es []externalDemuxSignals) (<-chan struct{}, round) {
	if len(es) == 0 {
		return nil, roundZero
	}
	cm.mu.Lock()
	defer cm.mu.Unlock()

	sort.Slice(es, func(i, j int) bool {
		ti := cm.m[es[i].CurrentRound].GetTimeout(es[i].FastRecoveryDeadline)
		tj := cm.m[es[j].CurrentRound].GetTimeout(es[j].FastRecoveryDeadline)
		return ti.Before(tj)
	})
	return cm.m[es[0].CurrentRound].TimeoutAt(es[0].FastRecoveryDeadline), es[0].CurrentRound
}

func (cm *clockManager) durationUntil(r round, t time.Time) time.Duration {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	c, ok := cm.m[r]
	if !ok {
		return 0
	}

	return c.DurationUntil(t)
}

type clockManagerSerialized struct {
	Clocks []struct{ R, C []byte }
}

func (cm *clockManager) Decode(data []byte) (*clockManager, error) {
	var s clockManagerSerialized
	err := protocol.DecodeReflect(data, &s)
	if err != nil {
		logging.Base().Errorf("clockManager decode error: %v", err)
		return nil, err
	}
	m := make(map[round]timers.Clock)
	for _, rc := range s.Clocks {
		var r round
		err := protocol.DecodeReflect(rc.R, &r)
		if err != nil {
			return nil, err
		}
		clk, err := cm.factory.Decode(rc.C)
		if err != nil {
			return nil, err
		}
		m[r] = clk
	}
	return &clockManager{m: m, factory: cm.factory}, err
}

func (cm *clockManager) Encode() []byte {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var s clockManagerSerialized
	for r, c := range cm.m {
		s.Clocks = append(s.Clocks, struct{ R, C []byte }{
			R: protocol.EncodeReflect(r),
			C: c.Encode(),
		})
	}
	return protocol.EncodeReflect(&s)
}
