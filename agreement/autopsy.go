// Copyright (C) 2019 Algorand, Inc.
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

package agreement

import (
	"fmt"
	"io"
	"os"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

// An Autopsy is a trace of the ordered input events and output
// actions as seen by the agreement state machine.
//
// Functions depending on autopsies are not guaranteed to be supported
// as the agreement protocol changes.
type Autopsy struct {
	io.Reader
	io.Closer
}

// PrepareAutopsyFromInputStream prepares an autopsy from std in.
func PrepareAutopsyFromInputStream() (*Autopsy, error) {
	a := new(Autopsy)
	a.Reader = os.Stdin
	a.Closer = os.Stdin
	return a, nil
}

type multiCloser struct {
	closers []io.Closer
}

func (m *multiCloser) Close() error {
	for _, c := range m.closers {
		err := c.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// MultiCloser returns a Closer that closes all the given closers.
func MultiCloser(closers ...io.Closer) io.Closer {
	r := make([]io.Closer, len(closers))
	copy(r, closers)
	return &multiCloser{r}
}

// PrepareAutopsy prepares an autopsy from a cadaver filename.
func PrepareAutopsy(cadaverBaseFilename string) (*Autopsy, error) {
	name0 := cadaverBaseFilename + ".archive" // read the archive file first
	name1 := cadaverBaseFilename

	a := new(Autopsy)

	in1, err := os.Open(name1)
	if err != nil {
		return nil, err
	}
	in0, err := os.Open(name0)
	if err != nil {
		if os.IsNotExist(err) {
			// only one file created
			a.Reader = in1
			a.Closer = in1
			return a, nil
		}
		return nil, err
	}
	a.Reader = io.MultiReader(in0, in1)
	a.Closer = MultiCloser(in0, in1)
	return a, nil
}

// ExtractCdvs returns all the autopsied cadaver sequences contained in an autopsy.
func (a *Autopsy) ExtractCdvs() (seqs []AutopsiedCdv, reterr error) {
	for {
		s, _, err := a.ExtractNextCdv(nil)
		if err != nil {
			reterr = err
			return
		}
		if s.Empty() {
			return
		}
		seqs = append(seqs, s)
	}
}

// ExtractNextCdv extracts the next AutopsiedCdv from an Autopsy  and calls the
// given callback every time it extracts a single AutopsyTrace.
//
// headSkipped indicates how many events were skipped from the head of
// the cadaver.
//
// AutopsiedCdv may be partial - that is, it may not have a metadata entry, esp. if the archive
// file was too big and overwritten.
//
// traces may be set if reterr != nil.
func (a *Autopsy) ExtractNextCdv(h func(AutopsyTrace) (bool, error)) (aCdv AutopsiedCdv, headSkipped int, reterr error) {
	recording := false
	var acc AutopsyTrace
	var accs AutopsyTraceSeq

	var err error
	defer func() {
		if recording {
			accs = append(accs, acc)
			if h != nil {
				_, reterr = h(acc)
			}
		}
		if err != nil && err.Error() == "EOF" {
			reterr = nil
		}
		aCdv.T = accs
	}()

	for { // terminates automatically on EOF
		var t cadaverEntryType
		err = protocol.DecodeStream(a, &t)
		if err != nil {
			reterr = fmt.Errorf("Autopsy.ExtractNextCdv: failed to decode cadaverEntryType: %v", err)
			return
		}

		switch t {
		case cadaverEOSEntry:
			// if cadaver sequence, terminate. This indicates a crash, or any new cadaver process.
			// else, no-op.
			if recording {
				return
			}
		case cadaverPlayerEntry:
			if recording {
				if len(acc.e) != len(acc.a) && len(acc.e) != len(acc.a)+1 { // last event may have resulted in a process failure
					reterr = fmt.Errorf("Autopsy.ExtractNextCdv: events do not align with actions: %d != %d (+1)", len(acc.e), len(acc.a))
					return
				}
				accs = append(accs, acc)
				if h != nil {
					keepGoing, err := h(acc)
					if err != nil || !keepGoing {
						reterr = err
						return
					}
				}
			}
			recording = true

			acc = AutopsyTrace{}
			err = protocol.DecodeStream(a, &acc.x)
			if err != nil {
				reterr = fmt.Errorf("Autopsy.ExtractNextCdv: failed to decode player: %v", err)
				return
			}

			if len(accs) == 0 {
				aCdv.StartRound = int64(acc.x.Round)
				aCdv.StartPeriod = int64(acc.x.Period)
			}
			aCdv.EndRound = int64(acc.x.Round)
			aCdv.EndPeriod = int64(acc.x.Period)
		case cadaverEventEntry:
			var et eventType
			err = protocol.DecodeStream(a, &et)
			if err != nil {
				reterr = fmt.Errorf("Autopsy.ExtractNextCdv: failed to decode eventType: %v", err)
				return
			}

			e := zeroEvent(et)
			err = protocol.DecodeStream(a, &e)
			if err != nil {
				reterr = fmt.Errorf("Autopsy.ExtractNextCdv: failed to decode event: %v", err)
				return
			}

			if recording {
				acc.e = append(acc.e, e)
			} else {
				headSkipped++
			}

		case cadaverActionEntry:
			var n int
			err = protocol.DecodeStream(a, &n)
			if err != nil {
				reterr = fmt.Errorf("Autopsy.ExtractNextCdv: failed to decode number of actions: %v", err)
			}

			var as []action
			for i := 0; i < n; i++ {
				var at actionType
				err = protocol.DecodeStream(a, &at)
				if err != nil {
					reterr = fmt.Errorf("Autopsy.ExtractNextCdv: failed to decode actionType: %v", err)
					return
				}

				zA := zeroAction(at)
				err = protocol.DecodeStream(a, &zA)
				if err != nil {
					fmt.Printf("Action type: %v\n", at.String())
					reterr = fmt.Errorf("Autopsy.ExtractNextCdv: failed to decode action: %v", err)
					return
				}

				as = append(as, zA)
			}

			if recording {
				acc.a = append(acc.a, as)
			} // headSkipped is accounted for already

		case cadaverMetaEntry:
			// note that we can read multiple of these for a singe "cadaver seq" during normal operation if a sequence spans multiple
			// files (due to fileTargetSize); the latest one gets printed (for now).
			err = protocol.DecodeStream(a, &aCdv.M)
			if err != nil {
				reterr = fmt.Errorf("Autopsy.ExtractNextCdv: failed to decode meta entry sequence number: %v", err)
				return
			}
		}
	}
}

// An AutopsyTrace is the explict trace extracted from a cadaver
// file for a single (round, period) pair.
type AutopsyTrace struct {
	x player
	e []event
	a [][]action
}

// Dump is another convenience function for live streaming autopsy
func (a AutopsyTrace) Dump() {
	fmt.Printf("autopsy: player state is %+v ", a.x)

	for i := range a.e {
		fmt.Printf("e: %v\n", a.e[i])
		fmt.Printf("actual: %v\n", a.a[i])
	}
}

// An AutopsyTraceSeq is a slice of traces extracted from the autopsy.
type AutopsyTraceSeq []AutopsyTrace

// An AutopsiedCdv is an ordered slice of AutopsyTraces, corresponding to
// one contiguous cadaver log sequence (e.g. before crashing)
type AutopsiedCdv struct {
	T           AutopsyTraceSeq
	M           CadaverMetadata
	StartRound  int64
	StartPeriod int64
	EndRound    int64
	EndPeriod   int64
}

// Empty returns true if AutopsiedCdv is empty (e.g. read from empty autopsy file)
func (seq AutopsiedCdv) Empty() bool {
	return seq.T == nil
}

// FilterBefore removes all traces smaller than the given round. Returns
// trimmed sequence and the first round of the first trace in the trimmed sequence.
func (seq AutopsyTraceSeq) FilterBefore(first int64) (AutopsyTraceSeq, int64) {
	var nextFirstRound int64
	for i := range seq {
		nextFirstRound = int64(seq[i].x.Round)
		if nextFirstRound >= first {
			// we want to keep seq[i]
			return seq[i:], nextFirstRound
		}
	}
	return nil, nextFirstRound
}

// FilterAfter removes all traces larger than the given round. Returns
// a trimmed seq and the last round of the last trace in the trimmed seq.
func (seq AutopsyTraceSeq) FilterAfter(last int64) (AutopsyTraceSeq, int64) {
	var prevLastRound int64
	for i := range seq {
		if int64(seq[i].x.Round) > last {
			// discard seq[i] and everything after; return round of seq[i-1]
			return seq[:i], prevLastRound
		}
		prevLastRound = int64(seq[i].x.Round)
	}
	// nothing to discard...
	return seq[:], prevLastRound
}

// DumpString dumps a textual representation of the AutopsyCdvs to the
// given io.Writer.
func DumpString(cdvs []AutopsiedCdv, w io.Writer) {
	var playerTracer tracer
	playerTracer.level = all
	playerTracer.log = serviceLogger{logging.Base()}
	var router rootRouter // TODO this could become inaccurate with orphaned events

	for _, aCdv := range cdvs {
		fmt.Fprintf(w, "autopsy: metadata: %v >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n", aCdv.M)

		for _, tr := range aCdv.T {
			player := tr.x
			fmt.Fprintln(w, "autopsy:-")
			fmt.Fprintln(w, "autopsy:===================================")
			DumpPlayerStr(w, player, router, "actual")

			var p actor = ioLoggedActor{checkedActor{actor: &player, actorContract: playerContract{}}, playerTracer}
			router.root = p

			for i, e := range tr.e {
				player, _ = router.submitTop(&playerTracer, player, e)
				if i == len(tr.a) {
					break
				}
				fmt.Fprintf(w, "actual: %v\n", tr.a[i])

				fmt.Fprintln(w, "autopsy:===================================")
				DumpPlayerStr(w, player, router, "predicted")
			}
		}
	}
}

// DumpPlayerStr prints useful state of the player, tagging the output with string
func DumpPlayerStr(w io.Writer, p player, r rootRouter, tag string) {
	playerCopy := p
	playerCopy.Pending = proposalTable{}
	fmt.Fprintf(w, "autopsy: (%s) player state is %+v (len(player.Pending = %d))\n", tag, playerCopy, len(p.Pending.Pending))

	// dump useful proposal state
	receivedBlocks := make([]string, 0)
	stageStatus := "(none)"

	rRouter := r.Children[p.Round]
	if rRouter != nil && rRouter.proposalRoot != nil {
		proposalStore := rRouter.proposalRoot.underlying().(*proposalStore)
		if proposalStore.Pinned != bottom {
			pinned := fmt.Sprintf("%.5v (Pinned),", proposalStore.Pinned.BlockDigest)
			receivedBlocks = append(receivedBlocks, pinned)
		}
		for _, assembler := range proposalStore.Assemblers {
			if assembler.Assembled {
				s := fmt.Sprintf("%.5v (Assembled),", assembler.Payload.Digest())
				receivedBlocks = append(receivedBlocks, s)
			} else if assembler.Filled {
				s := fmt.Sprintf("%.5v (Awaiting Verif.),", assembler.Pipeline.Digest())
				receivedBlocks = append(receivedBlocks, s)
			}
		}

		pRouter := rRouter.Children[p.Period]
		if pRouter != nil && pRouter.proposalRoot != nil {
			proposalTrack := pRouter.proposalRoot.underlying().(*proposalTracker)
			if proposalTrack.Staging != bottom {
				stageStatus = fmt.Sprintf("%.5v", proposalTrack.Staging.BlockDigest)
			}
		}
	}

	if rRouter != nil && rRouter.voteRoot != nil {
		voteRound := rRouter.voteRoot.underlying().(*voteTrackerRound)
		if voteRound.Freshest.t() != none {
			fmt.Fprintf(w, "autopsy: (%s) player has freshest bundle: %+v, (%v, %v, %v)\n",
				tag, voteRound.Freshest, voteRound.Freshest.Round, voteRound.Freshest.Period, voteRound.Freshest.Step)
		}
	}
	fmt.Fprintf(w, "autopsy: (%s) player has blocks: %+v\n", tag, receivedBlocks)
	fmt.Fprintf(w, "autopsy: (%s) player saw soft bundle (staging): %s\n", tag, stageStatus)
}

// DumpMessagePack dumps a msgpack representation of the AutopsiedCdvs to the
// given io.Writer.
func DumpMessagePack(cdvs []AutopsiedCdv, w io.WriteCloser) {
	var playerTracer tracer
	playerTracer.log = serviceLogger{logging.Base()}
	var router rootRouter // TODO this could become inaccurate with orphaned events

	for _, aCdv := range cdvs {
		// reset cadaver for every cdv seq (so we don't miss caching player state)
		c := cadaver{}
		c.overrideSetup = true
		c.out = &cadaverHandle{WriteCloser: w}

		protocol.EncodeStream(c.out, cadaverMetaEntry)
		protocol.EncodeStream(c.out, aCdv.M)

		for _, tr := range aCdv.T {
			player := tr.x
			var p actor = checkedActor{actor: &player, actorContract: playerContract{}}
			router.root = p

			for i, e := range tr.e {
				c.traceInput(player.Round, player.Period, player, tr.e[i])
				if i < len(tr.a) {
					c.traceOutput(player.Round, player.Period, player, tr.a[i])
				}
				player, _ = router.submitTop(&playerTracer, player, e)
				// TODO can check correspondence here
			}
		}
		protocol.EncodeStream(c.out, cadaverEOSEntry)
	}
}
