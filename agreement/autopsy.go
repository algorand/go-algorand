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

package agreement

import (
	"fmt"
	"io"
	"os"

	"github.com/algorand/go-algorand/data/basics"
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

	cdvs <-chan cdvInstance
}

// AutopsyBounds defines the range of rounds and periods spanned by a single
// invocation of a cadaver-generating process.
type AutopsyBounds struct {
	// Start and End are inclusive here.
	StartRound  uint64
	StartPeriod uint64
	EndRound    uint64
	EndPeriod   uint64
}

// PrepareAutopsyFromStream prepares an autopsy from a given ReadCloser.
//
// nextBounds is called with a sequence number for each new invocation of a
// cadaver-generating process (a "run").
//
// done is called with the total number of runs and any error encountered while
// performing the autopsy.
func PrepareAutopsyFromStream(stream io.ReadCloser, nextBounds func(int, AutopsyBounds), done func(int, error)) (*Autopsy, error) {
	return prepareStreamingAutopsy(stream, stream, nextBounds, done), nil
}

// PrepareAutopsy prepares an autopsy from a cadaver filename.
//
// nextBounds is called with a sequence number for each new invocation of a
// cadaver-generating process (a "run").
//
// done is called with the total number of runs and any error encountered while
// performing the autopsy.
func PrepareAutopsy(cadaverBaseFilename string, nextBounds func(int, AutopsyBounds), done func(int, error)) (*Autopsy, error) {
	name0 := cadaverBaseFilename + ".archive" // read the archive file first
	name1 := cadaverBaseFilename

	in1, err := os.Open(name1)
	if err != nil {
		return nil, err
	}
	in0, err := os.Open(name0)
	if err != nil {
		if os.IsNotExist(err) {
			// only one file created
			return prepareStreamingAutopsy(in1, in1, nextBounds, done), nil
		}
		return nil, err
	}

	return prepareStreamingAutopsy(io.MultiReader(in0, in1), makeMultiCloser(in0, in1), nextBounds, done), nil
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

// makeMultiCloser returns a Closer that closes all the given closers.
func makeMultiCloser(closers ...io.Closer) io.Closer {
	r := make([]io.Closer, len(closers))
	copy(r, closers)
	return &multiCloser{r}
}

type autopsyTrace struct {
	x player
	m CadaverMetadata

	p <-chan autopsyPair
}

type cdvInstance <-chan autopsyTrace

func prepareStreamingAutopsy(r io.Reader, c io.Closer, nextBounds func(int, AutopsyBounds), done func(int, error)) *Autopsy {
	a := new(Autopsy)
	a.Reader = r
	a.Closer = c

	ch := make(chan cdvInstance)
	go func() {
		defer func() {
			close(ch)
		}()

		for n := 0; ; n++ {
			tch := make(chan autopsyTrace)
			ch <- tch

			bounds, empty, err := a.extractNextCdv(tch)

			if !empty {
				nextBounds(n, bounds)
			}

			if err != nil {
				close(tch)
				done(n, err)
				return
			}
			if empty {
				close(tch)
				done(n, nil)
				return
			}
		}
	}()
	a.cdvs = ch
	return a
}

type switchableWriter struct {
	io.Writer
	disabled bool
}

func (w *switchableWriter) Enable() {
	w.disabled = false
}

func (w *switchableWriter) Disable() {
	w.disabled = true
}

func (w switchableWriter) Write(p []byte) (n int, err error) {
	if w.disabled {
		return len(p), nil
	}
	return w.Writer.Write(p)
}

type switchableWriteCloser struct {
	switchableWriter
	io.Closer
}

// AutopsyFilter represents a window of rounds to be filtered from the autopsy
// output.
type AutopsyFilter struct {
	Enabled bool         // do not filter if this is false
	First   basics.Round // first round to emit output for; inclusive
	Last    basics.Round // last round to emit output for; inclusive
}

// DumpString dumps a textual representation of the AutopsyCdvs to the
// given io.Writer.
func (a *Autopsy) DumpString(filter AutopsyFilter, w0 io.Writer) (version string) {
	w := &switchableWriter{Writer: w0}
	var playerTracer tracer
	playerTracer.level = all
	playerTracer.log = serviceLogger{logging.Base()}
	playerTracer.w = w
	var router rootRouter // TODO this could become inaccurate with orphaned events

	for cdv := range a.cdvs {
		first := true

		for tr := range cdv {
			if first {
				first = false
				fmt.Fprintf(w, "autopsy: metadata: %v >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n", tr.m)
				version = tr.m.VersionCommitHash
			}

			player := tr.x

			if filter.Enabled {
				if player.Round < filter.First || player.Round > filter.Last {
					w.Disable()
				} else {
					w.Enable()
				}
			}

			fmt.Fprintln(w, "autopsy:-")
			fmt.Fprintln(w, "autopsy:===================================")
			dumpPlayerStr(w, player, router, "actual")

			var p actor = ioLoggedActor{checkedActor{actor: &player, actorContract: playerContract{}}, playerTracer}
			router.root = p

			for pair := range tr.p {
				player, _ = router.submitTop(&playerTracer, player, pair.e)
				if !pair.aok {
					break
				}
				fmt.Fprintf(w, "actual: %v\n", pair.a)

				fmt.Fprintln(w, "autopsy:===================================")
				dumpPlayerStr(w, player, router, "predicted")
			}
		}
	}
	return
}

// dumpPlayerStr prints useful state of the player, tagging the output with string.
func dumpPlayerStr(w io.Writer, p player, r rootRouter, tag string) {
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
func (a *Autopsy) DumpMessagePack(filter AutopsyFilter, w0 io.WriteCloser) (version string) {
	w := &switchableWriteCloser{switchableWriter: switchableWriter{Writer: w0}, Closer: w0}
	var playerTracer tracer
	playerTracer.log = serviceLogger{logging.Base()}
	playerTracer.w = w
	var router rootRouter // TODO this could become inaccurate with orphaned events

	for cdv := range a.cdvs {
		first := true

		// reset cadaver for every cdv seq (so we don't miss caching player state)
		c := cadaver{}
		c.overrideSetup = true
		c.out = &cadaverHandle{WriteCloser: w}

		for tr := range cdv {
			if first {
				first = false
				protocol.EncodeStream(c.out, cadaverMetaEntry)
				protocol.EncodeStream(c.out, tr.m)
				version = tr.m.VersionCommitHash
			}

			player := tr.x
			var p actor = checkedActor{actor: &player, actorContract: playerContract{}}
			router.root = p

			if filter.Enabled {
				if player.Round < filter.First || player.Round > filter.Last {
					w.Disable()
				} else {
					w.Enable()
				}
			}

			for pair := range tr.p {
				c.traceInput(player.Round, player.Period, player, pair.e)
				if pair.aok {
					c.traceOutput(player.Round, player.Period, player, pair.a)
				}
				player, _ = router.submitTop(&playerTracer, player, pair.e)
				// TODO can check correspondence here
			}
		}
		protocol.EncodeStream(c.out, cadaverEOSEntry)
	}
	return
}

type autopsyPair struct {
	e   event
	a   []action
	aok bool
}

func (a *Autopsy) extractNextCdv(ch chan<- autopsyTrace) (bounds AutopsyBounds, empty bool, reterr error) {
	empty = true

	recording := false
	var acc autopsyTrace

	var pch chan autopsyPair
	var err error
	defer func() {
		if recording {
			empty = false
			close(pch)
			close(ch)
		}
		if err != nil && err.Error() == "EOF" {
			reterr = nil
		}
	}()

	expectAction := false // if false, event is expected; else action
	var accp autopsyPair

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
				empty = false
				close(pch)
			}

			pch = make(chan autopsyPair, 0)
			acc = autopsyTrace{m: acc.m, p: pch}
			err = protocol.DecodeStream(a, &acc.x)
			if err != nil {
				reterr = fmt.Errorf("Autopsy.ExtractNextCdv: failed to decode player: %v", err)
				return
			}
			expectAction = false

			bounds.EndRound = uint64(acc.x.Round)
			bounds.EndPeriod = uint64(acc.x.Period)

			if !recording {
				// first time
				bounds.StartRound = uint64(acc.x.Round)
				bounds.StartPeriod = uint64(acc.x.Period)
			}
			recording = true

			ch <- acc

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
				if expectAction {
					reterr = fmt.Errorf("Autopsy.ExtractNextCdv: expected action but got event")
					return
				}
				accp.e = e
				expectAction = !expectAction
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
				if !expectAction {
					reterr = fmt.Errorf("Autopsy.ExtractNextCdv: expected event but got action")
					return
				}
				accp.aok = true
				accp.a = as
				pch <- accp

				accp = autopsyPair{}
				expectAction = !expectAction
			}

		case cadaverMetaEntry:
			// note that we can read multiple of these for a singe "cadaver seq" during normal operation if a sequence spans multiple
			// files (due to fileTargetSize); the latest one gets printed (for now).
			err = protocol.DecodeStream(a, &acc.m)
			if err != nil {
				reterr = fmt.Errorf("Autopsy.ExtractNextCdv: failed to decode meta entry sequence number: %v", err)
				return
			}
		}
	}
}
