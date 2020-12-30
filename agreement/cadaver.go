// Copyright (C) 2019-2020 Algorand, Inc.
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
	"path/filepath"

	"github.com/algorand/go-algorand/config"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/protocol"
)

//msgp:ignore cadaverEntryType
type cadaverEntryType int

const (
	cadaverMetaEntry cadaverEntryType = iota
	cadaverPlayerEntry
	cadaverEventEntry
	cadaverActionEntry
	cadaverEOSEntry // denotes the end of a cadaver sequence
)

// CadaverMetadata contains informational metadata written to the top of every cadaver file
type CadaverMetadata struct {
	NumOpened         int
	VersionCommitHash string
}

type cadaver struct {
	overrideSetup bool // if true, do not execute code in trySetup

	baseFilename   string // no logging happens if this is ""
	fileSizeTarget int64

	out       *cadaverHandle
	numOpened int

	failed error

	prevRound  round
	prevPeriod period
}

func (c *cadaver) filename() string {
	// Put cadaver files in our data directory
	p := config.GetCurrentVersion().DataDirectory

	fmtstr := "%s.cdv"
	return filepath.Join(p, fmt.Sprintf(fmtstr, c.baseFilename))
}

func (c *cadaver) init() (err error) {
	f, err := os.OpenFile(c.filename(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("cadaver: failed to create file %v: %v", c.filename(), err)
	}

	err = f.Chmod(0666)
	if err != nil {
		return err
	}

	c.out, err = makeCadaverHandle(f)
	if err != nil {
		return err
	}

	if c.out.bytesWritten > 0 {
		// close out previous cadaver sequence
		protocol.EncodeStream(c.out, cadaverEOSEntry)
	}
	protocol.EncodeStream(c.out, cadaverMetaEntry)
	meta := CadaverMetadata{
		NumOpened:         c.numOpened,
		VersionCommitHash: config.GetCurrentVersion().CommitHash,
	}
	protocol.EncodeStream(c.out, meta)
	c.numOpened++
	return nil
}

func (c *cadaver) trySetup() bool {
	if c.overrideSetup {
		return true
	}

	if c == nil {
		return false
	}
	if c.baseFilename == "" {
		return false
	}
	if c.failed != nil {
		return false
	}

	if c.out == nil {
		err := c.init()
		if err != nil {
			c.failed = err
			return false
		}
	}

	if c.out.bytesWritten >= c.fileSizeTarget {
		err := c.out.Close()
		if err != nil {
			logging.Base().Warn("unable to close cadaver file : %v", err)
		}
		err = os.Rename(c.filename(), c.filename()+".archive")
		if err != nil {
			if os.IsNotExist(err) {
				// we can't rename the cadaver file since it doesn't exists.
				// this typically happens when it being externally deleted, and could happen
				// far before we close the handle above.
				logging.Base().Info(err)
			} else {
				logging.Base().Warn(err)
				c.failed = err
				return false
			}
		}

		err = c.init()
		if err != nil {
			logging.Base().Warn(err)
			c.failed = err
			return false
		}
	}

	return true
}

func (c *cadaver) trace(r round, p period, x player) (ok bool) {
	if !c.trySetup() {
		return false
	}

	if r != c.prevRound || p != c.prevPeriod {
		c.prevRound = r
		c.prevPeriod = p
		protocol.EncodeStream(c.out, cadaverPlayerEntry)
		protocol.EncodeStream(c.out, x)
	}

	return true
}

func (c *cadaver) traceInput(r round, p period, x player, e event) {
	if !c.trace(r, p, x) {
		return
	}

	protocol.EncodeStream(c.out, cadaverEventEntry)
	protocol.EncodeStream(c.out, e.t())
	protocol.EncodeStream(c.out, e)
}

func (c *cadaver) traceOutput(r round, p period, x player, a []action) {
	if !c.trace(r, p, x) {
		return
	}

	protocol.EncodeStream(c.out, cadaverActionEntry)
	protocol.EncodeStream(c.out, len(a))
	for _, a := range a {
		protocol.EncodeStream(c.out, a.t())
		protocol.EncodeStream(c.out, a)
	}
}

type cadaverHandle struct {
	io.WriteCloser
	bytesWritten int64
}

func makeCadaverHandle(f *os.File) (h *cadaverHandle, err error) {
	info, err := f.Stat()
	if err != nil {
		err = fmt.Errorf("cadaver: failed to stat file: %v", err)
		return
	}

	h = new(cadaverHandle)
	h.WriteCloser = f
	h.bytesWritten = info.Size()
	return
}

func (h *cadaverHandle) Write(p []byte) (n int, err error) {
	n, err = h.WriteCloser.Write(p)
	if err != nil {
		return
	}
	h.bytesWritten += int64(n)
	return
}
