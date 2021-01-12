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

package main

import (
	"archive/tar"
	"compress/bzip2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-deadlock"
)

type tarBlockSet struct {
	// known tarfiles
	entries []*tarBlockFile

	// tarfiles with an open handle
	// a cache with random replacement
	open []*tarBlockFile

	// replacement index
	nextOpen int

	l deadlock.Mutex
}

const maxOpenTars = 3

func openTarBlockDir(path string) (tars *tarBlockSet, err error) {
	out := &tarBlockSet{}
	matches, err := filepath.Glob(filepath.Join(path, "*_*.tar.bz2"))
	if err != nil {
		return nil, err
	}
	out.entries = make([]*tarBlockFile, 0, len(matches))
	for _, path := range matches {
		tbf := parseTarPathname(path)
		if tbf != nil {
			out.entries = append(out.entries, tbf)
		}
	}
	logging.Base().Infof("found %d block tarfiles", len(out.entries))
	out.open = make([]*tarBlockFile, 0, maxOpenTars)
	return out, nil
}

func (tars *tarBlockSet) getBlock(round uint64) (data []byte, err error) {
	tars.l.Lock()
	defer tars.l.Unlock()
	for _, tbf := range tars.open {
		if tbf.first <= round && round <= tbf.last {
			return tbf.getBlock(round)
		}
	}
	for _, tbf := range tars.entries {
		if tbf.first <= round && round <= tbf.last {
			if len(tars.open) >= maxOpenTars {
				tars.open[tars.nextOpen].close()
				tars.open[tars.nextOpen] = tbf
				tars.nextOpen = (tars.nextOpen + 1) % len(tars.open)
			} else {
				tars.open = append(tars.open, tbf)
			}
			return tbf.getBlock(round)
		}
	}
	return nil, nil
}

type tarBlockFile struct {
	path  string
	first uint64
	last  uint64

	// fields valid when tarfile is open
	rawFile      io.ReadCloser
	bz2Stream    io.Reader
	tarfile      *tar.Reader
	current      *tar.Header
	currentRound uint64

	l deadlock.Mutex

	blocks map[uint64][]byte
}

func parseTarPathname(path string) (tbf *tarBlockFile) {
	fname := filepath.Base(path)
	underscore := strings.IndexRune(fname, '_')
	if underscore < 0 {
		return nil
	}
	dottar := strings.Index(fname, ".tar")
	if dottar < 0 {
		return nil
	}
	first, err := strconv.ParseUint(fname[:underscore], 10, 64)
	if err != nil {
		return nil
	}
	last, err := strconv.ParseUint(fname[underscore+1:dottar], 10, 64)
	if err != nil {
		return nil
	}
	return &tarBlockFile{
		path:  path,
		first: first,
		last:  last,
	}
}

func (tbf *tarBlockFile) _open() (err error) {
	if tbf.tarfile != nil {
		logging.Base().Infof("%s already open", tbf.path)
		return nil
	}
	tbf.rawFile, err = os.Open(tbf.path)
	if err != nil {
		err = fmt.Errorf("%s: os.open %v", tbf.path, err)
		tbf.rawFile = nil
		return
	}
	logging.Base().Infof("open %p %s", tbf, tbf.path)
	if strings.HasSuffix(tbf.path, ".bz2") {
		tbf.bz2Stream = bzip2.NewReader(tbf.rawFile)
		tbf.tarfile = tar.NewReader(tbf.bz2Stream)
	} else {
		tbf.tarfile = tar.NewReader(tbf.rawFile)
	}
	tbf.blocks = make(map[uint64][]byte, 1000)
	return nil
}

func (tbf *tarBlockFile) close() (err error) {
	tbf.l.Lock()
	defer tbf.l.Unlock()
	return tbf._close()
}

func (tbf *tarBlockFile) _close() (err error) {
	if tbf.rawFile != nil {
		err = tbf.rawFile.Close()
		logging.Base().Infof("close %p %s, %v", tbf, tbf.path, err)
		tbf.rawFile = nil
		tbf.bz2Stream = nil
		tbf.tarfile = nil
		tbf.current = nil
		tbf.blocks = nil
	} else {
		logging.Base().Infof("close %p %s", tbf, tbf.path)
	}
	return
}

func (tbf *tarBlockFile) getBlock(round uint64) (data []byte, err error) {
	tbf.l.Lock()
	defer tbf.l.Unlock()
	if tbf.blocks != nil {
		var ok bool
		data, ok = tbf.blocks[round]
		if ok {
			return
		}
	}
	//logging.Base().Infof("get block %d", round)
	//defer logging.Base().Infof("get block %d done %v", round, err)
	if tbf.tarfile == nil {
		err = tbf._open()
		if err != nil {
			err = fmt.Errorf("%s: open, %v", tbf.path, err)
			return
		}
		if tbf.tarfile == nil {
			err = fmt.Errorf("%s: tarfile didn't open", tbf.path)
			return
		}
	}
	err = nil
	for true {
		tbf.current, err = tbf.tarfile.Next()
		if err == io.EOF {
			tbf._close()
			// we don't have it
			return nil, nil
		}
		if err != nil {
			err = fmt.Errorf("%s: next, %v", tbf.path, err)
			tbf._close()
			return nil, err
		}
		tbf.currentRound, err = strconv.ParseUint(tbf.current.Name, 10, 64)
		if err != nil {
			err = fmt.Errorf("%s: could not parse block file name %#v, %v", tbf.path, tbf.current.Name, err)
			return nil, err
		}
		data = make([]byte, tbf.current.Size)
		_, err = io.ReadFull(tbf.tarfile, data)
		if err != nil {
			err = fmt.Errorf("%s: read %s, %v", tbf.path, tbf.current.Name, err)
		}
		tbf.blocks[tbf.currentRound] = data
		if tbf.currentRound == round {
			return
		}
	}
	return nil, errors.New("this should be unreachable")
}
