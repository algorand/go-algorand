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

package main

import (
	"archive/tar"
	"compress/bzip2"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/algorand/go-algorand/logging"
)

type tarBlockSet struct {
	// known tarfiles
	entries []*tarBlockFile

	// tarfiles with an open handle
	// a cache with random replacement
	open []*tarBlockFile
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
	for _, tbf := range tars.open {
		if tbf.first <= round && round <= tbf.last {
			return tbf.getBlock(round)
		}
	}
	for _, tbf := range tars.entries {
		if tbf.first <= round && round <= tbf.last {
			if len(tars.open) >= maxOpenTars {
				// random replacement
				i := rand.Intn(len(tars.open))
				tars.open[i].close()
				tars.open[i] = tbf
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

	l sync.Mutex
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
	} else {
		logging.Base().Infof("close %p %s", tbf, tbf.path)
	}
	return
}

func (tbf *tarBlockFile) getBlock(round uint64) (data []byte, err error) {
	tbf.l.Lock()
	defer tbf.l.Unlock()
	logging.Base().Infof("get block %d", round)
	defer logging.Base().Infof("get block %d done %v", round, err)
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
	pass := 0
	if tbf.current == nil {
		// starting from the beginning, we won't miss anything, so if it's not there, don't start over from the beginning.
		pass = 1
	}
	for true {
		if tbf.current != nil && tbf.currentRound == round {
			data = make([]byte, tbf.current.Size)
			_, err = io.ReadFull(tbf.tarfile, data)
			if err != nil {
				err = fmt.Errorf("%s: read %s, %v", tbf.path, tbf.current.Name, err)
			}
			return
		}
		if tbf.tarfile == nil {
			err = fmt.Errorf("%s tarfile unexpectedly nil", tbf.path)
			return
		}
		tbf.current, err = tbf.tarfile.Next()
		if err == io.EOF {
			tbf._close()
			if pass == 0 {
				// try again from the beginning
				pass++
				err = tbf._open()
				if err != nil {
					err = fmt.Errorf("%s: open, %v", tbf.path, err)
					return
				}
				continue
			} else {
				// we don't have it
				return nil, nil
			}
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
		// fall through to maybe-return clause at top of loop
	}
	return nil, errors.New("this should be unreachable")
}
