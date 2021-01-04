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

package libgoal

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	walletHandlesJSONName = "walletHandles.json"
)

type walletHandles struct {
	Handles map[string]string
}

func readLocked(path string) ([]byte, error) {
	lf, err := newLockedFile(path)
	if err != nil {
		return nil, err
	}
	return lf.read()
}

func writeLocked(path string, data []byte, perm os.FileMode) error {
	lf, err := newLockedFile(path)
	if err != nil {
		return err
	}
	return lf.write(data, perm)
}

func (whs *walletHandles) loadFromDisk(cacheDir string) error {
	path := walletHandlesCachePath(cacheDir)
	_, err := os.Stat(path)
	if !os.IsNotExist(err) {
		raw, err := readLocked(path)
		if err != nil {
			return err
		}
		err = json.Unmarshal(raw, &whs)
		if err != nil {
			return err
		}
	}
	return nil
}

func (whs *walletHandles) dumpToDisk(cacheDir string) error {
	raw, err := json.MarshalIndent(whs, "", "  ")
	if err != nil {
		return err
	}

	path := walletHandlesCachePath(cacheDir)
	err = writeLocked(path, raw, 0600)
	if err != nil {
		return err
	}
	return nil
}

func walletHandlesCachePath(cacheDir string) string {
	return filepath.Join(cacheDir, walletHandlesJSONName)
}

func loadWalletHandleFromDisk(walletID []byte, cacheDir string) ([]byte, error) {
	whs := walletHandles{}
	err := whs.loadFromDisk(cacheDir)
	if err != nil {
		return nil, err
	}
	return []byte(whs.Handles[string(walletID)]), nil
}

func writeWalletHandleToDisk(handle, walletID []byte, cacheDir string) error {
	whs := walletHandles{}
	if err := whs.loadFromDisk(cacheDir); err != nil {
		return err
	}
	if whs.Handles == nil {
		whs.Handles = make(map[string]string)
	}
	whs.Handles[string(walletID)] = string(handle)

	return whs.dumpToDisk(cacheDir)
}
