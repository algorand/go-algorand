// Copyright (C) 2019-2024 Algorand, Inc.
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

package trackerdb

import (
	"io"
	"os"
	"path/filepath"
)

// isDirEmpty returns if a given directory is empty or not.
func isDirEmpty(path string) (bool, error) {
	dir, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	_, err = dir.Readdirnames(1)
	if err != io.EOF {
		return false, err
	}
	return true, nil
}

// GetEmptyDirs returns a slice of paths for empty directories which are located in PathToScan arg
func GetEmptyDirs(PathToScan string) ([]string, error) {
	var emptyDir []string
	err := filepath.Walk(PathToScan, func(path string, f os.FileInfo, errIn error) error {
		if errIn != nil {
			return errIn
		}
		if !f.IsDir() {
			return nil
		}
		isEmpty, err := isDirEmpty(path)
		if err != nil {
			if os.IsNotExist(err) {
				return filepath.SkipDir
			}
			return err
		}
		if isEmpty {
			emptyDir = append(emptyDir, path)
		}
		return nil
	})
	return emptyDir, err
}
