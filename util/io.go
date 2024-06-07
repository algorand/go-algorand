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

package util

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MoveFile moves a file from src to dst. The advantages of using this over
// os.Rename() is that it can move files across different filesystems.
func MoveFile(src, dst string) error {
	err := os.Rename(src, dst)
	if err != nil {
		// os.Rename() may have failed because src and dst are on different
		// filesystems. Let's try to move the file by copying and deleting the
		// source file.
		return moveFileByCopying(src, dst)
	}
	return err
}

func moveFileByCopying(src, dst string) error {
	// Lstat is specifically used to detect if src is a symlink. We could
	// support moving symlinks by deleting src and creating a new symlink at
	// dst, but we don't currently expect to encounter that case, so it has not
	// been implemented.
	srcInfo, srcErr := os.Lstat(src)
	if srcErr != nil {
		return srcErr
	}
	if !srcInfo.Mode().IsRegular() {
		return fmt.Errorf("cannot move source file '%s': it is not a regular file (%v)", src, srcInfo.Mode())
	}

	if dstInfo, dstErr := os.Lstat(dst); dstErr == nil {
		if dstInfo.Mode().IsDir() {
			return fmt.Errorf("cannot move source file '%s' to destination '%s': destination is a directory", src, dst)
		}
		if os.SameFile(dstInfo, srcInfo) {
			return fmt.Errorf("cannot move source file '%s' to destination '%s': source and destination are the same file", src, dst)
		}
	}

	dstDir := filepath.Dir(dst)
	dstBase := filepath.Base(dst)

	tmpDstFile, errTmp := os.CreateTemp(dstDir, dstBase+".tmp-")
	if errTmp != nil {
		return errTmp
	}
	tmpDst := tmpDstFile.Name()
	if errClose := tmpDstFile.Close(); errClose != nil {
		return errClose
	}

	if _, err := CopyFile(src, tmpDst); err != nil {
		// If the copy fails, try to clean up the temporary file
		_ = os.Remove(tmpDst)
		return err
	}
	if err := os.Rename(tmpDst, dst); err != nil {
		// If the rename fails, try to clean up the temporary file
		_ = os.Remove(tmpDst)
		return err
	}
	if err := os.Remove(src); err != nil {
		// Don't try to clean up the destination file here. Duplicate data is
		// better than lost/incomplete data.
		return fmt.Errorf("failed to remove source file '%s' after moving it to '%s': %w", src, dst, err)
	}
	return nil
}

// CopyFile uses io.Copy() to copy a file to another location
// This was copied from https://opensource.com/article/18/6/copying-files-go
func CopyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	return nBytes, err
}

// FileExists checks to see if the specified file (or directory) exists
func FileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	fileExists := err == nil
	return fileExists
}

// IsEmpty recursively check path for files and returns true if there are none.
func IsEmpty(path string) bool {
	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		return os.ErrExist
	})
	return err == nil
}

// ExeDir returns the absolute path to the current executing binary (not including the filename)
func ExeDir() (string, error) {
	ex, err := os.Executable()
	if err != nil {
		return "", err
	}
	baseDir := filepath.Dir(ex)
	binDir, err := filepath.Abs(baseDir)
	return binDir, err
}

// GetFirstLineFromFile retrieves the first line of the specified file.
func GetFirstLineFromFile(netFile string) (string, error) {
	addrStr, err := os.ReadFile(netFile)
	if err != nil {
		return "", err
	}
	// We only want the first line, so split at newlines and take the first
	lines := strings.Split(string(addrStr), "\n")
	return lines[0], err
}

// IsDir returns true if the specified directory is valid
func IsDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// IncludeFilter is a callback for filtering files and folders encountered while copying with CopyFileWithFilter()
type IncludeFilter func(name string, info os.FileInfo) bool

// CopyFolderWithFilter recursively copies an entire directory to another location (ignoring symlinks)
// with an optional filter function to include/exclude folders or files
func CopyFolderWithFilter(source, dest string, includeFilter IncludeFilter) (err error) {
	if !IsDir(source) {
		return fmt.Errorf("%s is not a folder - unable to copy", source)
	}

	info, err := os.Stat(source)
	if err != nil {
		return fmt.Errorf("error getting status for '%s': %v", source, err)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlink are not supported")
	}

	return copyFolder(source, dest, info, includeFilter)
}

// CopyFolder recursively copies an entire directory to another location (ignoring symlinks)
func CopyFolder(source, dest string) error {
	return CopyFolderWithFilter(source, dest, nil)
}

func copyFolder(source string, dest string, info os.FileInfo, includeFilter IncludeFilter) (err error) {
	if err := os.MkdirAll(dest, info.Mode()); err != nil {
		return fmt.Errorf("error creating destination folder: %v", err)
	}

	contents, err := os.ReadDir(source)
	if err != nil {
		return err
	}

	for _, content := range contents {
		name := content.Name()
		sourceName := filepath.Join(source, name)
		sourceInfo, statErr := os.Stat(sourceName)
		if statErr != nil {
			return statErr
		}

		// Skip symlinks
		if sourceInfo.Mode()&os.ModeSymlink != 0 {
			continue
		}

		// If filter provided, see if it wants to include
		if includeFilter != nil && !includeFilter(sourceName, sourceInfo) {
			continue
		}

		destName := filepath.Join(dest, name)
		if sourceInfo.IsDir() {
			err = copyFolder(sourceName, destName, sourceInfo, includeFilter)
		} else {
			_, err = CopyFile(sourceName, destName)
		}
		if err != nil {
			return
		}
	}

	return
}
