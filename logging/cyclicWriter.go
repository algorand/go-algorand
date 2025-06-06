// Copyright (C) 2019-2025 Algorand, Inc.
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

package logging

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-deadlock"
)

// CyclicFileWriter implements the io.Writer interface and wraps an underlying file.
// It ensures that the file never grows over a limit.
type CyclicFileWriter struct {
	mu        deadlock.Mutex
	writer    *os.File
	liveLog   string
	nextWrite uint64
	limit     uint64
	logStart  time.Time
	maxLogAge time.Duration

	archiveFilename *template.Template
}

// MakeCyclicFileWriter returns a writer that wraps a file to ensure it never grows too large
func MakeCyclicFileWriter(liveLogFilePath string, archiveFilePath string, sizeLimitBytes uint64, maxLogAge time.Duration) *CyclicFileWriter {
	var err error
	cyclic := CyclicFileWriter{writer: nil, liveLog: liveLogFilePath, nextWrite: 0, limit: sizeLimitBytes, maxLogAge: maxLogAge}
	cyclic.archiveFilename = template.New("archiveFilename")
	cyclic.archiveFilename, err = cyclic.archiveFilename.Parse(archiveFilePath)
	if err != nil {
		panic(fmt.Sprintf("bad LogArchiveName: %s", err))
	}
	cyclic.logStart = time.Now()

	fs, err := os.Stat(liveLogFilePath)
	if err == nil {
		cyclic.nextWrite = uint64(fs.Size())
	}

	writer, err := os.OpenFile(liveLogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		panic(fmt.Sprintf("CyclicFileWriter: cannot open log file %v", err))
	}
	cyclic.writer = writer
	return &cyclic
}

type archiveFilenameTemplateData struct {
	Year      string
	Month     string
	Day       string
	Hour      string
	Minute    string
	Second    string
	EndYear   string
	EndMonth  string
	EndDay    string
	EndHour   string
	EndMinute string
	EndSecond string
}

func (cyclic *CyclicFileWriter) getArchiveFilename(now time.Time) string {
	buf := strings.Builder{}
	cyclic.archiveFilename.Execute(&buf, archiveFilenameTemplateData{
		fmt.Sprintf("%04d", cyclic.logStart.Year()),
		fmt.Sprintf("%02d", cyclic.logStart.Month()),
		fmt.Sprintf("%02d", cyclic.logStart.Day()),
		fmt.Sprintf("%02d", cyclic.logStart.Hour()),
		fmt.Sprintf("%02d", cyclic.logStart.Minute()),
		fmt.Sprintf("%02d", cyclic.logStart.Second()),
		fmt.Sprintf("%04d", now.Year()),
		fmt.Sprintf("%02d", now.Month()),
		fmt.Sprintf("%02d", now.Day()),
		fmt.Sprintf("%02d", now.Hour()),
		fmt.Sprintf("%02d", now.Minute()),
		fmt.Sprintf("%02d", now.Second()),
	})
	return buf.String()
}

func (cyclic *CyclicFileWriter) getArchiveGlob() string {
	buf := strings.Builder{}
	cyclic.archiveFilename.Execute(&buf, archiveFilenameTemplateData{
		"*", "*", "*", "*", "*", "*",
		"*", "*", "*", "*", "*", "*",
	})
	return buf.String()
}

func procWait(cmd *exec.Cmd, cause string) {
	err := cmd.Wait()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", cause, err)
	}
}

// Write ensures the the underlying file can store an additional len(p) bytes. If there is not enough room left it seeks
// to the beginning of the file.
func (cyclic *CyclicFileWriter) Write(p []byte) (n int, err error) {
	cyclic.mu.Lock()
	defer cyclic.mu.Unlock()

	if uint64(len(p)) > cyclic.limit {
		// there's no hope for writing this entry to the log

		// for the large lines this is a clear indication something does wrong, dump data into stderr
		const minDebugLogLineSize = 10 * 1024 * 1024
		if len(p) >= minDebugLogLineSize {
			buf := make([]byte, 16*1024)
			stlen := runtime.Stack(buf, false)
			fmt.Fprintf(os.Stderr, "Attempt to write a large log line:\n%s\n", string(buf[:stlen]))
			fmt.Fprintf(os.Stderr, "The offending line:\n%s\n", string(p[:4096]))
		}

		return 0, fmt.Errorf("CyclicFileWriter: input too long to write. Len = %v", len(p))
	}

	if cyclic.nextWrite+uint64(len(p)) > cyclic.limit {
		now := time.Now()
		// we don't have enough space to write the entry, so archive data
		cyclic.writer.Close()

		globPath := cyclic.getArchiveGlob()
		oldarchives, err1 := filepath.Glob(globPath)
		if err1 != nil && !os.IsNotExist(err1) {
			fmt.Fprintf(os.Stderr, "%s: glob err: %s\n", globPath, err1)
		} else if cyclic.maxLogAge != 0 {
			tooOld := now.Add(-cyclic.maxLogAge)
			for _, path := range oldarchives {
				finfo, err2 := os.Stat(path)
				if err2 != nil {
					fmt.Fprintf(os.Stderr, "%s: stat: %s\n", path, err2)
					continue
				}
				if finfo.ModTime().Before(tooOld) {
					err2 = os.Remove(path)
					if err2 != nil {
						fmt.Fprintf(os.Stderr, "%s: rm: %s\n", path, err2)
					}
				}
			}
		}
		archivePath := cyclic.getArchiveFilename(now)
		shouldGz := false
		shouldBz2 := false
		if strings.HasSuffix(archivePath, ".gz") {
			shouldGz = true
			archivePath = archivePath[:len(archivePath)-3]
		} else if strings.HasSuffix(archivePath, ".bz2") {
			shouldBz2 = true
			archivePath = archivePath[:len(archivePath)-4]
		}
		if err1 = util.MoveFile(cyclic.liveLog, archivePath); err1 != nil {
			panic(fmt.Sprintf("CyclicFileWriter: cannot archive full log %v", err1))
		}
		if shouldGz {
			cmd := exec.Command("gzip", archivePath)
			err1 = cmd.Start()
			if err1 != nil {
				fmt.Fprintf(os.Stderr, "%s: could not gzip: %s", archivePath, err1)
			} else {
				go procWait(cmd, archivePath)
			}
		} else if shouldBz2 {
			cmd := exec.Command("bzip2", archivePath)
			err1 = cmd.Start()
			if err1 != nil {
				fmt.Fprintf(os.Stderr, "%s: could not bzip2: %s", archivePath, err1)
			} else {
				go procWait(cmd, archivePath)
			}
		}
		cyclic.logStart = now
		cyclic.writer, err1 = os.OpenFile(cyclic.liveLog, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
		if err1 != nil {
			panic(fmt.Sprintf("CyclicFileWriter: cannot open log file %v", err1))
		}
		cyclic.nextWrite = 0
	}
	// write the data
	n, err = cyclic.writer.Write(p)
	cyclic.nextWrite += uint64(n)
	return
}
