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

// Command phase3 converts errorcontains.CaptureError calls to specific error assertions.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// CallSite represents aggregated data from the aggregate tool.
type CallSite struct {
	File        string         `json:"file"`
	Line        int            `json:"line"`
	Count       int            `json:"count"`
	ErrorTypes  map[string]int `json:"error_types"`
	LCS         string         `json:"lcs"`
	LCSLength   int            `json:"lcs_length"`
	Samples     []string       `json:"samples"`
	UserMsgs    map[string]int `json:"user_msgs,omitempty"`
	NeedsReview bool           `json:"needs_review,omitempty"`
}

var (
	// Pattern to match CaptureError calls
	captureErrorRe = regexp.MustCompile(`(?m)^(\s*)errorcontains\.CaptureError\(([^,]+),\s*([^,)]+)(?:,\s*([^)]+))?\)\s*$`)

	// Pattern to match the next line after CaptureError
	errorIsRe  = regexp.MustCompile(`(?m)^(\s*)require\.ErrorIs\(([^,]+),\s*([^,]+),\s*([^)]+)\)`)
	containsRe = regexp.MustCompile(`(?m)^(\s*)require\.Contains\(([^,]+),\s*([^.]+)\.Error\(\),\s*("[^"]+"|` + "`[^`]+`" + `)\)`)
	equalRe    = regexp.MustCompile(`(?m)^(\s*)require\.Equal\(([^,]+),\s*([^,]+),\s*([^)]+)\)`)
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: phase3 <error_sites.json> <root_dir> [--dry-run]")
		fmt.Println("       phase3 /tmp/error_sites.json /path/to/go-algorand")
		os.Exit(1)
	}

	sitesFile := os.Args[1]
	rootDir := os.Args[2]
	dryRun := len(os.Args) > 3 && os.Args[3] == "--dry-run"

	// Load aggregated error data
	sites, err := loadSites(sitesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading sites: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Loaded %d call sites\n", len(sites))

	// Build lookup map by file:line
	siteLookup := make(map[string]*CallSite)
	for i := range sites {
		key := fmt.Sprintf("%s:%d", sites[i].File, sites[i].Line)
		siteLookup[key] = &sites[i]
	}

	// Find all Go test files
	var files []string
	err = filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, "_test.go") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error walking directory: %v\n", err)
		os.Exit(1)
	}

	stats := struct {
		filesModified   int
		captureRemoved  int
		toErrorIs       int
		toErrorContains int
		standalone      int
		skipped         int
	}{}

	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n", file, err)
			continue
		}

		original := string(content)
		modified := processFile(original, file, rootDir, siteLookup, &stats)

		if modified != original {
			stats.filesModified++
			if dryRun {
				fmt.Printf("Would modify: %s\n", file)
			} else {
				if err := os.WriteFile(file, []byte(modified), 0644); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", file, err)
					continue
				}
				fmt.Printf("Modified: %s\n", file)
			}
		}
	}

	// Run goimports if not dry run
	if !dryRun && stats.filesModified > 0 {
		fmt.Println("\nRunning goimports...")
		cmd := exec.Command("goimports", "-w", rootDir)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: goimports failed: %v\n", err)
		}
	}

	fmt.Printf("\nSummary:\n")
	fmt.Printf("  Files modified: %d\n", stats.filesModified)
	fmt.Printf("  CaptureError removed (kept ErrorIs): %d\n", stats.captureRemoved)
	fmt.Printf("  Converted to ErrorIs: %d\n", stats.toErrorIs)
	fmt.Printf("  Converted to ErrorContains: %d\n", stats.toErrorContains)
	fmt.Printf("  Standalone converted: %d\n", stats.standalone)
	fmt.Printf("  Skipped (needs review): %d\n", stats.skipped)
}

func loadSites(filename string) ([]CallSite, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var sites []CallSite
	if err := json.Unmarshal(data, &sites); err != nil {
		return nil, err
	}
	return sites, nil
}

func processFile(content, filePath, rootDir string, siteLookup map[string]*CallSite, stats *struct {
	filesModified   int
	captureRemoved  int
	toErrorIs       int
	toErrorContains int
	standalone      int
	skipped         int
}) string {
	lines := strings.Split(content, "\n")

	// Find CaptureError calls and their line numbers
	type replacement struct {
		lineIdx     int
		newLine     string
		deleteNext  bool
		nextLineIdx int
	}
	var replacements []replacement

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Check for CaptureError call
		if !strings.Contains(line, "errorcontains.CaptureError") {
			continue
		}

		// Parse the CaptureError line
		match := captureErrorRe.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		indent := match[1]
		tVar := strings.TrimSpace(match[2])
		errVar := strings.TrimSpace(match[3])
		userMsg := ""
		if len(match) > 4 && match[4] != "" {
			userMsg = strings.TrimSpace(match[4])
		}

		// Get relative path for lookup
		relPath := filePath
		if idx := strings.Index(filePath, "go-algorand/"); idx != -1 {
			relPath = filePath[idx+len("go-algorand/"):]
		}

		// Line numbers in the file are 1-indexed, array is 0-indexed
		lineNum := i + 1
		siteKey := fmt.Sprintf("%s:%d", relPath, lineNum)

		// Check next line for pattern
		nextLine := ""
		if i+1 < len(lines) {
			nextLine = lines[i+1]
		}

		// Pattern 1: CaptureError + ErrorIs -> just remove CaptureError
		if strings.Contains(nextLine, "require.ErrorIs") || strings.Contains(nextLine, "a.ErrorIs") {
			replacements = append(replacements, replacement{
				lineIdx: i,
				newLine: "", // delete the line
			})
			stats.captureRemoved++
			continue
		}

		// Pattern 2: CaptureError + Contains -> ErrorContains
		if containsMatch := containsRe.FindStringSubmatch(nextLine); containsMatch != nil {
			substring := containsMatch[4]
			var newLine string
			if userMsg != "" {
				newLine = fmt.Sprintf("%srequire.ErrorContains(%s, %s, %s, %s)", indent, tVar, errVar, substring, userMsg)
			} else {
				newLine = fmt.Sprintf("%srequire.ErrorContains(%s, %s, %s)", indent, tVar, errVar, substring)
			}
			replacements = append(replacements, replacement{
				lineIdx:     i,
				newLine:     newLine,
				deleteNext:  true,
				nextLineIdx: i + 1,
			})
			stats.toErrorContains++
			continue
		}

		// Pattern 3: CaptureError + Equal(sentinel, err) -> ErrorIs
		if equalMatch := equalRe.FindStringSubmatch(nextLine); equalMatch != nil {
			arg1 := strings.TrimSpace(equalMatch[3])
			arg2 := strings.TrimSpace(equalMatch[4])

			// Check if this is comparing error to sentinel
			var sentinel string
			if arg2 == errVar || strings.HasSuffix(arg2, errVar) {
				sentinel = arg1
			} else if arg1 == errVar || strings.HasSuffix(arg1, errVar) {
				sentinel = arg2
			}

			if sentinel != "" && !strings.Contains(sentinel, ".Error()") {
				var newLine string
				if userMsg != "" {
					newLine = fmt.Sprintf("%srequire.ErrorIs(%s, %s, %s, %s)", indent, tVar, errVar, sentinel, userMsg)
				} else {
					newLine = fmt.Sprintf("%srequire.ErrorIs(%s, %s, %s)", indent, tVar, errVar, sentinel)
				}
				replacements = append(replacements, replacement{
					lineIdx:     i,
					newLine:     newLine,
					deleteNext:  true,
					nextLineIdx: i + 1,
				})
				stats.toErrorIs++
				continue
			}
		}

		// Pattern 4: Standalone CaptureError -> ErrorContains with LCS
		site := siteLookup[siteKey]
		if site == nil {
			// Try with just the file basename
			baseName := filepath.Base(relPath)
			for k, s := range siteLookup {
				if strings.HasSuffix(k, baseName+":"+strconv.Itoa(lineNum)) {
					site = s
					break
				}
			}
		}

		if site != nil && site.LCS != "" && !site.NeedsReview {
			lcs := escapeString(site.LCS)
			var newLine string
			if userMsg != "" {
				newLine = fmt.Sprintf("%srequire.ErrorContains(%s, %s, %s, %s)", indent, tVar, errVar, lcs, userMsg)
			} else {
				newLine = fmt.Sprintf("%srequire.ErrorContains(%s, %s, %s)", indent, tVar, errVar, lcs)
			}
			replacements = append(replacements, replacement{
				lineIdx: i,
				newLine: newLine,
			})
			stats.standalone++
		} else {
			stats.skipped++
		}
	}

	// Apply replacements in reverse order to preserve line numbers
	sort.Slice(replacements, func(i, j int) bool {
		return replacements[i].lineIdx > replacements[j].lineIdx
	})

	for _, r := range replacements {
		if r.deleteNext && r.nextLineIdx < len(lines) {
			lines = append(lines[:r.nextLineIdx], lines[r.nextLineIdx+1:]...)
		}
		if r.newLine == "" {
			lines = append(lines[:r.lineIdx], lines[r.lineIdx+1:]...)
		} else {
			lines[r.lineIdx] = r.newLine
		}
	}

	return strings.Join(lines, "\n")
}

func escapeString(s string) string {
	// Use backtick if possible (no backticks in string)
	if !strings.Contains(s, "`") && !strings.Contains(s, "\n") {
		return "`" + s + "`"
	}
	// Otherwise use double quotes with escaping
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	escaped = strings.ReplaceAll(escaped, "\n", `\n`)
	escaped = strings.ReplaceAll(escaped, "\t", `\t`)
	return `"` + escaped + `"`
}
