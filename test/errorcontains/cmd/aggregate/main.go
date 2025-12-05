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

// Command aggregate reads error capture JSONL files and produces an aggregated
// report with longest common substrings for each call site.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CapturedError represents one entry from the JSONL capture file.
type CapturedError struct {
	Test      string `json:"test"`
	File      string `json:"file"`
	Line      int    `json:"line"`
	ErrorType string `json:"error_type"`
	ErrorMsg  string `json:"error_msg"`
	UserMsg   string `json:"user_msg"`
	Unwrapped string `json:"unwrapped"`
}

// CallSite represents aggregated data for one file:line location.
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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: aggregate <input.jsonl> [output.json]")
		fmt.Println("       aggregate /tmp/all_errors.jsonl /tmp/error_sites.json")
		os.Exit(1)
	}

	inputFile := os.Args[1]
	outputFile := "/tmp/error_sites.json"
	if len(os.Args) > 2 {
		outputFile = os.Args[2]
	}

	// Read and parse input
	sites, err := readAndAggregate(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Compute LCS for each site
	for key, site := range sites {
		if len(site.Samples) > 0 {
			site.LCS = longestCommonSubstring(site.Samples)
			site.LCSLength = len(site.LCS)
			if site.LCSLength < 5 {
				site.NeedsReview = true
			}
		}
		// Keep only first 3 samples for output
		if len(site.Samples) > 3 {
			site.Samples = site.Samples[:3]
		}
		sites[key] = site
	}

	// Convert to sorted slice for output
	var results []CallSite
	for _, site := range sites {
		results = append(results, *site)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].File != results[j].File {
			return results[i].File < results[j].File
		}
		return results[i].Line < results[j].Line
	})

	// Write output
	output, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling output: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outputFile, output, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}

	// Print summary
	needsReview := 0
	for _, r := range results {
		if r.NeedsReview {
			needsReview++
		}
	}
	fmt.Printf("Aggregated %d call sites from %s\n", len(results), inputFile)
	fmt.Printf("Output written to %s\n", outputFile)
	fmt.Printf("Sites needing review (LCS < 5 chars): %d\n", needsReview)
}

func readAndAggregate(filename string) (map[string]*CallSite, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sites := make(map[string]*CallSite)
	scanner := bufio.NewScanner(f)
	// Increase buffer size for long lines
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		var entry CapturedError
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse line %d: %v\n", lineNum, err)
			continue
		}

		// Normalize file path
		entry.File = normalizePath(entry.File)

		key := fmt.Sprintf("%s:%d", entry.File, entry.Line)
		site, ok := sites[key]
		if !ok {
			site = &CallSite{
				File:       entry.File,
				Line:       entry.Line,
				ErrorTypes: make(map[string]int),
				UserMsgs:   make(map[string]int),
				Samples:    []string{},
			}
			sites[key] = site
		}

		site.Count++
		site.ErrorTypes[entry.ErrorType]++
		if entry.UserMsg != "" {
			site.UserMsgs[entry.UserMsg]++
		}

		// Add unique samples (up to 10 for LCS computation)
		if len(site.Samples) < 10 && !containsString(site.Samples, entry.ErrorMsg) {
			site.Samples = append(site.Samples, entry.ErrorMsg)
		}
	}

	return sites, scanner.Err()
}

func normalizePath(path string) string {
	// Remove the absolute path prefix, keep relative from repo root
	if idx := strings.Index(path, "go-algorand/"); idx != -1 {
		return path[idx+len("go-algorand/"):]
	}
	return filepath.Base(path)
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// longestCommonSubstring finds the longest substring common to all strings.
func longestCommonSubstring(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	if len(strs) == 1 {
		// For single sample, return first meaningful phrase
		return extractPhrase(strs[0])
	}

	// Start with LCS of first two strings
	lcs := lcs2(strs[0], strs[1])

	// Iteratively find LCS with remaining strings
	for i := 2; i < len(strs) && lcs != ""; i++ {
		lcs = lcs2(lcs, strs[i])
	}

	// Trim whitespace and clean up
	lcs = strings.TrimSpace(lcs)

	// If LCS is too short, try to find a common prefix
	if len(lcs) < 5 {
		prefix := commonPrefix(strs)
		if len(prefix) > len(lcs) {
			lcs = prefix
		}
	}

	return lcs
}

// lcs2 finds the longest common substring between two strings.
func lcs2(s1, s2 string) string {
	if s1 == "" || s2 == "" {
		return ""
	}

	// Use dynamic programming
	m, n := len(s1), len(s2)

	// Optimization: use shorter string as s1
	if m > n {
		s1, s2 = s2, s1
		m, n = n, m
	}

	// Use rolling array to save memory
	prev := make([]int, n+1)
	curr := make([]int, n+1)

	maxLen := 0
	endIdx := 0

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if s1[i-1] == s2[j-1] {
				curr[j] = prev[j-1] + 1
				if curr[j] > maxLen {
					maxLen = curr[j]
					endIdx = i
				}
			} else {
				curr[j] = 0
			}
		}
		prev, curr = curr, prev
		// Reset curr for next iteration
		for j := range curr {
			curr[j] = 0
		}
	}

	if maxLen == 0 {
		return ""
	}
	return s1[endIdx-maxLen : endIdx]
}

// commonPrefix finds the longest common prefix of all strings.
func commonPrefix(strs []string) string {
	if len(strs) == 0 {
		return ""
	}

	prefix := strs[0]
	for _, s := range strs[1:] {
		for !strings.HasPrefix(s, prefix) {
			prefix = prefix[:len(prefix)-1]
			if prefix == "" {
				return ""
			}
		}
	}
	return prefix
}

// extractPhrase extracts a meaningful phrase from a single error message.
// For single samples (or all identical samples), return the full message
// as it's the best possible match string.
func extractPhrase(msg string) string {
	msg = strings.TrimSpace(msg)
	// Return the full message - it's the only sample so use it entirely
	return msg
}
