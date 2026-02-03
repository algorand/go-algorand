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

// Command sentinel converts require.ErrorContains calls to require.ErrorIs
// where the error message matches a known sentinel error.
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// SentinelInfo holds information about an error sentinel variable.
type SentinelInfo struct {
	VarName string
	File    string
	Pkg     string
	Msg     string
}

// Regex patterns for finding error sentinels
var (
	// var ErrFoo = errors.New("message") - matches both " and ` quoted strings
	// Also matches lowercase (unexported) sentinels for same-package usage
	errorsNewRe = regexp.MustCompile("^(?:var\\s+)?([a-zA-Z][A-Za-z0-9_]*)\\s*=\\s*errors\\.New\\([\"\\x60]([^\"\\x60]+)[\"\\x60]\\)")
	// var ErrFoo = fmt.Errorf("message") - only static messages (no format verbs)
	fmtErrorfRe = regexp.MustCompile(`^(?:var\s+)?([a-zA-Z][A-Za-z0-9_]*)\s*=\s*fmt\.Errorf\("([^"]+)"\)`)
	// package declaration
	packageRe = regexp.MustCompile(`^package\s+(\w+)`)

	// require.ErrorContains(t, err, "message"...) or `message`...
	// Captures: 1=indent, 2=t var, 3=err var, 4=message literal (with quotes)
	// We use a simpler regex and handle the rest of the line separately
	errorContainsRe = regexp.MustCompile("^(\\s*)require\\.ErrorContains\\(([^,]+),\\s*([^,]+),\\s*(`[^`]+`|\"[^\"]+\")")
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: sentinel <root_dir> [--dry-run]")
		fmt.Println("       sentinel /path/to/go-algorand --dry-run")
		os.Exit(1)
	}

	rootDir := os.Args[1]
	dryRun := len(os.Args) > 2 && os.Args[2] == "--dry-run"

	// Scan for sentinels
	sentinelsByMsg, err := scanSentinels(rootDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error scanning sentinels: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Found %d unique sentinel messages\n", len(sentinelsByMsg))

	// Find and convert ErrorContains calls
	stats := struct {
		filesModified int
		converted     int
		skipped       int
	}{}

	err = filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if name == "vendor" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		original := string(content)
		modified := processFile(original, path, rootDir, sentinelsByMsg, &stats)

		if modified != original {
			stats.filesModified++
			if dryRun {
				fmt.Printf("Would modify: %s\n", path)
			} else {
				if err := os.WriteFile(path, []byte(modified), 0644); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", path, err)
					return nil
				}
				fmt.Printf("Modified: %s\n", path)
			}
		}
		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error walking directory: %v\n", err)
		os.Exit(1)
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
	fmt.Printf("  Converted to ErrorIs: %d\n", stats.converted)
	fmt.Printf("  Skipped (no sentinel match): %d\n", stats.skipped)
}

func processFile(content, filePath, rootDir string, sentinelsByMsg map[string][]SentinelInfo, stats *struct {
	filesModified int
	converted     int
	skipped       int
}) string {
	lines := strings.Split(content, "\n")

	type replacement struct {
		lineIdx int
		newLine string
	}
	var replacements []replacement

	for i, line := range lines {
		if !strings.Contains(line, "require.ErrorContains") {
			continue
		}

		matchLoc := errorContainsRe.FindStringSubmatchIndex(line)
		if matchLoc == nil {
			continue
		}

		// Extract capture groups using indices
		indent := line[matchLoc[2]:matchLoc[3]]
		tVar := strings.TrimSpace(line[matchLoc[4]:matchLoc[5]])
		errVar := strings.TrimSpace(line[matchLoc[6]:matchLoc[7]])
		msgLiteral := line[matchLoc[8]:matchLoc[9]]

		// Everything after the message literal to end of line
		rest := line[matchLoc[9]:]

		// Extract the actual message string (remove quotes)
		msg := msgLiteral
		if strings.HasPrefix(msg, "`") && strings.HasSuffix(msg, "`") {
			msg = msg[1 : len(msg)-1]
		} else if strings.HasPrefix(msg, `"`) && strings.HasSuffix(msg, `"`) {
			msg = msg[1 : len(msg)-1]
		}

		// Look up sentinel - first try exact match, then substring match
		var sentinel *SentinelInfo
		if sentinels, ok := sentinelsByMsg[msg]; ok && len(sentinels) > 0 {
			sentinel = &sentinels[0]
		} else {
			// Try substring match: find sentinels whose message contains this substring
			sentinel = findSubstringMatch(msg, sentinelsByMsg)
		}

		if sentinel == nil {
			stats.skipped++
			continue
		}

		// Check if sentinel is unexported and test is in different package
		isUnexported := len(sentinel.VarName) > 0 && sentinel.VarName[0] >= 'a' && sentinel.VarName[0] <= 'z'
		testPkg := getTestPackage(filePath, rootDir)
		if isUnexported && testPkg != sentinel.Pkg {
			stats.skipped++
			continue
		}

		sentinelRef := formatSentinelRef(sentinel.Pkg, sentinel.VarName, filePath, rootDir)

		// Build the new line, preserving any trailing arguments
		newLine := fmt.Sprintf("%srequire.ErrorIs(%s, %s, %s%s", indent, tVar, errVar, sentinelRef, rest)

		replacements = append(replacements, replacement{
			lineIdx: i,
			newLine: newLine,
		})
		stats.converted++
	}

	// Apply replacements in reverse order
	sort.Slice(replacements, func(i, j int) bool {
		return replacements[i].lineIdx > replacements[j].lineIdx
	})

	for _, r := range replacements {
		lines[r.lineIdx] = r.newLine
	}

	return strings.Join(lines, "\n")
}

// findSubstringMatch finds a sentinel whose message contains the given substring.
// If multiple sentinels match, returns the one with the shortest message (most specific).
func findSubstringMatch(substring string, sentinelsByMsg map[string][]SentinelInfo) *SentinelInfo {
	if len(substring) < 5 {
		// Too short - would match too many things
		return nil
	}

	var bestMatch *SentinelInfo
	bestLen := int(^uint(0) >> 1) // max int

	for msg, sentinels := range sentinelsByMsg {
		if strings.Contains(msg, substring) && len(sentinels) > 0 {
			if len(msg) < bestLen {
				bestLen = len(msg)
				s := sentinels[0]
				bestMatch = &s
			}
		}
	}

	return bestMatch
}

// getTestPackage returns the package name for a test file based on its directory.
func getTestPackage(testFilePath, rootDir string) string {
	testDir := filepath.Dir(testFilePath)
	relTestDir := testDir
	if strings.HasPrefix(testDir, rootDir) {
		relTestDir = strings.TrimPrefix(testDir, rootDir)
		relTestDir = strings.TrimPrefix(relTestDir, "/")
	}
	return filepath.Base(relTestDir)
}

// formatSentinelRef returns the appropriate reference to a sentinel variable.
func formatSentinelRef(sentinelPkg, sentinelVar, testFilePath, rootDir string) string {
	testDir := filepath.Dir(testFilePath)
	relTestDir := testDir
	if strings.HasPrefix(testDir, rootDir) {
		relTestDir = strings.TrimPrefix(testDir, rootDir)
		relTestDir = strings.TrimPrefix(relTestDir, "/")
	}

	testPkg := filepath.Base(relTestDir)

	if testPkg == sentinelPkg {
		return sentinelVar
	}

	return sentinelPkg + "." + sentinelVar
}

// scanSentinels walks a directory tree and finds all error sentinel definitions.
func scanSentinels(rootDir string) (map[string][]SentinelInfo, error) {
	sentinelsByMsg := make(map[string][]SentinelInfo)

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if name == "vendor" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(path, "/test/") {
			return nil
		}

		sentinels, err := extractSentinelsFromFile(path, rootDir)
		if err != nil {
			return nil
		}

		for _, s := range sentinels {
			sentinelsByMsg[s.Msg] = append(sentinelsByMsg[s.Msg], s)
		}
		return nil
	})

	return sentinelsByMsg, err
}

// extractSentinelsFromFile parses a Go file and extracts error sentinel definitions.
func extractSentinelsFromFile(path, rootDir string) ([]SentinelInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var sentinels []SentinelInfo
	var pkgName string

	relPath := path
	if strings.HasPrefix(path, rootDir) {
		relPath = strings.TrimPrefix(path, rootDir)
		relPath = strings.TrimPrefix(relPath, "/")
	}

	scanner := bufio.NewScanner(f)
	inVarBlock := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if pkgName == "" {
			if match := packageRe.FindStringSubmatch(trimmed); match != nil {
				pkgName = match[1]
			}
		}

		if strings.HasPrefix(trimmed, "var (") {
			inVarBlock = true
			continue
		}
		if inVarBlock && trimmed == ")" {
			inVarBlock = false
			continue
		}

		lineToCheck := trimmed
		if inVarBlock {
			lineToCheck = "var " + trimmed
		}

		if match := errorsNewRe.FindStringSubmatch(lineToCheck); match != nil {
			varName := match[1]
			if varName == "err" || varName == "e" {
				continue
			}
			sentinels = append(sentinels, SentinelInfo{
				VarName: varName,
				File:    relPath,
				Pkg:     pkgName,
				Msg:     match[2],
			})
			continue
		}

		if match := fmtErrorfRe.FindStringSubmatch(lineToCheck); match != nil {
			msg := match[2]
			if strings.ContainsAny(msg, "%") {
				continue
			}
			sentinels = append(sentinels, SentinelInfo{
				VarName: match[1],
				File:    relPath,
				Pkg:     pkgName,
				Msg:     msg,
			})
		}
	}

	return sentinels, scanner.Err()
}
