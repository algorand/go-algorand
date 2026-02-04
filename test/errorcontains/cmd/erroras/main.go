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

// Command erroras converts require.ErrorContains calls to require.ErrorAs
// where the captured runtime error type is a typed error (not plain string).
// It reads the aggregated error_sites.json produced by the aggregate tool
// and matches ErrorContains substrings to find typed error sites.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// CallSite from the aggregate tool output.
type CallSite struct {
	File       string         `json:"file"`
	Line       int            `json:"line"`
	ErrorTypes map[string]int `json:"error_types"`
	LCS        string         `json:"lcs"`
	Samples    []string       `json:"samples"`
}

// Plain error types that don't benefit from ErrorAs
var plainTypes = map[string]bool{
	"*errors.errorString": true,
	"*fmt.wrapError":      true,
	"*fmt.wrapErrors":     true,
	"*errors.joinError":   true,
}

// Matches require.ErrorContains or assert.ErrorContains
var errorContainsRe = regexp.MustCompile("^(\\s*)(require|assert)\\.ErrorContains\\(([^,]+),\\s*([^,]+),\\s*(`[^`]+`|\"[^\"]+\")")

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: erroras <error_sites.json> <root_dir> [--dry-run]")
		fmt.Println("       erroras error_sites.json /path/to/go-algorand --dry-run")
		os.Exit(1)
	}

	sitesFile := os.Args[1]
	rootDir := os.Args[2]
	dryRun := len(os.Args) > 3 && os.Args[3] == "--dry-run"

	// Load sites and filter to those with typed errors
	typedSites, err := loadTypedSites(sitesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading sites: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Found %d call sites with typed errors\n", len(typedSites))

	// Walk codebase and convert
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
			if name := info.Name(); name == "vendor" || name == ".git" {
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
		modified := processFile(original, path, rootDir, typedSites, &stats)

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
	fmt.Printf("  Converted to ErrorAs: %d\n", stats.converted)
	fmt.Printf("  Skipped (unexported cross-pkg): %d\n", stats.skipped)
}

// loadTypedSites reads error_sites.json and returns only sites where
// a non-plain typed error was observed.
func loadTypedSites(filename string) ([]CallSite, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var allSites []CallSite
	if err := json.Unmarshal(data, &allSites); err != nil {
		return nil, err
	}

	var typed []CallSite
	for _, site := range allSites {
		typedErr := bestTypedError(site.ErrorTypes)
		if typedErr != "" {
			// Unescape the LCS (aggregate tool double-escapes)
			site.LCS = unescapeJSON(site.LCS)
			for i := range site.Samples {
				site.Samples[i] = unescapeJSON(site.Samples[i])
			}
			typed = append(typed, site)
		}
	}
	return typed, nil
}

// bestTypedError returns the most useful typed error from the error_types map,
// or empty string if only plain error types were seen.
func bestTypedError(types map[string]int) string {
	var best string
	for t := range types {
		if !plainTypes[t] {
			best = t
		}
	}
	return best
}

// unescapeJSON undoes the double-escaping from the capture tool's manual JSON encoding.
func unescapeJSON(s string) string {
	s = strings.ReplaceAll(s, `\"`, `"`)
	s = strings.ReplaceAll(s, `\\`, `\`)
	return s
}

// funcRe matches top-level function declarations to identify scope boundaries.
var funcRe = regexp.MustCompile(`^func\s`)

func processFile(content, filePath, rootDir string, typedSites []CallSite, stats *struct {
	filesModified int
	converted     int
	skipped       int
}) string {
	lines := strings.Split(content, "\n")

	relPath := filePath
	for _, repoName := range []string{"go-algorand/", "errorcontains/"} {
		if idx := strings.Index(filePath, repoName); idx != -1 {
			relPath = filePath[idx+len(repoName):]
			break
		}
	}

	testPkg := filepath.Base(filepath.Dir(filePath))

	// Map each line to its enclosing function start line so we can
	// deduplicate var declarations per function scope.
	funcStartForLine := make([]int, len(lines))
	currentFunc := -1
	for i, line := range lines {
		if funcRe.MatchString(line) {
			currentFunc = i
		}
		funcStartForLine[i] = currentFunc
	}

	type replacement struct {
		lineIdx int
		varDecl string // empty if var already declared in this function
		newLine string
	}
	var replacements []replacement

	// Track which var names have been declared per function scope
	declaredInFunc := map[int]map[string]bool{}

	for i, line := range lines {
		if !strings.Contains(line, ".ErrorContains") {
			continue
		}

		matchLoc := errorContainsRe.FindStringSubmatchIndex(line)
		if matchLoc == nil {
			continue
		}

		indent := line[matchLoc[2]:matchLoc[3]]
		assertPkg := line[matchLoc[4]:matchLoc[5]]
		tVar := strings.TrimSpace(line[matchLoc[6]:matchLoc[7]])
		errVar := strings.TrimSpace(line[matchLoc[8]:matchLoc[9]])
		msgLiteral := line[matchLoc[10]:matchLoc[11]]
		rest := line[matchLoc[11]:]

		msg := msgLiteral
		if strings.HasPrefix(msg, "`") && strings.HasSuffix(msg, "`") {
			msg = msg[1 : len(msg)-1]
		} else if strings.HasPrefix(msg, `"`) && strings.HasSuffix(msg, `"`) {
			msg = msg[1 : len(msg)-1]
		}

		site := findMatchingSite(relPath, msg, typedSites)
		if site == nil {
			continue
		}

		errType := bestTypedError(site.ErrorTypes)
		ti := parseTypeInfo(errType)
		if ti == nil {
			stats.skipped++
			continue
		}

		if !ti.exported && ti.pkg != testPkg {
			stats.skipped++
			continue
		}

		typeRef := ti.qualifiedType(testPkg)
		varName := ti.varName()

		// Only emit var declaration on first use per function
		funcStart := funcStartForLine[i]
		if declaredInFunc[funcStart] == nil {
			declaredInFunc[funcStart] = map[string]bool{}
		}
		var varDecl string
		if !declaredInFunc[funcStart][varName] {
			varDecl = fmt.Sprintf("%svar %s %s", indent, varName, typeRef)
			declaredInFunc[funcStart][varName] = true
		}

		var newLine string
		if rest != "" && rest != ")" {
			newLine = fmt.Sprintf("%s%s.ErrorAs(%s, %s, &%s%s", indent, assertPkg, tVar, errVar, varName, rest)
		} else {
			newLine = fmt.Sprintf("%s%s.ErrorAs(%s, %s, &%s)", indent, assertPkg, tVar, errVar, varName)
		}

		replacements = append(replacements, replacement{
			lineIdx: i,
			varDecl: varDecl,
			newLine: newLine,
		})
		stats.converted++
	}

	if len(replacements) == 0 {
		return content
	}

	// Apply in reverse order so line indices stay valid
	sort.Slice(replacements, func(i, j int) bool {
		return replacements[i].lineIdx > replacements[j].lineIdx
	})

	for _, r := range replacements {
		lines[r.lineIdx] = r.newLine
		if r.varDecl != "" {
			lines = append(lines[:r.lineIdx], append([]string{r.varDecl}, lines[r.lineIdx:]...)...)
		}
	}

	return strings.Join(lines, "\n")
}

// findMatchingSite finds a typed error site where any sample error message
// contains the ErrorContains substring, scoped to the same file.
func findMatchingSite(relPath, substring string, sites []CallSite) *CallSite {
	for i := range sites {
		site := &sites[i]
		if site.File != relPath && filepath.Base(site.File) != filepath.Base(relPath) {
			continue
		}
		// Check if the LCS or any sample contains the substring
		if strings.Contains(site.LCS, substring) {
			return site
		}
		for _, sample := range site.Samples {
			if strings.Contains(sample, substring) {
				return site
			}
		}
	}
	return nil
}

type typeInfo struct {
	pkg      string
	typeName string
	pointer  bool
	exported bool
}

func parseTypeInfo(typeStr string) *typeInfo {
	ti := &typeInfo{}

	s := typeStr
	if strings.HasPrefix(s, "*") {
		ti.pointer = true
		s = s[1:]
	}

	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 || parts[1] == "" {
		return nil
	}

	ti.pkg = parts[0]
	ti.typeName = parts[1]
	ti.exported = unicode.IsUpper(rune(ti.typeName[0]))

	return ti
}

func (ti *typeInfo) qualifiedType(currentPkg string) string {
	var prefix string
	if ti.pointer {
		prefix = "*"
	}
	if ti.pkg == currentPkg {
		return prefix + ti.typeName
	}
	return prefix + ti.pkg + "." + ti.typeName
}

func (ti *typeInfo) varName() string {
	name := ti.typeName
	if len(name) > 0 {
		name = strings.ToLower(name[:1]) + name[1:]
	}
	if strings.HasSuffix(name, "Error") && len(name) > 5 {
		name = name[:len(name)-5] + "Err"
	}
	return name
}
