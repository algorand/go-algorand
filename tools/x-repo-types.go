package main

import (
	"encoding/csv"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

var goal = "go-algorand"
var goalSDK = "go-algorand-sdk"
var goalStateProof = "go-stateproof-verification"

var repos = map[string]string{
	goal:           "master",
	goalSDK:        "develop",
	goalStateProof: "x-repo-types",
}

type Field struct {
	Name string
	Type string
	Tag  string
}

type StructInfo struct {
	Name     string
	Location string
	Mirror   string
	Fields   []Field
}

type ScoredPair struct {
	X     StructInfo
	Y     StructInfo
	Score float64
}

func similarityScore(s1, s2 StructInfo) float64 {
	f1 := make([]Field, len(s1.Fields))
	copy(f1, s1.Fields)
	f2 := make([]Field, len(s2.Fields))
	copy(f2, s2.Fields)

	sortFieldsByName(f1)
	sortFieldsByName(f2)

	totalMetric := 0.0
	maxLen := max(len(f1), len(f2))

	for i := 0; i < maxLen; i++ {
		if i < len(f1) && i < len(f2) {
			totalMetric += compareFields(f1[i], f2[i])
		}
	}
	if maxLen == 0 {
		// in the case of no fields, pretend there is a single
		// identical field.
		maxLen += 1
		totalMetric += 2.5
	}

	if s1.Name == s2.Name {
		totalMetric += 2.5 * float64(maxLen)
	}

	// Normalize the distance
	return totalMetric / (5.0 * float64(maxLen))

}

func sortFieldsByName(fields []Field) {
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].Name < fields[j].Name
	})
}

func compareFields(field1, field2 Field) float64 {
	var dist float64 = 0

	if field1.Name == field2.Name {
		dist += 1
	}
	if field1.Type == field2.Type {
		dist += 1
	}
	if field1.Tag == field2.Tag {
		dist += 0.5
	}

	return dist
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func algorandURL(repo string) string {
	return fmt.Sprintf("https://github.com/tzaffi/%s", repo)
}

func main() {
	repoStructs := make(map[string][]StructInfo)
	for repo, branch := range repos {
		repoObj, err := gitClone(repo, branch)
		if err != nil {
			log.Printf("Error cloning repository %s: %v", repo, err)
			os.Exit(1)
		}
		_ = repoObj
		allStructs, err := extractStructs(repo)
		if err != nil {
			log.Printf("Error extracting structs from repository %s: %v", repo, err)
			os.Exit(1)
		}

		// Sort all structs by their names
		sort.Slice(allStructs, func(i, j int) bool {
			return allStructs[i].Name < allStructs[j].Name
		})
		// Write all structs to a single CSV file
		writeStructsToCSV(repo, allStructs)

		repoStructs[repo] = allStructs
	}

	saveSimilarStructs(repoStructs, goal, goalStateProof, 25)
	saveSimilarStructs(repoStructs, goal, goalSDK, 250)

}

func gitClone(repo, branch string) (*git.Repository, error) {
	// Clone the repository

	err := os.RemoveAll(repo)
	if err != nil {
		return nil, fmt.Errorf("failed to remove local repository directory: %w", err)
	}

	repoObj, err := git.PlainClone(repo, false, &git.CloneOptions{
		URL:           algorandURL(repo),
		ReferenceName: plumbing.ReferenceName(fmt.Sprintf("refs/heads/%s", branch)),
		SingleBranch:  true,
		Depth:         1,
		Tags:          git.NoTags,
	})

	if err != nil {
		return nil, err
	}

	return repoObj, nil
}

func extractStructs(repoPath string) (allStructs []StructInfo, err error) {
	err = filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && filepath.Ext(path) == ".go" {
			err = processGoFile(path, &allStructs)
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		err = fmt.Errorf("error processing repository %s: %w", repoPath, err)
	}
	return
}

func processGoFile(filename string, allStructs *[]StructInfo) error {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("error parsing file %s: %w", filename, err)
	}

	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.TypeSpec:
			if theStructType, ok := x.Type.(*ast.StructType); ok {
				structName := x.Name.Name
				mirrorOf, fields := getFlatFields(theStructType)
				*allStructs = append(
					*allStructs,
					StructInfo{
						Name:     structName,
						Fields:   fields,
						Location: filename,
						Mirror:   mirrorOf,
					})
			}
		}
		return true
	})
	return nil
}

func getFlatFields(obj *ast.StructType) (string, []Field) {
	var fields []Field
	// By convention, to denote the source of a Struct,
	// annotate the first field in the form:
	// "// @mirrorOf: REPO_PATH::STRUCT_NAME"
	mirrorOf := ""

	for _, field := range obj.Fields.List {
		if len(field.Names) == 0 { // Anonymous field (embedded struct)
			ident, ok := field.Type.(*ast.Ident)
			if ok && ident.Obj != nil {
				typeSpec, ok := ident.Obj.Decl.(*ast.TypeSpec)
				if ok {
					embeddedStruct, ok := typeSpec.Type.(*ast.StructType)
					if ok {
						mirrorOf2, embeddedFields := getFlatFields(embeddedStruct)
						fields = append(fields, embeddedFields...)
						if mirrorOf2 != "" {
							mirrorOf = mirrorOf2
						}
					}
				}
			}
		} else {
			if field.Doc != nil {
				// Get the annotation comment
				for _, commentGroup := range field.Doc.List {
					text := commentGroup.Text
					if strings.HasPrefix(text, "// @mirrorOf:") {
						mirrorOf = strings.TrimPrefix(text, "// @mirrorOf:")
					}
				}
			}

			if field.Names == nil { //|| !ast.IsExported(field.Names[0].Name) {
				continue
			}

			// Handle pointer types correctly
			var fieldType string
			switch t := field.Type.(type) {
			case *ast.Ident:
				fieldType = t.Name
			case *ast.StarExpr:
				if ident, ok := t.X.(*ast.Ident); ok {
					fieldType = "*" + ident.Name
				}
			case *ast.ArrayType:
				if ident, ok := t.Elt.(*ast.Ident); ok {
					fieldType = "[]" + ident.Name
				}
			case *ast.SelectorExpr:
				if ident, ok := t.X.(*ast.Ident); ok {
					fieldType = ident.Name + "." + t.Sel.Name
				}
			case *ast.MapType:
				if keyIdent, ok := t.Key.(*ast.Ident); ok {
					if valueIdent, ok := t.Value.(*ast.Ident); ok {
						fieldType = fmt.Sprintf("map[%s]%s", keyIdent.Name, valueIdent.Name)
					}
				}
			case *ast.ChanType:
				if ident, ok := t.Value.(*ast.Ident); ok {
					fieldType = "chan " + ident.Name
				}
			case *ast.FuncType:
				fieldType = "func"
				if t.Params != nil {
					fieldType += "("
					for _, param := range t.Params.List {
						if ident, ok := param.Type.(*ast.Ident); ok {
							fieldType += fmt.Sprintf(" %s", ident.Name)
						}
					}
					fieldType += ")"
				}
				if t.Results != nil {
					if len(t.Results.List) == 1 {
						if ident, ok := t.Results.List[0].Type.(*ast.Ident); ok {
							fieldType += fmt.Sprintf(" %s", ident.Name)
						}
					} else {
						fieldType += " ("
						for _, result := range t.Results.List {
							if ident, ok := result.Type.(*ast.Ident); ok {
								fieldType += fmt.Sprintf(" %s", ident.Name)
							}
						}
						fieldType += ")"
					}
				}
			case *ast.InterfaceType:
				fieldType = "interface{}"
			case *ast.StructType:
				fieldType = "struct {...see source...}"
			default:
				continue
			}

			fieldName := field.Names[0].Name
			fieldTag := ""

			if field.Tag != nil {
				fieldTag = field.Tag.Value
			}

			fields = append(fields, Field{Name: fieldName, Type: fieldType, Tag: fieldTag})
		}
	}

	return mirrorOf, fields
}

func writeStructsToCSV(repo string, structs []StructInfo) {
	csvFile, err := os.Create(fmt.Sprintf("%s.csv", repo))
	if err != nil {
		log.Printf("Error creating CSV file: %v", err)
		return
	}
	defer csvFile.Close()

	csvWriter := csv.NewWriter(csvFile)
	defer csvWriter.Flush()

	if err := csvWriter.Write([]string{"struct name", "location", "mirrorOf"}); err != nil {
		log.Printf("Error writing CSV header: %v", err)
	}

	for _, structInfo := range structs {
		record := []string{structInfo.Name, structInfo.Location, structInfo.Mirror}
		if err := csvWriter.Write(record); err != nil {
			log.Printf("Error writing CSV record: %v", err)
		}
	}
}

func saveSimilarStructs(repoStructs map[string][]StructInfo, source string, target string, top int) {
	goalStructs, ok := repoStructs[source]
	if !ok {
		log.Printf("%s structs not found", source)
		os.Exit(1)
	}

	targetStructs, ok := repoStructs[target]
	if !ok {
		log.Printf("%s structs not found", target)
		os.Exit(1)
	}

	scoredPairs := sortedComparisons(goalStructs, targetStructs, top)

	file, err := os.Create(fmt.Sprintf("%s_V_%s.csv", source, target))
	if err != nil {
		log.Printf("Error creating CSV file: %v", err)
		os.Exit(1)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{
		"score",
		fmt.Sprintf("%s struct", source),
		fmt.Sprintf("%s struct", target),
		fmt.Sprintf("%s location", source),
		fmt.Sprintf("%s location", target),
	})

	for _, pair := range scoredPairs {
		writer.Write([]string{
			strconv.FormatFloat(pair.Score, 'f', 2, 64),
			pair.X.Name,
			pair.Y.Name,
			pair.X.Location,
			pair.Y.Location,
		})
	}
}

// sortedComparisons returns the top N scored pairs of structs.
// Comparison is done using scores and then by name to break ties.
func sortedComparisons(structs1, structs2 []StructInfo, top int) []ScoredPair {
	pairs := []ScoredPair{}

	for _, s1 := range structs1 {
		for _, s2 := range structs2 {
			score := similarityScore(s1, s2)
			pairs = append(pairs, ScoredPair{X: s1, Y: s2, Score: score})
		}
	}

	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Score == pairs[j].Score {
			return pairs[i].X.Name < pairs[j].X.Name
		}
		return pairs[i].Score > pairs[j].Score
	})

	if len(pairs) < top {
		return pairs
	}
	return pairs[:top]
}
