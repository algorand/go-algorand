// Copyright (C) 2019-2023 Algorand, Inc.
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
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/spf13/cobra"

	_ "embed"
)

//go:embed runner/main.tmpl
var differTmpl string

func main() {
	var xPkg, xBranch, xType, yPkg, yBranch, yType string

	rootCmd := &cobra.Command{
		Use:   "xrt",
		Short: "Compare types across repos",
		Run: func(cmd *cobra.Command, args []string) {
			if err := runApp(xPkg, xBranch, xType, yPkg, yBranch, yType); err != nil {
				log.Fatal(err)
			}
		},
	}

	rootCmd.Flags().StringVar(&xPkg, "x-package", "", "Go repo and package for type x")
	rootCmd.Flags().StringVar(&xBranch, "x-branch", "", "repository branch for type x")
	rootCmd.Flags().StringVar(&xType, "x-type", "", "Exported type in the package for type x")
	rootCmd.Flags().StringVar(&yPkg, "y-package", "", "Go repo and package for type for type y")
	rootCmd.Flags().StringVar(&yBranch, "y-branch", "", "repository branch for type y")
	rootCmd.Flags().StringVar(&yType, "y-type", "", "Exported type in the package for type y")

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runApp(xPkg, xBranch, xType, yPkg, yBranch, yType string) error {
	if xPkg == "" || xType == "" {
		return fmt.Errorf("package:%s, and type:%s flags are required", xPkg, xType)
	}
	if yPkg == "" || yType == "" {
		return fmt.Errorf("package:%s, and type:%s flags are required", yPkg, yType)
	}

	xPkgBranch := xPkg
	if xBranch != "" {
		xPkgBranch += "@" + xBranch
	}
	yPkgBranch := yPkg
	if yBranch != "" {
		yPkgBranch += "@" + yBranch
	}

	err := goGet(xPkgBranch)
	if err != nil {
		return err
	}
	err = goGet(yPkgBranch)
	if err != nil {
		return err
	}

	xParts := strings.Split(xPkg, "/")
	yParts := strings.Split(yPkg, "/")

	xRepo := strings.Join(xParts[:3], "/")
	yRepo := strings.Join(yParts[:3], "/")

	xPkgSuffix := strings.Join(xParts[3:], "/")
	yPkgSuffix := strings.Join(yParts[3:], "/")

	// Instantiate the type in a separate process as a "Smoke Test"
	err = instantiate(xRepo, xPkgSuffix, xType)
	if err != nil {
		return err
	}
	err = instantiate(yRepo, yPkgSuffix, yType)
	if err != nil {
		return err
	}

	// Compare the types by running the template xrt_tmpl.go.tmpl in a separate process
	// xrt_tmpl.go will return an error if the types are not the same
	// here we propagate the error to the caller, so as to fail the test.
	err = serializationDiff(xRepo, xPkgSuffix, xType, yRepo, yPkgSuffix, yType)
	if err != nil {
		return err
	}
	return nil
}

func goGet(repo string) error {
	fmt.Println("Downloading repo:", repo)
	cmd := exec.Command("go", "get", repo)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func instantiate(repo, pkgPath, typeName string) error {
	fmt.Println("Instantiating type for:", typeName)

	pkgParts := strings.Split(pkgPath, "/")
	pkgOnly := pkgParts[len(pkgParts)-1]

	code := fmt.Sprintf(`package main

import (
	"fmt"
	"%s/%s"
)

func main() {
	var item %s.%s
	fmt.Printf("Instantiated: %%#v\n\n", item)
}
`, repo, pkgPath, pkgOnly, typeName)

	tmpDir, err := os.MkdirTemp(".", "instantiate-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	tmpFile := filepath.Join(tmpDir, "main.go")
	err = os.WriteFile(tmpFile, []byte(code), 0644)
	if err != nil {
		return err
	}

	//nolint:gosec // tmpFile is defined above so no security concerns here
	cmd := exec.Command("go", "run", tmpFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func serializationDiff(xRepo, xPkgPath, xType, yRepo, yPkgPath, yType string) error {
	fmt.Printf("Diffing %s from package %s VS %s from package %s...\n", xType, xPkgPath, yType, yPkgPath)

	tmpl, err := template.New("code").Parse(differTmpl)
	if err != nil {
		fmt.Println("Error parsing template:", err)
		os.Exit(1)
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, map[string]string{
		"XModulePath":   xRepo,
		"XPackagePath":  xPkgPath,
		"XTypeInstance": xType,
		"YModulePath":   yRepo,
		"YPackagePath":  yPkgPath,
		"YTypeInstance": yType,
	})
	if err != nil {
		fmt.Println("Error executing template:", err)
		os.Exit(1)
	}

	main := filepath.Join("runner", "main.go")
	typeAnalyzer := filepath.Join("runner", "typeAnalyzer.go")
	err = os.WriteFile(main, buf.Bytes(), 0644)
	if err != nil {
		return err
	}

	cmd := exec.Command("go", "run", main, typeAnalyzer)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
