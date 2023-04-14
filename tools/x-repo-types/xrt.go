package main

import (
	"bytes"
	"fmt"
	"go/types"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
	"golang.org/x/tools/go/packages"

	_ "embed"
)

//go:embed xrt_tmpl.go.tmpl
var walkerTmpl string

func main() {
	var sBranch, xPkg, xType, yBranch, yPkg, yType string

	rootCmd := &cobra.Command{
		Use:   "xrt",
		Short: "Compare types across repos",
		Run: func(cmd *cobra.Command, args []string) {
			if err := runApp(sBranch, xPkg, xType, yBranch, yPkg, yType); err != nil {
				log.Fatal(err)
			}
		},
	}

	rootCmd.Flags().StringVar(&sBranch, "x-branch", "", "repository brahnch for type x")
	rootCmd.Flags().StringVar(&xPkg, "x-package", "", "Go repo and package for type x")
	rootCmd.Flags().StringVar(&xType, "x-type", "", "Exported type in the package for type x")
	rootCmd.Flags().StringVar(&yBranch, "y-branch", "", "repository branch for type y")
	rootCmd.Flags().StringVar(&yPkg, "y-package", "", "Go repo and package for type for type y")
	rootCmd.Flags().StringVar(&yType, "y-type", "", "Exported type in the package for type y")

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runApp(xBranch, xPkg, xType, yBranch, yPkg, yType string) error {
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

	// Build the package
	err = goBuild(xPkg)
	if err != nil {
		return err
	}
	err = goBuild(yPkg)
	if err != nil {
		return err
	}

	// Show the type/outline
	err = showKind(xPkg, xType)
	if err != nil {
		return err
	}
	err = showKind(yPkg, yType)
	if err != nil {
		return err
	}

	xParts := strings.Split(xPkg, "/")
	yParts := strings.Split(yPkg, "/")

	xRepo := strings.Join(xParts[:3], "/")
	yRepo := strings.Join(yParts[:3], "/")

	xPkgSuffix := strings.Join(xParts[3:], "/")
	yPkgSuffix := strings.Join(yParts[3:], "/")

	// Instantiate the type
	err = instantiate(xRepo, xPkgSuffix, xType)
	if err != nil {
		return err
	}
	err = instantiate(yRepo, yPkgSuffix, yType)
	if err != nil {
		return err
	}

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

func goBuild(pkg string) error {
	fmt.Println("Building package:", pkg)
	cmd := exec.Command("go", "build", pkg)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func showKind(pkg, typeName string) error {
	fmt.Println("Showing kind for:", typeName)

	// Load package
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedTypes}
	pkgs, err := packages.Load(cfg, pkg)
	if err != nil {
		return err
	}

	// Find the type
	var typ types.Object
	for _, p := range pkgs {
		obj := p.Types.Scope().Lookup(typeName)
		if obj != nil && obj.Exported() {
			typ = obj
			break
		}
	}

	if typ == nil {
		return fmt.Errorf("exported type %q not found in package %q", typeName, pkg)
	}

	// Show the type kind
	fmt.Printf("Type %q with (kind: %+v)\n\n", typeName, typ.String())
	return nil
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

	tmpDir, err := os.MkdirTemp(".", "walk-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	tmpFile := filepath.Join(tmpDir, "main.go")
	err = os.WriteFile(tmpFile, []byte(code), 0644)
	if err != nil {
		return err
	}

	cmd := exec.Command("go", "run", tmpFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func serializationDiff(xRepo, xPkgPath, xType, yRepo, yPkgPath, yType string) error {
	fmt.Printf("Diffing %s from package %s VS %s from package %s...\n", xType, xPkgPath, yType, yPkgPath)

	tmpl, err := template.New("code").Parse(walkerTmpl)
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

	tmpDir, err := os.MkdirTemp("", "walk-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	tmpFile := filepath.Join(tmpDir, "main.go")
	err = os.WriteFile(tmpFile, buf.Bytes(), 0644)
	if err != nil {
		return err
	}

	cmd := exec.Command("go", "run", tmpFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
