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

//go:embed experimental.go.tmpl
var walkerTmpl string

func main() {
	var repo, pkg, typeName string

	// blah := types.LedgerStateDelta{}

	rootCmd := &cobra.Command{
		Use:   "mycli",
		Short: "A CLI for downloading, building, and instantiating Go packages.",
		Run: func(cmd *cobra.Command, args []string) {
			if err := runApp(repo, pkg, typeName); err != nil {
				log.Fatal(err)
			}
		},
	}

	rootCmd.Flags().StringVar(&repo, "repo", "", "GitHub repository URL")
	rootCmd.Flags().StringVar(&pkg, "package", "", "Go package path in the repo")
	rootCmd.Flags().StringVar(&typeName, "type", "", "Exported type in the package")

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runApp(repo, pkg, typeName string) error {
	if repo == "" || pkg == "" || typeName == "" {
		return fmt.Errorf("repo, package, and type flags are required")
	}

	// Download the repo
	if repo != "github.com/algorand/go-algorand" {
		err := goGet(repo)
		if err != nil {
			return err
		}
	}

	// Build the package
	err := goBuild(pkg)
	if err != nil {
		return err
	}

	// Show the type/outline
	err = showKind(pkg, typeName)
	if err != nil {
		return err
	}

	clearRepo := strings.Split(repo, "@")[0]
	if !strings.HasPrefix(pkg, clearRepo+"/") {
		return fmt.Errorf("package %q does not start with repo %q", pkg, clearRepo)
	}
	pkgOnly := strings.TrimPrefix(pkg, clearRepo+"/")
	// Instantiate the type
	err = instantiate(clearRepo, pkgOnly, typeName)
	if err != nil {
		return err
	}

	err = walkTheWalk(clearRepo, pkgOnly, typeName)
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
	fmt.Println("Instantiating type:", typeName)

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

func walkTheWalk(repo, pkgPath, typeName string) error {
	fmt.Printf("Walking %s from package %s...\n", typeName, pkgPath)

	tmpl, err := template.New("code").Parse(walkerTmpl)
	if err != nil {
		fmt.Println("Error parsing template:", err)
		os.Exit(1)
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, map[string]string{
		"ModulePath":   repo,
		"PackagePath":  pkgPath,
		"TypeInstance": typeName,
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
