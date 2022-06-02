package core

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	lua "github.com/yuin/gopher-lua"

	"github.com/algorand/go-algorand/cmd/algomation/core/bindings"
)

var AlgomationCmd *cobra.Command

type params struct {
	ScriptFile string
}

func init() {
	var (
		p params
	)

	AlgomationCmd = &cobra.Command{
		Use:   "algomation",
		Short: "Execute lua scripts for algorand automation tasks.",
		Run: func(cmd *cobra.Command, args []string) {
			if err := run(p); err != nil {
				fmt.Fprintf(os.Stderr, "Problem running script: %s.\n", err)
			}
		},
	}

	AlgomationCmd.Flags().StringVarP(&p.ScriptFile, "file", "f", "", "script to execute")
}

func run(p params) error {
	L := lua.NewState()
	L.PreloadModule("test", bindings.TestLoader)
	ncLoader := bindings.MakeNodeControllerLoader("/home/will/go/bin", "/home/will/nodes/testdir")
	L.PreloadModule("algodModule", ncLoader)
	bindings.RegisterNodeControllerType(L)
	defer L.Close()
	if err := L.DoFile(p.ScriptFile); err != nil {
		return err
	}
	return nil
}
