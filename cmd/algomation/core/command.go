package core

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/algorand/go-algorand/cmd/algomation/core/common"
	"github.com/algorand/go-algorand/cmd/algomation/core/luarunner"
	"github.com/algorand/go-algorand/cmd/algomation/core/pyrunner"

	"github.com/spf13/cobra"
)

var AlgomationCmd *cobra.Command

func init() {
	var (
		p common.Params
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

func run(p common.Params) error {
	switch ext := filepath.Ext(p.ScriptFile); ext {
	case ".lua":
		return luarunner.Run(p)
	case ".py":
		return pyrunner.Run(p)
	default:
		return fmt.Errorf("unknown script extension: %s", ext)
	}

}
