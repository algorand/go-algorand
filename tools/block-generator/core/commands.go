package core

import (
	"github.com/algorand/go-algorand/tools/block-generator/generator"
	"github.com/algorand/go-algorand/tools/block-generator/runner"
	"github.com/spf13/cobra"
)

// BlockGenerator related cobra commands, ready to be executed or included as subcommands.
var BlockGenerator *cobra.Command

func init() {
	BlockGenerator = &cobra.Command{
		Use:   `block-generator`,
		Short: `Block generator testing tools.`,
	}
	BlockGenerator.AddCommand(runner.RunnerCmd)
	BlockGenerator.AddCommand(generator.DaemonCmd)
}
