// Copyright (C) 2019-2024 Algorand, Inc.
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
