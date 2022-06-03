package pyrunner

import (
	"fmt"

	"github.com/go-python/gpython/py"
	"github.com/go-python/gpython/repl"
	"github.com/go-python/gpython/repl/cli"
	// This initializes gpython for runtime execution and is essential.
	// It defines forward-declared symbols and registers native built-in modules, such as sys and time.
	_ "github.com/go-python/gpython/modules"

	"github.com/algorand/go-algorand/cmd/algomation/core/common"
)

func Run(p common.Params) error {
	return runWithFile(p.ScriptFile)
}

// Copied directly from example:
// https://github.com/go-python/gpython/blob/80944be95fc263ed7845f6a7eafb6a4b1831c1a6/examples/embedding/main.go#L26
func runWithFile(pyFile string) error {

	// See type Context interface and related docs
	ctx := py.NewContext(py.DefaultContextOpts())

	// This drives modules being able to perform cleanup and release resources
	defer ctx.Close()

	var err error
	if len(pyFile) == 0 {
		replCtx := repl.New(ctx)

		fmt.Print("\n=======  Entering REPL mode, press Ctrl+D to exit  =======\n")

		_, err = py.RunFile(ctx, "lib/REPL-startup.py", py.CompileOpts{}, replCtx.Module)
		if err == nil {
			cli.RunREPL(replCtx)
		}

	} else {
		_, err = py.RunFile(ctx, pyFile, py.CompileOpts{}, nil)
	}

	if err != nil {
		py.TracebackDump(err)
	}

	return err
}
