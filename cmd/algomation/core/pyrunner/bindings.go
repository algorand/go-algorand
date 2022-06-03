package pyrunner

import (
	"fmt"
	"runtime"

	"github.com/go-python/gpython/py"

	"github.com/algorand/go-algorand/nodecontrol"
)

var (
	pyNodeControllerType = py.NewType("NodeController", "")
)

func init() {
	pyNodeControllerType.Dict["start"] = py.MustNewMethod("Start", nodeControllerStart, 0, "")
	pyNodeControllerType.Dict["stop"] = py.MustNewMethod("Stop", nodeControllerStop, 0, "")
	pyNodeControllerType.Dict["status"] = py.MustNewMethod("Status", nodeControllerStatus, 0, "")

	methods := []*py.Method{
		py.MustNewMethod("Algod_new", nodeControllerNew, 0, ""),
	}

	// Register a ModuleImpl instance used by the gpython runtime to instantiate new py.Module when first imported.
	py.RegisterModule(&py.ModuleImpl{
		Info: py.ModuleInfo{
			Name: "algod_go",
			Doc:  "Algod node controller wrapper.",
		},
		Methods: methods,
		Globals: py.StringDict{
			"PY_VERSION": py.String("Python 3.4 (github.com/go-python/gpython)"),
			"GO_VERSION": py.String(fmt.Sprintf("%s on %s %s", runtime.Version(), runtime.GOOS, runtime.GOARCH)),
			"MYLIB_VERS": py.String("Algod 1.0 by Will"),
		},
		OnContextClosed: func(instance *py.Module) {
			fmt.Print("<<< host py.Context of py.Module instance closing >>>\n+++\n")
		},
	})
}

type nodeControllerWrapper struct {
	nc     *nodecontrol.NodeController
	MadeBy string
}

func (nc *nodeControllerWrapper) Type() *py.Type {
	return pyNodeControllerType
}

func nodeControllerNew(module py.Object, args py.Tuple) (py.Object, error) {
	var bindir string
	var datadir string

	vars := []interface{}{bindir, &datadir}
	err := py.LoadTuple(args, vars)
	if err != nil {
		return nil, fmt.Errorf("unable to load bindir, and data dir: %w", err)
	}

	nc := nodecontrol.MakeNodeController(bindir, datadir)
	v := &nodeControllerWrapper{
		nc: &nc,
	}

	// For Module-bound methods, we have easy access to the parent Module
	py.LoadAttr(module, "MYLIB_VERS", &v.MadeBy)

	ret := py.Tuple{
		v,
		py.String(v.MadeBy),
	}

	return ret, nil
}

func nodeControllerStart(self py.Object, args py.Tuple) (py.Object, error) {
	v, ok := self.(*nodeControllerWrapper)
	if !ok {
		return nil, fmt.Errorf("unexpected type provided to node controller start")
	}
	v.nc.StartAlgod(nodecontrol.AlgodStartArgs{})
	return py.None, nil
}

func nodeControllerStop(self py.Object, args py.Tuple) (py.Object, error) {
	v, ok := self.(*nodeControllerWrapper)
	if !ok {
		return nil, fmt.Errorf("unexpected type provided to node controller start")
	}
	v.nc.StopAlgod()
	return py.None, nil
}

func nodeControllerStatus(self py.Object, args py.Tuple) (py.Object, error) {
	v, ok := self.(*nodeControllerWrapper)
	if !ok {
		return nil, fmt.Errorf("unexpected type provided to node controller start")
	}

	c, err := v.nc.AlgodClient()
	if err != nil {
		return nil, fmt.Errorf("problem getting client")
	}
	s, err := c.Status()
	if err != nil {
		return nil, fmt.Errorf("problem getting status")
	}
	fmt.Printf("%v\n", s)
	return py.None, nil
}
