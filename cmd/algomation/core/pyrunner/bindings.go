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
	pyNodeControllerType.Dict["start"] = py.MustNewMethod("Start", NodeController_start, 0, "")
	pyNodeControllerType.Dict["stop"] = py.MustNewMethod("Stop", NodeController_stop, 0, "")
	pyNodeControllerType.Dict["status"] = py.MustNewMethod("Status", NodeController_status, 0, "")

	methods := []*py.Method{
		py.MustNewMethod("Algod_new", NodeController_new, 0, ""),
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

type NodeControllerWrapper struct {
	nc     *nodecontrol.NodeController
	MadeBy string
}

func (nc *NodeControllerWrapper) Type() *py.Type {
	return pyNodeControllerType
}

func NodeController_new(module py.Object, args py.Tuple) (py.Object, error) {
	var bindir string
	var datadir string

	vars := []interface{}{bindir, &datadir}
	err := py.LoadTuple(args, vars)
	if err != nil {
		return nil, fmt.Errorf("unable to load bindir, and data dir: %w", err)
	}

	nc := nodecontrol.MakeNodeController(bindir, datadir)
	v := &NodeControllerWrapper{
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

func NodeController_start(self py.Object, args py.Tuple) (py.Object, error) {
	v, ok := self.(*NodeControllerWrapper)
	if !ok {
		return nil, fmt.Errorf("unexpected type provided to node controller start")
	}
	v.nc.StartAlgod(nodecontrol.AlgodStartArgs{})
	return py.None, nil
}

func NodeController_stop(self py.Object, args py.Tuple) (py.Object, error) {
	v, ok := self.(*NodeControllerWrapper)
	if !ok {
		return nil, fmt.Errorf("unexpected type provided to node controller start")
	}
	v.nc.StopAlgod()
	return py.None, nil
}

func NodeController_status(self py.Object, args py.Tuple) (py.Object, error) {
	v, ok := self.(*NodeControllerWrapper)
	if !ok {
		return nil, fmt.Errorf("unexpected type provided to node controller start")
	}

	c, err := v.nc.AlgodClient()
	if err != nil {
		return nil, fmt.Errorf("Problem getting client.")
	}
	s, err := c.Status()
	if err != nil {
		return nil, fmt.Errorf("Problem getting status.")
	}
	fmt.Printf("%v\n", s)
	return py.None, nil
}
