package luarunner

import (
	"fmt"

	lua "github.com/yuin/gopher-lua"

	"github.com/algorand/go-algorand/nodecontrol"
)

// testLoader basic module test that also has field.
func testLoader(L *lua.LState) int {
	// this mod thing might be a hack.
	var mod *lua.LTable

	start := func(L *lua.LState) int {
		fmt.Println("Start algod here...")
		L.SetField(mod, "state", lua.LString("started"))
		return 0
	}

	var exports = map[string]lua.LGFunction{
		"start": start,
	}

	// register functions to the table
	mod = L.SetFuncs(L.NewTable(), exports)

	// register other stuff
	L.SetField(mod, "state", lua.LString("stopped"))

	// returns the module
	L.Push(mod)
	return 1
}

// makeNodeControllerLoader initializes bindings to node controller with hard coded bin/data dir.
// Example lua:
// 	   local algod = require("algodModule")
// 	   print("Starting node.")
// 	   algod.start()
// 	   print("Getting status, node started.")
// 	   algod.status()
// 	   print("Stopping node.")
// 	   algod.stop()
func makeNodeControllerLoader(bindir, datadir string) lua.LGFunction {
	return func(L *lua.LState) int {
		var mod *lua.LTable
		nc := nodecontrol.MakeNodeController(bindir, datadir)

		var exports = map[string]lua.LGFunction{
			"start": func(L *lua.LState) int {
				nc.StartAlgod(nodecontrol.AlgodStartArgs{})
				return 0
			},
			"stop": func(L *lua.LState) int {
				nc.StopAlgod()
				return 0
			},
			"status": func(L *lua.LState) int {
				c, err := nc.AlgodClient()
				if err != nil {
					fmt.Println("Problem getting client.")
					return 1
				}
				s, err := c.Status()
				if err != nil {
					fmt.Println("Problem getting status.")
					return 1
				}
				fmt.Printf("%v\n", s)
				return 0
			},
		}

		// register functions to the table
		mod = L.SetFuncs(L.NewTable(), exports)

		// returns the module
		L.Push(mod)
		return 1
	}
}

const luaNodeControllerName = "node-controller"

func checkNodeController(L *lua.LState) *nodecontrol.NodeController {
	ud := L.CheckUserData(1)
	if v, ok := ud.Value.(*nodecontrol.NodeController); ok {
		return v
	}
	L.ArgError(1, "node controller expected")
	return nil
}

// registerNodeControllerType initializes bindings to a global node controller type.
// Example lua:
//		local node = algod.new("/home/will/go/bin", "/home/will/nodes/testdir")
//		node:start()
//		node:status()
//		node:stop()
func registerNodeControllerType(L *lua.LState) {
	// Constructor
	newAlgod := func(L *lua.LState) int {
		nc := nodecontrol.MakeNodeController(L.CheckString(1), L.CheckString(2))
		ud := L.NewUserData()
		ud.Value = &nc
		L.SetMetatable(ud, L.GetTypeMetatable(luaNodeControllerName))
		L.Push(ud)
		return 1
	}

	// Type methods
	var methods = map[string]lua.LGFunction{
		"start": func(L *lua.LState) int {
			nc := checkNodeController(L)
			nc.StartAlgod(nodecontrol.AlgodStartArgs{})
			return 1
		},
		"stop": func(L *lua.LState) int {
			nc := checkNodeController(L)
			nc.StopAlgod()
			return 1
		},
		"status": func(L *lua.LState) int {
			nc := checkNodeController(L)
			c, err := nc.AlgodClient()
			if err != nil {
				fmt.Println("Problem getting client.")
				return 1
			}
			s, err := c.Status()
			if err != nil {
				fmt.Println("Problem getting status.")
				return 1
			}
			fmt.Printf("%v\n", s)
			return 1
		},
	}

	// Register new type
	mt := L.NewTypeMetatable(luaNodeControllerName)
	L.SetGlobal("algod", mt)
	L.SetField(mt, "new", L.NewFunction(newAlgod))
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), methods))
}
