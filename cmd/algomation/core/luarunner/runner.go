package luarunner

import (
	"github.com/algorand/go-algorand/cmd/algomation/core/common"
	lua "github.com/yuin/gopher-lua"
)

func Run(p common.Params) error {
	L := lua.NewState()
	L.PreloadModule("test", testLoader)
	ncLoader := makeNodeControllerLoader("/home/will/go/bin", "/home/will/nodes/testdir")
	L.PreloadModule("algodModule", ncLoader)
	registerNodeControllerType(L)
	defer L.Close()
	if err := L.DoFile(p.ScriptFile); err != nil {
		return err
	}
	return nil
}
