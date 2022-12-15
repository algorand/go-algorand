# Recipes

Most of the recipes' net.json and genesis.json use one of the following methods to call `netgoal generate`:
1. `Makefile`
2. `python3 {GO_ALGORAND_PATH}/test/testdata/deployednettemplates/generate-recipe/generate_network.py -f {PATH_TO}/network-tpl.json`

Details for netgoal generate could be found in the binary with:
```
netgoal generate -h
```

Source code for netgoal can be found in `{GO_ALGORAND_PATH}/cmd/netgoal/generate.go`
[Documentation](../../../../cmd/netgoal/README.md)

Make sure you set the PATH and GOPATH variables to the netgoal binary's path.

## Custom Recipe
Leverages the generate_network.py script and has unique instructions found in the README:
https://github.com/algorand/go-algorand/tree/master/test/testdata/deployednettemplates/recipes/custom
