# Custom Recipe
Custom Recipe can be used on your forked repo and be modified.

The key to this custom recipe is to serve as an example and a template for performance testing.

## Creating and Updating generated genesis.json, net.json, topology.json
1. Modify values in `network-tpl.json`
2. `cd go-algorand`
3. `python3 test/testdata/deployednettemplates/generate-recipe/generate_network.py -f test/testdata/deployednettemplates/recipes/custom/network-tpl.json`
4. This will create a new set of files in the `generated` folder
5. If you want to save a couple different generated files for testing, you can rename the generated folder, e.g. `generated1`, update the `network-tpl.json`, and rerun the python script. `python3 test/testdata/deployednettemplates/generate-recipe/generate_network.py -f test/testdata/deployednettemplates/recipes/custom/network-tpl.json`
6. If you want to run `generated1` you will have to update the paths in `recipe.json`.

## Updating consensus.json
If you add a `consensus.json` file with the protocol matching the one in network-tpl.json, the consensus.json will be added to the data folder before you spin up algonet.

1. To generate a consensus.json, run `goal protocols > consensus.json` on the latest code.
2. If you are using an existing protocol, all the keys have to match the ones you see after running `goal protocols`.