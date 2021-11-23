# Custom Recipe
Custom Recipe can be used on your forked repo and be modified.

The key to this custom recipe is to serve as an example and a template for performance testing.

## Creating and Updating generated genesis.json, net.json, topology.json
1. Modify values in `network-tpl.json`
- `"FractionApply"` in configs/node.json represents the number of nodes to report to telemetry. We don't want to overwhelm the telemetry server, so use "0.2" on a large network. For small networks, you may need to update it to "1.0"
2. `cd go-algorand`
3. `python3 test/testdata/deployednettemplates/generate-recipe/generate_network.py -f test/testdata/deployednettemplates/recipes/custom/network-tpl.json`
4. This will create a new set of files in the `generated` folder
5. If you want to save a couple different generated files for testing, you can rename the generated folder, e.g. `generated1`, update the `network-tpl.json`, and rerun the python script. `python3 test/testdata/deployednettemplates/generate-recipe/generate_network.py -f test/testdata/deployednettemplates/recipes/custom/network-tpl.json`
6. If you want to run `generated1` you will have to update the paths in `recipe.json`.

## Updating consensus.json
If you add a `consensus.json` file with the protocol matching the one in network-tpl.json, the `consensus.json` will be added to the data folder before you spin up algonet.

** Remove consensus.json if you don't want to overwrite the default consensus values!**
1. To generate a consensus.json, run `goal protocols > generated_consensus.json` on the latest code.
2. For whichever protocol you are trying to overwrite, you must have all the keys the protocol has in the `generated_consensus.json`. Copy and paste the protocol object you're interested in and paste it into `consensus.json`
3. Make sure `consensus.json` is a valid json and then update the values for the particular protocol. Save.

## Updating config.json
If you look at the files in `configs/node.json`, `nonPartNode.json`, and `relay.json` you will see there's already a `ConfigJSONOverride` parameter. This will be used to create a config.json in algonet's data folders. However, if you want to easily add **additional** config changes to all three types of nodes, you can add json files in the `config_jsons` folder.
1. copy and paste something like this into a json file and save into `config_jsons`:
```
{
  "ProposalAssemblyTime": 250000000,
  "TxPoolSize": 20000,
  "NetworkProtocolVersion": 3.1
}
```