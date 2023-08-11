# Custom Recipe
This custom recipe serves as a template for performance testing on algonet (new network on AWS EC2 machines).
With this recipe, you can modify the number of nodes, the type of machines, introduce new parameters to modify the
network's configs and consensus parameters.

N = participating Nodes
NPN = Non-Participating Nodes
R = relays

## Running a Small Network (less than 20 total nodes)
If you are running a network with less than 20 nodes, then you will need to update the default "FractionApply"
1. Modify `configs/node.json` folder
    - `"FractionApply"` in configs/node.json represents the number of nodes to report to telemetry. We don't want to
    overwhelm the telemetry server, so use something small like "0.2" on a large network.
    - For small networks, update this value to "1.0"

## Quick Start - Jenkins
Build and create the recipe.
- (See the first section above for small networks.)
1. Modify the `network_templates/network-tpl.json` file.
2. Select "custom" recipe
3. Specify `network-tpl.json` as the `CUSTOM_NETWORK_TEMPLATE`
- See Modify consensus values (below) to update consensus
- See Update config.json (below) to update config.json

## "Quick" Start - Manual recipe generation (not using Jenkins)
Generate the recipe with the `network-tpl.json` file. You will need netgoal set up in your local environment/path.
- (See the first section above for small networks. See Troubleshooting for netgoal path set up)
1. Make sure you're in the same directory as this README and `cp network_templates/network-tpl.json network-tpl.json`
2. Generate the recipe with a python script:
```
cd go-algorand
python3 test/testdata/deployednettemplates/generate-recipe/generate_network.py -f test/testdata/deployednettemplates/recipes/custom/network_templates/network-tpl.json
```
3. This will create a new set of files in the `generated` folder

## "Quick" Start - Manual recipe generation based off of Network Performance Rules (not using Jenkins)
If you have a network_performance_Rules file in the following format on each line `group1 group2 minrtt`, you can
first generate a template and then generate the recipe. You will need netgoal set up in your local environment/path.
1. Generate the template:
```
cd go-algorand
python3 test/testdata/deployednettemplates/generate-recipe/generate_network_tpl.py --network-rules-file example/npr/five-relays.txt --out test/testdata/deployednettemplates/recipes/custom/network_templates/five-relays.json
```
2. Generate the recipe:
```
cp test/testdata/deployednettemplates/recipes/custom/network_templates/five-relays.json test/testdata/deployednettemplates/recipes/custom/.
python3 test/testdata/deployednettemplates/generate-recipe/generate_network.py -f test/testdata/deployednettemplates/recipes/custom/five-relays.json
```

## Network Templates
With the custom recipe, you can store multiple network templates in the network_templates directory.
Variables to modify:
- `wallets`: Number of wallets used by N
- `nodes`: Number of N
- `ConsensusProtocol`: ConsensusProtocol used for the genesis
- `type`: machine sizes. For `us-east-2`, you can use `m5d.4xl` for most testing. If you need more powerful compute (make sure you get approval because it can get costly) use `c4d.4xl` or `c4d.18xl`
- `count`: Number of machines per type
- `percent`: percentage of machines in group to dedicate to certain types of nodes.

## Modify consensus values
If you add a `consensus.json` file in this folder with the protocol matching the one in `network-tpl.json`, the `consensus.json` will merge with a generated_consensus.json template on Jenkins.
- see `example/consensus.json`

### How is consensus updated in Jenkins?
- In Jenkins, this will be generated via `goal protocols > generated_consensus.json`
- This means that you do not have to provide the whole `consensus.json` in this folder, but only the values you wish to update.
- If you are spinning up a network manually and wish to update a network with `consensus.json`, you must have all of the existing keys for the particular protocol in your consensus.json.

## Update config.json in the network
If you look at the files in the "configs" folder, you will see `node.json`, `nonPartNode.json`, and `relay.json`. These jsons already have a `ConfigJSONOverride` parameter which will generate a config.json in the node's data directories. For testing, if you want to update all three types of nodes at once, you can save a `config.json` file here.
1. copy and paste something like this into a json file and save into `config_jsons`:
```
{
  "ProposalAssemblyTime": 250000000,
  "TxPoolSize": 20000
}
```
This file will merge with the config.json created by `ConfigJSONOverride` and update the parameters if the keys match. This will be applied to participating nodes, nonParticipating Nodes, and relays.

See `example/config_jsons` for an example of what it should look like.

Most parameters that can be modified by config.json can be found in `go-algorand/config/local_defaults.go`.

## Troubleshooting
### Can't find netgoal
- Make sure you have netgoal installed (you can either download it or run through the go-algorand build process)
- Make sure you export GOBIN and GOPATH in your environment and add it to your path.
On a mac, update by editing `~/.zshrc`, add
```
export GOBIN=/Users/{user}/go/bin

export GOPATH=/Users/{user}/go
export PATH=$PATH:/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/Users/ec2-user/Library/Python/3.8/bin:/usr/local/go/bin:$GOBIN:$GOPATH

```
### Machine Type doesn't exist
- Make sure the machine type exists. It uses the regions in the groups and the type to come up with the host template name in `test/testdata/deployednettemplates/hosttemplates/hosttemplates.json`. If it doesn't exist, you will have to add it to that file.

### couldn't initialize the node: unsupported protocol
- check your consensus.json. It may be missing the keys in the future protocol if you are doing this manually. Compare the consensus.json with `goal protocols > generated_consensus.json`
