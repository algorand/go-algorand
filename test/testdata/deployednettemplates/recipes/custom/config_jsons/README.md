# Updating config.json in the network
If you look at the files in the "configs" folder, you will see `node.json`, `nonPartNode.json`, and `relay.json`. These jsons already have a `ConfigJSONOverride` parameter which will generate a config.json in the node's data directories. For testing, if you want to update all three types of nodes at once, you can save a `config.json` file here.
1. copy and paste something like this into a json file and save into `config_jsons`:
```
{
  "ProposalAssemblyTime": 250000000,
  "TxPoolSize": 20000
}
```
This file will merge with the config.json created by `ConfigJSONOverride` and update the parameters if the keys match. This will be applied to participating nodes, nonParticipating Nodes, and relays.

## Example
See `example/config_jsons` for an example of what it should look like.

## Notes
Most examples of what can be modified by config.json can be found in `go-algorand/config/local_defaults.go`.