# PingPong usage

In order to run PingPong locally, an Algorand network must be available. It's
sufficient to set it up using `goal network create -r {data directory} -t {network template json file}`.
The `-r` tells `goal` where to set up a directory for the local network data and `-t` describes the network
to be created.

Example network template:

```{
    "Genesis": {
        "NetworkName": "tbd",
        "ConsensusProtocol": "future",
        "LastPartKeyRound": 3000,
        "Wallets": [
            {
                "Name": "Wallet1",
                "Stake": 50,
                "Online": true
            },
            {
                "Name": "Wallet2",
                "Stake": 50,
                "Online": true
            }
        ]
    },
    "Nodes": [
        {
            "Name": "Primary",
            "IsRelay": true,
            "Wallets": [
                { "Name": "Wallet1",
                  "ParticipationOnly": false }
            ]
        },
        {
            "Name": "Node",
            "Wallets": [
                { "Name": "Wallet2",
                  "ParticipationOnly": false }
            ]
        }
    ]
}
```

Other examples can be found in `test/testdata/nettemplates`. This will create the network data directory,
which will contain a node data directory at `{network data directory}/Primary`. The node data directory will
be used in the `pingpong` command for the `-d` argument.

Once the network is successfully created, run `goal network start -r {data directory}`.

Now you should be able to run PingPong on your local machine.

Example:
`pingpong run -d {node data directory} --numapp 10 --numboxread 4 --tps 200 --refresh 1800 --numaccounts 500 --duration 120`

Note: if you don't set the `--duration` parameter the test will continue running until it's stopped externally.

`pingpong run -h` will describe each CLI parameter.