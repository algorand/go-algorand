# Model Mainnet (mmnet) Recipe

> `NOTE`: The name `mmnet` is short for `model mainnet`.

This recipe is meant to be a _best-effort representation_ of mainnet that can be used for testing purposes. In no way is this an exact copy as that would be financially unfeasible. This recipe was first created based on the [scenario2](../scenario2/) recipe with the intention of expanding on the number relays to match mainnet's distribution amongst other improvements.

## Mainnet Relay Parity

The analysis of mainnet relays was done on 2022-07-07, and the total number of relays were ~136 across various regions. This table outlines the distribution more specifically:

| Provider | Region         | Location                | Number of Relays                     |
| -------- | -------------- | ----------------------- | ------------------------------------ |
| AWS      | us-east-1      | Virginia, USA           | 20                                   |
| AWS      | us-east-2      | Ohio, USA               | 20                                   |
| AWS      | us-west-2      | Oregeon, USA            | 10                                   |
| AWS      | ca-central-1   | Canada                  | 6                                    |
| AWS      | eu-west-1      | Ireland                 | 14                                   |
| AWS      | eu-north-1     | Stockholm, Sweden       | 2                                    |
| AWS      | eu-south-1     | Milan, Italy            | 4 (include 2 in Romania and Ukraine) |
| AWS      | ap-east-1      | Hong Kong, China        | 5                                    |
| AWS      | ap-south-1     | Mumbai, India           | 3                                    |
| AWS      | ap-southeast-1 | Singapore               | 12                                   |
| AWS      | ap-southeast-2 | Sydney, Australia       | 4                                    |
| AWS      | ap-northeast-3 | Osaka, Japan            | 15                                   |
| AWS      | me-south-1     | Middle East (Bahrain)   | 2                                    |
| AWS      | af-south-1     | Cape Town, South Africa | 4                                    |
| AWS      | sa-east-1      | Sao Paulo, Brazil       | 4 (include 1 in Rio)                 |

> `NOTE`: These values are represented by a dict in [gen_topology.py](./gen_topology.py)
