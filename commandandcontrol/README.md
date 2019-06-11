# Command and Control Center

Command and Control Service and distributed Agents are designed to help test the Algorand blockchain network.  Through a central service node, agents deployed to Algorand host nodes can be controlled and monitored by clients.
The initial version support launching the ping pong utility on target hosts and nodes.

```
                             CC Agent   ->  Ping Pong
                          /   
  CC Client -> CC Service  
                          \  
                             CC Agent   ->  Ping Pong 
```

## Starting the CC Service
The following command can be used to start the CC Service.  Run this from the machine that will host the CC Service.
```Shell
cc_service 
    -addr <host>:<port> 
```

One or more data dirs can be specified.

## Starting the CC Agent
The following `cc_agent` command will start the CC Agent. Run this from each of the machines that host the Algod Instances. Specify the data dir for each of the Algod Instances to be controlled.
```Shell
cc_agent 
    -service-addr <host>:<port> 
    -hostname <agent_hostname> 
    -bindir <bin_dir> 
    -tempdir <temp_dir>
    -d <node_dir1> 
    -d <node_dir2> ...
```

The flag -bindir specifies where the algod binaries are located.

## Using the Client to Control the Agents  
The following cc_agent command will send an action to the CC Service which will then dispatch it to each of the agents.
```Shell
cc_client 
    -target <host>:<port> 
    -component (pingpong) 
    -action (start|stop)  
    -options <options_filepath>
```

## Example Scripts for running CC Service, Agent, and Client
The following `example/cc_example.sh` script will launch local instance of the CC Service and CC Agent.

#### cc_example.sh
```Shell
#!/usr/bin/env bash
set -v
set -x

CC_SERVICE_HOST="localhost:8080"
BIN_DIR=${GOPATH}/bin/
TEMP_DIR=${TMPDIR}
SLEEP_TIME=5

# Start the cc_service
cc_service \
    -addr ${CC_SERVICE_HOST} &

sleep ${SLEEP_TIME}

# Start the cc_agent for 2 local algod instances
cc_agent \
    -service-addr ${CC_SERVICE_HOST} \
    -hostname Host1 \
    -bindir ${BIN_DIR} \
    -tempdir ${TEMP_DIR} \
    -d /tmp/test3/root/Node \
    -d /tmp/test3/root/Primary/ &
```

#### cc_example_client.sh
Then use the `example/cc_example_client.sh` to start pingpong on the agent, wait 30 seconds, then change pingpong params, wait 30 seconds, then stop pingpong.

```Shell
#!/usr/bin/env bash
set -v
set -x

CC_SERVICE_HOST=localhost:8080
SLEEP_TIME=10

# Start ping pong running on all known host and instances with configuration from pingpong1.json
cc_client \
    -service-addr ${CC_SERVICE_HOST} \
    -target *:* \
    -component pingpong \
    -action start \
    -options ./pingpong1.json

# Sleep 
sleep ${SLEEP_TIME}

# Restart ping pong running on all host Host1 and node Primary with configuration from pingpong2.json
cc_client \
    -service-addr ${CC_SERVICE_HOST} \
    -target Host1:Primary \
    -component pingpong \
    -action start \
    -options ./pingpong2.json

# Sleep 
sleep ${SLEEP_TIME}

# Stop ping pong on all known instances and nodes
cc_client \
    -service-addr ${CC_SERVICE_HOST} \
    -target *:* \
    -component pingpong \
    -action stop \
    -options ./pingpong1.json

```
#### pingpong1.json
Example `pingpong1.json` input options to pingpong 

```Json
{
  "SrcAccount": "",
  "DelayBetweenTxn": 100,
  "RandomizeFee": false,
  "RandomizeAmt": false,
  "RandomizeDst": false,
  "MaxFee": 5,
  "MaxAmt": 20,
  "NumPartAccounts": 10,
  "RunTime": 10000,
  "RestTime": 10000,
  "RefreshTime": 10000,
  "MinAccountFunds": 100000
}
```
