# Block Generator

This tool is used for testing Conduit import performance. It does this by generating synthetic blocks which are sent by mocking the Algod REST API endpoints that Conduit uses.

## Scenario Configuration

Block generator uses a YAML config file to describe the composition of each randomly generated block. There are three levels of configuration:
1. Setup
2. Transaction type distribution
3. Transaction type specific configuration

At the time of writing, the block generator supports **payment** and **asset** transactions. The settings are hopefully, more or less, obvious. Distributions are specified as fractions of 1.0, and the sum of all options must add up to 1.0.

Here is an example which uses all of the current options. Notice that the synthetic blocks are not required to follow algod limits, in this case the block size is specified as 19999:
```
name: "Mixed (19,999)"
genesis_accounts: 10000
genesis_account_balance: 1000000000000
tx_per_block: 19999

# transaction distribution
tx_pay_fraction: 0.3
tx_asset_fraction: 0.7

# payment config
pay_acct_create_fraction: 0.02
pay_xfer_fraction: 0.98

# asset config
asset_create_fraction: 0.001
asset_optin_fraction: 0.1
asset_close_fraction: 0.05
asset_xfer_fraction: 0.849
asset_delete_fraction: 0
```

## Modes

The block generator can run in one of two _modes_:
1. standalone **daemon**
2. test suite **runner**

### daemon

In standalone daemon mode, a block-generator process starts and exposes the mock algod endpoints for **/genesis** and **/v2/blocks/{block}**. If you choose to query them manually, it only supports fetching blocks sequentially. This is due to the fact that it generates a pseudorandom stream of transactions and after each random transaction the state increments to the next.

Here is the help output for **daemon**: 
```bash
~$ ./block-generator daemon -h
Start the generator daemon in standalone mode.

Usage:
  block-generator daemon [flags]

Flags:
  -c, --config string   Specify the block configuration yaml file.
  -h, --help            help for daemon
  -p, --port uint       Port to start the server at. (default 4010)
```
  
### runner

The runner mode is well suited for runing the same set of tests consistently across many scenarios and for different releases. The runner mode automates this process by starting the **daemon** with many different configurations, managing a postgres database, and running a separate Conduit process configured to use them.

The results of the testing are written to the directory specified by the **--report-directory** option, and include many different metrics. In addition to the report, the Conduit log is written to this directory. The files are named according to the scenario file, and end in "report" or "log".

Here is an example report from running with a test duration of "1h":
```
test_duration_seconds:30
test_duration_actual_seconds:30.018076
transaction_asset_close_total:472
transaction_asset_create_total:711
transaction_asset_optin_total:1230
transaction_asset_xfer_total:468
transaction_pay_total:1457
transaction_pay_create_total:1472
early_average_import_time_sec:0.05
early_cumulative_import_time_sec:11.05
early_average_imported_tx_per_block:10.00
early_cumulative_imported_tx_per_block:2390
early_imported_round:239
early_overall_transactions_per_second:216.26
early_uptime_seconds:30.02
final_average_import_time_sec:0.05
final_cumulative_import_time_sec:31.36
final_average_imported_tx_per_block:10.00
final_cumulative_imported_tx_per_block:5800
final_imported_round:580
final_overall_transactions_per_second:184.93
final_uptime_seconds:30.02
```

Here is the help output for **runner**:
```bash
~$ ./block-generator runner -h
Run an automated test suite using the block-generator daemon and a provided conduit binary. Results are captured to a specified output directory.

Usage:
  block-generator runner [flags]

Flags:
  -i, --conduit-binary string               Path to conduit binary.
      --cpuprofile string                   Path where conduit writes its CPU profile.
  -h, --help                                help for runner
  -k, --keep-data-dir                       If set the validator will not delete the data directory after tests complete.
  -l, --log-level string                    LogLevel to use when starting conduit. [panic, fatal, error, warn, info, debug, trace] (default "error")
  -p, --metrics-port uint                   Port to start the metrics server at. (default 9999)
  -c, --postgres-connection-string string   Postgres connection string.
  -r, --report-directory string             Location to place test reports.
      --reset                               If set any existing report directory will be deleted before running tests.
  -s, --scenario string                     Directory containing scenarios, or specific scenario file.
  -d, --test-duration duration              Duration to use for each scenario. (default 5m0s)
      --validate                            If set the validator will run after test-duration has elapsed to verify data is correct. An extra line in each report indicates validator success or failure.
```

## Example Scenario Run using Conduit and Postgres - `run_runner.sh`

A typical **runner** scenario involves:
* a [scenario configuration](#scenario-configuration) file, e.g. [test_config.yml](./test_config.yml)
* access to a `conduit` binary to query the block generator's mock Algod endpoint and ingest the synthetic blocks
* a datastore -such as a postgres database- to collect `conduit`'s output
* a `conduit` config file to define its import/export behavior

`run_runner.sh` makes the following choices for the previous bullet points:
* it can accept any scenario as its second argument, but defaults to [test_config.yml](./test_config.yml) when this isn't provided (this is a scenario with a lifetime of ~30 seconds)
* knows how to import through a mock Algod running on port 11112 (which is the port the runner avails)
* sets up a dockerized postgres database to receive conduit's output
* configures `conduit` for these specs using [this config template](./runner/template/conduit.yml.tmpl)

### Sample Run

First you'll need to get a `conduit` binary. For example you can follow the [developer portal's instructions](https://developer.algorand.org/docs/get-details/conduit/GettingStarted/#installation) or run `go build .` inside of the directory `cmd/conduit` after downloading the `conduit` repo.

Assume you've navigated to the `tools/block-generator` directory of 
the `go-algorand` repo, and:
* saved the conduit binary to `tools/block-generator/conduit`
* created a block generator scenario config at `tools/block-generator/scenario.yml`

Then you can execute the following command to run the scenario:
```sh
./run_runner.sh ./conduit scenario.yml 
```

### Scenario Report

If all goes well, the run will generate a directory `tools/block-generator/OUTPUT_RUN_RUNNER_TEST` and in that directory you can see the statistics 
of the run in `scenario.report`.

