# Block Generator

This tool is used for testing Conduit import performance. It does this by generating synthetic blocks which are sent by mocking the Algod REST API endpoints that Conduit uses.

## Benchmark Scenarios

Several scenarios were designed to mimic different block traffic patterns. Scenarios can be used to test the same traffic across multiple versions of software. Each benchmark is run twice. Once with blocks containing 25000 transactions, and once with blocks containing 50000 transactions.

### Organic Traffic

Simulate the current mainnet traffic pattern. Approximately:
* 15% payment transactions
* 10% application transactions
* 75% asset transactions

With current tooling, the app transactions use boxes much more frequently than current mainnet traffic.

### Payment Test (best case TPS)

Blocks are entirely made up of payments. Most payments are transfers between existing accounts.

### Stress Test (worst case TPS)

Blocks are heavily weighted towards creating applications and boxes. This means a lot of data is being written which should translate to lower TPS.

## Scenario Configuration

Block generator uses a YAML config file to describe the composition of each randomly generated block. There are three levels of configuration:

1. Setup
2. Transaction type distribution
3. Transaction type specific configuration

The block generator supports **payment**, **asset**, and **application** transactions. The settings are hopefully, more or less, obvious. Distributions are specified as fractions of 1.0, and the sum of all options must add up to ~1.0.

Here is an example which uses all of the current options. Notice that the synthetic blocks are not required to follow algod limits, in this case the block size is specified as 99,999:

```yml
name: "Mixed (99,999)"
genesis_accounts: 10000
genesis_account_balance: 1000000000000
tx_per_block: 99999

# transaction distribution
tx_pay_fraction: 0.5
tx_asset_fraction: 0.3
tx_app_fraction: 0.2

# payment config
pay_acct_create_fraction: 0.02
pay_xfer_fraction: 0.98

# asset config
asset_create_fraction: 0.001
asset_optin_fraction: 0.1
asset_close_fraction: 0.05
asset_xfer_fraction: 0.849
asset_delete_fraction: 0

# app choice config
app_swap_fraction: 0.5
app_boxes_fraction: 0.5

# app_swap config
app_swap_create_fraction: 0.001
app_swap_update_fraction: 0.001
app_swap_delete_fraction: 0
app_swap_optin_fraction: 0.1
app_swap_call_fraction: 0.98
app_swap_close_fraction: 0.005
app_swap_clear_fraction: 0.003

# app_boxes config
app_boxes_create_fraction: 0.001
app_boxes_update_fraction: 0.001
app_boxes_delete_fraction: 0
app_boxes_optin_fraction: 0.1
app_boxes_call_fraction: 0.98
app_boxes_close_fraction: 0.005
app_boxes_clear_fraction: 0.003
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

The runner mode is well suited for running the same set of tests consistently across many scenarios and for different releases. The runner mode automates this process by starting the **daemon** with many different configurations, managing a postgres database, and running a separate Conduit process configured to use them.

The results of the testing are written to the directory specified by the **--report-directory** option, and include many different metrics. In addition to the report, the Conduit log is written to this directory. The files are named according to the scenario file, and end in "report" or "log".

Here is an example report from running with a test duration of "1h":

```json
test_duration_seconds:3600
test_duration_actual_seconds:3600.056457
transaction_pay_total:30024226
transaction_pay_create_total:614242
early_average_import_time_sec:2.13
early_cumulative_import_time_sec:1083.26
early_average_imported_tx_per_block:99999.00
early_cumulative_imported_tx_per_block:10179491
early_average_block_upload_time_sec:NaN
early_cumulative_block_upload_time_sec:0.00
early_average_postgres_eval_time_sec:0.33
early_cumulative_postgres_eval_time_sec:167.41
early_imported_round:509
early_overall_transactions_per_second:9397.09
early_uptime_seconds:3600.06
final_average_import_time_sec:2.35
final_cumulative_import_time_sec:3602.62
final_average_imported_tx_per_block:99999.00
final_cumulative_imported_tx_per_block:30598470
final_average_block_upload_time_sec:NaN
final_cumulative_block_upload_time_sec:0.00
final_average_postgres_eval_time_sec:0.33
final_cumulative_postgres_eval_time_sec:507.38
final_imported_round:1530
final_overall_transactions_per_second:8493.40
final_uptime_seconds:3600.06
```

Here is the help output for **runner**:

```bash
~$ ./block-generator runner -h
Run an automated test suite using the block-generator daemon and a provided conduit binary. Results are captured to a specified output directory.

Usage:
  block-generator runner [flags]

Flags:
  -i, --conduit-binary string               Path to conduit binary.
  -l, --conduit-log-level string            LogLevel to use when starting Conduit. [panic, fatal, error, warn, info, debug, trace] (default "error")
      --cpuprofile string                   Path where Conduit writes its CPU profile.
  -f, --genesis-file string                 file path to the genesis associated with the db snapshot
  -h, --help                                help for runner
  -k, --keep-data-dir                       If set the validator will not delete the data directory after tests complete.
  -p, --metrics-port uint                   Port to start the metrics server at. (default 9999)
  -c, --postgres-connection-string string   Postgres connection string.
  -r, --report-directory string             Location to place test reports.
      --reset-db                            If set database will be deleted before running tests.
      --reset-report-dir                    If set any existing report directory will be deleted before running tests.
  -s, --scenario string                     Directory containing scenarios, or specific scenario file.
  -d, --test-duration duration              Duration to use for each scenario. (default 5m0s)
      --validate                            If set the validator will run after test-duration has elapsed to verify data is correct. An extra line in each report indicates validator success or failure.
  -v, --verbose                             If set the runner will print debugging information from the generator and ledger.
 ```

## Example Run using Conduit and Postgres in **bash** via `run_runner.sh`

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

If all goes well, the run will generate a directory `../../tmp/OUTPUT_RUN_RUNNER_TEST`
and in that directory you can see the statistics of the run in `scenario.report`.
