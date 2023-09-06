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

Here is an example which uses all of the current options. Notice that the synthetic blocks are not required to follow algod limits, and that in this case the block size is specified as 99,999:

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
  -v, --verbose         If set the daemon will print debugging information from the generator and ledger.
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

We recommend printing out the help information for the **runner**:

```bash
~$ ./block-generator runner -h
Run an automated test suite using the block-generator daemon and a provided conduit binary. Results are captured to a specified output directory.

Usage:
  block-generator runner [flags]

... etc ...
```

## Example Runs using Conduit

A typical **runner** scenario involves:

* a [scenario configuration](#scenario-configuration) file, e.g. [config.asset.xfer.yml](./scenarios/config.asset.xfer.yml) or for the example below [test_scenario.yml](./generator/test_scenario.yml)
* access to a `conduit` binary to query the block generator's mock Algod endpoint and ingest the synthetic blocks (below it's assumed to be set in the `CONDUIT_BINARY` environment variable)
* a datastore -such as a postgres database- to collect `conduit`'s output
* a `conduit` config file to define its import/export behavior

### Sample Run with Postgres

First you'll need to get a `conduit` binary. For example you can follow the [developer portal's instructions](https://developer.algorand.org/docs/get-details/conduit/GettingStarted/#installation) or run `go build .` inside of the directory `cmd/conduit` after downloading the `conduit` repo.

Run `make install` from the `go-algorand` root, this should add `block-generator` to your path.

Start a postgres container using `scripts/run_postgres.sh`. This starts a container on port 15432 a database named generator_db and a user with credentials algorand/algorand.

Now run `block-generator runner` to run the test:

```sh
block-generator runner \
  --conduit-binary "$CONDUIT_BINARY" \
  --report-directory reports \
  --test-duration 30s \
  --conduit-log-level trace \
  --postgres-connection-string "host=localhost user=algorand password=algorand dbname=generator_db port=15432 sslmode=disable" \
  --scenario generator/test_scenario.yml \
  --reset-db
```

### Scenario Report

If all goes well, the run will generate a directory named `reports`
in the same directory in which the command was run.
In that directory you can see the statistics of the run in the file ending with `.report`.

The `block-generator runner` subcommand has a number of options to configure behavior.

## Sample Run with the File Exporter

It's possible to save the generated blocks to the file system.
This enables running benchmarks and stress tests at a later time and without
needing a live block generator. The setup is very similar to the previous Postgres example. The main change compared to the previous is to _**specify a different conduit configuration**_ template.

The `block-generator runner` command in this case would look like:

```sh
block-generator runner \
  --conduit-binary "$CONDUIT_BINARY" \
  --report-directory reports \
  --test-duration 30s \
  --conduit-log-level trace \
  --template file-exporter \
  --keep-data-dir \
  --scenario generator/test_scenario.yml
```

### Generated Blocks

If all goes well, the run will generate a directory named `reports`
in the same directory in which the command was run.
In addition to the statistical report and run logs,
there will be a directory ending with `_data` - this is conduit's
data directory (which is saved thanks to the `--keep-data-dir` flag).
In that directory under `exporter_file_writer/`
the generated blocks and a genesis file will be saved.

## Scenario Distribution - Configuration vs. Reality

This section follows up on the [Scenario Configuration](#scenario-configuration) section to detail how each kind of transaction is actually chosen.
Note that -especially for early rounds- there is no guarantee that the
percentages of transaction types will resemble the configured distribution.

For example consider the [Organic 25,000](scenarios/benchmarks/organic.25000.yml) scenario:

```yml
name: "Organic (25000)"
genesis_accounts: 10000
genesis_account_balance: 1000000000000
tx_per_block: 25000

# transaction distribution
tx_pay_fraction: 0.05
tx_asset_fraction: 0.75
tx_app_fraction: 0.20

# payment config
pay_acct_create_fraction: 0.10
pay_xfer_fraction: 0.90

# asset config
asset_create_fraction: 0.001
asset_optin_fraction: 0.1
asset_close_fraction: 0.05
asset_xfer_fraction: 0.849
asset_delete_fraction: 0

# app kind config
app_boxes_fraction: 1.0
app_swap_fraction: 0.0

# app boxes config
app_boxes_create_fraction: 0.01
app_boxes_optin_fraction: 0.1
app_boxes_call_fraction: 0.89
```

We are _actually_ asking the generator for the following distribution:

* `pay_acct_create_fraction = 0.005 (= 0.05 * 0.10)`
* `pay_xfer_fraction =  0.045 (= 0.05 * 0.90)`
* `asset_create_fraction = 0.00075 (= 0.75 * 0.001)`
* `asset_optin_fraction = 0.075 (= 0.75 * 0.1)`
* `asset_close_fraction = 0.0375 (= 0.75 * 0.05)`
* `asset_xfer_fraction = 0.63675 (= 0.75 * 0.849)`
* `asset_delete_fraction = 0`
* `app_boxes_create_fraction = 0.002 (= 0.20 * 1.0 * 0.01)`
* `app_boxes_optin_fraction = 0.02 (= 0.20 * 1.0 * 0.1)`
* `app_boxes_call_fraction = 0.178 (= 0.20 * 1.0 * 0.89)`

The block generator randomly chooses

1. the transaction type (pay, asset, or app) according to the `transaction distribution`
2. based on the type:

   a. for payments and assets, the specific type based on the `payment config` and `asset config` distributions

   b. for apps, the app kind (boxes or swaps) based on the `app kind config` distribution

3. For _apps only_: the specific app call based on the `app boxes config` (and perhaps in the future `app swap config`)

As each of the steps above is itself random, we only expect _approximate matching_ to the configured distribution.

Furthermore, for certain asset and app transactions there may be a substitution that occurs based on the type. In particular:

* for **assets**:
  * when a requested asset txn is **create**, it is never substituted
  * when there are no assets, an **asset create** is always substituted
  * when a requested asset txn is **delete** but the creator doesn't hold all asset funds, an **asset close** is substitued (which itself may be substituted using the **close** rule below)
  * when a requested asset txn is **opt in** but all accounts are already opted in, an  **asset close** is substituted (which itself may be substituted using the **close** rule below)
  * when a requested asset txn is **transfer** but there is only one account holding it,  an **asset opt in** is substituted (which itself may be substituted using the **asset opt in** rule above)
  * when a requested asset txn is **close** but there is only one account holding it, an **asset opt in** is substituted (which itself may be substituted using the **asset opt in** rule above)
* for **apps**:
  * when a requested app txn is **create**, it is never substituted
  * when a requested app txn is **opt in**:
    * if the sender is already opted in, an **app call** is substituted
    * otherwise, if the sender's opt-in is pending for the round, an **app create** is substituted
  * when a requested app txn is **call** but it's not opted into, an **app opt in** is attempted to be substituted (but this may itself be substituted for given the **app opt in** rule above)

Over time, we expect the state of the generator to stabilize so that very few substitutions occur. However, especially for the first few rounds, there may be drastic differences between the config distribution and observed percentages.

In particular:

* for Round 1, all app transactions are replaced by **app create**
* for Round 2, all **app call** transactions are replaced by **app opt in**

Therefore, for scenarios involving a variety of app transactions, only for Round 3 and higher do we expect to see distributions comparable to those configured.

> NOTE: Even in the steady state, we still expect fundamental deviations 
> from the configured distributions in the cases of apps. This is because
> an app call may have associated group and inner transactions. For example,
> if an app call requires 1 sibling asset call in its group and has 2 inner payments, this single app call will generate 1 additional asset txn and 2 payment txns.
