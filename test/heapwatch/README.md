# Heap Watch

Collect RAM, bandwidth, and other stats over the course of a test cluster run.

Produce reports and plots from data.

## Scripts

* heapWatch.py
  * collect data from algod
  * heap profiling, /metrics, cpu profiling, block headers, goroutine profile
  * capture from local algod by data dir or cluster from terraform-inventory.host
  * convert profiles to svg or other reports

* block_history.py
  * Capture block headers every round from a running `algod`

* block_history_relays.py
  * Capture block headers every round from one or more running `algod`
  * Talk to a set of relays found in a terraform-inventory.host file.

* block_history_plot.py
  * Plot the output of test/heapwatch/{block_history.py,block_history_relays.py}

* client_ram_report.py
  * Process heap profiles (*.heap) collected from heapWatch.py
  * Create a report on `algod` RAM usage

* plot_crr_csv.py
  * Plot the output of test/heapwatch/client_ram_report.py --csv

* metrics_delta.py
  * Process /metrics data captured by heapWatch.py
  * Generate text report on bandwidth in and out of relays/PN/NPN
  * optionally plot txn pool fullness

* start.sh stop.sh
  * Run a local private network of three nodes and two pingpongs.
  * Periodically sample pprof memory profiles.
  * Watch memory usage from `ps` and write to a CSV file for each algod.

* bwstart.sh stop.sh
  * Run a local private network of 3 relays and 8 leafs
  * Run 40 TPS of payment txns through it.
  * Record metrics for bandwidth analysis.

* runNodeHost.py nodeHostTarget.py
  * run new ec2 host with npn and pn algod on it pointed at one relay (no DNS needed)


## heapWatch.py local cluster usage

To start:

```sh
bash test/heapwatch/start.sh /tmp/todaysTest
```

To stop:

```sh
bash test/heapwatch/stop.sh /tmp/todaysTest
```

Results:

Snapshot usage plots and inter-snapshot delta plots.

```sh
ls /tmp/todaysTest/heaps/*.svg
```

The raw files for analysis with `go tool pprof`

```sh
ls /tmp/todaysTest/heaps/*.heap
```

CSV files of memory usage according to `ps`:

```sh
ls /tmp/todaysTest/heaps/*.csv
```