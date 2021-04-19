# Heap Watch

Tools for checking if algod has memory leaks.

Run a local private network of three nodes and two pingpongs.

Periodically sample pprof memory profiles.

Watch memory usage from `ps` and write to a CSV file for each algod.

# Usage

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