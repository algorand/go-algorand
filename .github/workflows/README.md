# Github Actions Workflows

## Benchmarking Performance Tests
`benchmarks.yml` contains a workflow to check for any performance regressions or
improvements in benchmark tests. 

It uses
[github-action-benchmark](https://github.com/benchmark-action/github-action-benchmark)
to check performance diffs between a PR and the `master` branch, comments if it
there is a regression past a certain threshold (default: `200%`), and generates
a performance diff JSON between consecutive commits in the `master` branch in
the `gh-pages` branch (the JSON is visualized into a graph that can be seen at:
https://algorand.github.io/go-algorand/dev/bench/)

Currently, the workflow runs the `BenchmarkUintMath` in the `Run benchmark`
step. Additional benchmarks can be run using the `-bench` flag. 
