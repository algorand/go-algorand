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
https://algorand.github.io/go-algorand/dev/bench/).

### Adding benchmark tests
Add run steps or extend existing benchmark invocations in the `Run benchmark`
step. Additional benchmarks can be run using the `-bench` flag. Since there's
few benchmarks run by the workflow, there are _no_ formal groupings and/or
naming conventions.

### CI Variance
There may be some variance between runs because github actions might spin up a
different machine each time (e.g. Intel Xeon 8370C vs 8171M; the latter might
run benchmarks slightly slower). Empirically, the variance seems to be 10~30%
for the most part. Due to this environment variance, the workflow is most
suitable for finding _large_ performance degradations.
