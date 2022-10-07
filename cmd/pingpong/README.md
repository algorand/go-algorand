# PingPong usage

Example:
`pingpong run -d {node data directory} --numapp 10 --numboxread 4 --tps 200 --refresh 1800 --numaccounts 500 --duration 120`

Note: if you don't set the `--duration` parameter the test will continue running until it's stopped externally.

`pingpong run -h` will describe each CLI parameter.