# Misc Tools

Collection of various tools that are useful enough to save, but niche enough that they don't belong in goal.


### convertAddress

It's sometimes useful to convert addresses between the public "Stripped Base32 /w checksum" format, and the Base64 encoded 32 byte format. This tool converts the two formats.

There is only very minor error checking, results from this tool to not ensure valid inputs.

```sh
# Address to Base64 encoded bytes.
~$ go run convertAddress.go -addr E33YVTQNYH2BHI33OCYL7JQQSEMXD4EN74CZQ37FC6EZFHIBCNWOWXIZ5M
JveKzg3B9BOje3Cwv6YQkRlx8I3/BZhv5ReJkp0BE2w=

# Base64 encoded bytes to Address.
~$ go run convertAddress.go -addr JveKzg3B9BOje3Cwv6YQkRlx8I3/BZhv5ReJkp0BE2w=
E33YVTQNYH2BHI33OCYL7JQQSEMXD4EN74CZQ37FC6EZFHIBCNWOWXIZ5M

```

If you want to run it more than once, it may be useful to compile a binary rather than building with `go run` on each invokation:
```sh
# Build binary.
~$ go build convertAddress.go

# Use binary.
~$ ./convertAddress -addr JveKzg3B9BOje3Cwv6YQkRlx8I3/BZhv5ReJkp0BE2w=
E33YVTQNYH2BHI33OCYL7JQQSEMXD4EN74CZQ37FC6EZFHIBCNWOWXIZ5M
```
