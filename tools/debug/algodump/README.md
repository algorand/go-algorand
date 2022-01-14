# Algodump

This is a tool for monitoring the messages sent over Algorand's network
protocol.

By default, the tool connects to a network in the same way that `algod`
does, using SRV records and connecting to 4 relays from that list.

You can change the network by using the `-network` flag; you will likely
also need to specify the correct `-genesis` flag for that network (e.g.,
`-network testnet -genesis testnet-v1.0`).

You can also instruct `algodump` to connect to just one server.  This may
be useful if you want to debug a specific server, or if you want to avoid
seeing the same message received from multiple relays.  To do this, use
the `-server` flag (e.g., `-server r-po.algorand-mainnet.network:4160`).

By default, `algodump` will print all messages received.  If you want to
print just some message types, use the `-tags` flag (e.g., `-tags TX`
to only see transactions, or `-tags AV` to see votes).  The full list
of tag types is in `protocol/tags.go`.

Although `algodump` will print all message types, it might not know how
to meaningfully display the contents of some message types.  If you
are trying to monitor messages that `algodump` doesn't know how to
pretty-print, you will see just where the message came from, the message
type, and the length of its payload.  You can add more formatting code
to print the contents of other messages by adding more cases to the
`switch` statement in `dumpHandler.Handle()` in `main.go`.

Finally, `algodump` by default truncates the addresses it prints (e.g.,
the sender of a transaction or the address of a voter); you can use the
`-long` flag to print full-length addresses.
