--local test = require("test")
--
--print(test.state)
--test.start()
--print(test.state)

--local algod = require("algodModule")
--print("Getting status, node not started.")
--algod.status()
--print("Starting node.")
--algod.start()
--print("Getting status, node started.")
--algod.status()
--print("Stopping node.")
--algod.stop()
--print("Getting status, node stopped.")
--algod.status()
--


--local algod = require("algodModule")
--print("Starting node.")
--algod.start()
--print("Getting status, node started.")
--algod.status()
--print("Stopping node.")
--algod.stop()

local node = algod.new("/home/will/go/bin", "/home/will/nodes/testdir")
node:start()
node:status()
node:stop()
