from sys import stdin, stdout
import json

"""
Visualize the state of everyone's ledger and see what gets written to it and when.
Usage: cat ../faucet/temp.log | python showchains.py
Or, to follow along with a running instance: tail -f ../faucet/temp.log | python showchains.py
(noting that writes to temp.log are buffered so the output of tail -f comes in batches and you won't see 100% realtime output)

Output has the round number and one column per player (for the first 20 players) with a (truncated) hash of the latest block in that player's ledger.
When output is to a terminal, hashes are colorized and updated hashes are printed in bold to make to make it easier to see what's going on.

Additionally, if a player doesn't have a block they tried to fetch and is waiting to receive it, print WAIT when they start waiting. With the current implementation it seems anyone who starts waiting never updates their ledger again.
"""
# Terminal escape codes to colorize output
bold = lambda s : "\033[1m"+s+"\033[m" if stdout.isatty() else s
color = lambda c,s : "\033[3"+str(c)+"m"+s+"\033[m" if stdout.isatty() else s

def colorize(digest):
	return color(int(digest,16)%7+1, digest)

PLAYERCOUNT = 20 # number of players to watch, ignore all others
latestblocks = ["0000"] * PLAYERCOUNT
print(" R " + "  ".join(["%4d"%i for i in range(PLAYERCOUNT)]) )
print("== " + "  ".join(["====" for i in range(PLAYERCOUNT)]) )
for line in stdin:
	record = json.loads(line)
	if record["msg"].startswith("wrote block to ledger with digest blk-"):
		player = int(record["player"][-3:])
		if player >= PLAYERCOUNT:
			continue
		newhash = record["msg"][len("wrote block to ledger with digest blk-"):]
		newhash = newhash[:4]
		latestblocks[player] = newhash
		output = [colorize(hash) for hash in latestblocks]
		output[player] = bold(output[player])
	elif record["msg"].startswith("do not own block: wait for fast-forward"):
		player = int(record["player"][-2:])
		if player >= PLAYERCOUNT:
			continue
		output = [colorize(hash) for hash in latestblocks]
		output[player] = bold(color(1,"WAIT"))
	else:
		continue
	print("{round:02} {hashes}".format(round=record["round"], hashes="  ".join(output)))
