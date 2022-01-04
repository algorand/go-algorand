import socket
import base64
import tempfile, os

def handshake(conn):
	print("Handshaking...")
	assert conn.recv(8) == b"Algornd1"
	conn.recv(8)
	conn.sendall(b"Algornd1")
	conn.sendall(bytes(8*[0]))
	print("Shook hands.")

def connect():
	print("Connecting...")
	conn = socket.create_connection(("r1.algodev.network", 4160))
	print("Connected.")
	handshake(conn)
	return conn

def getmessage(conn):
	header = conn.recv(6)
	length = header[0] + (header[1]<<8) + (header[2]<<16) + (header[3]<<24)
	tag = header[4:6]
	msg = b""
	while len(msg) < length:
		chunk = conn.recv(length - len(msg))
		if len(chunk) == 0:
			raise "Disconnected"
		msg += chunk
	return (tag, msg)

if __name__ == "__main__":
	c = connect()
	print("(Press Ctrl-C to exit)")
	while True:
		tag, msg = getmessage(c)
		if tag == b"AV":
			print("Heard a vote")
		elif tag == b"TX":
			print("Heard a transaction")
		elif tag == b"BP":
			fd, name = tempfile.mkstemp(prefix="blockproposal-")
			os.write(fd, base64.b64encode(msg))
			print("Heard a block proposal, wrote it to: ", name)
		elif tag == b"RW":
			print("Heard a reward claim")
		elif tag == b"Q?":
			print("Heard an RPC request")
		elif tag == b"A!":
			print("Heard an RPC reply")
		elif tag == b"VB":
			print("Heard a vote bundle")
		else:
			print("Heard a message with tag ", tag, " and length ", len(msg))
