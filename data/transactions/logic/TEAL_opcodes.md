# Opcodes

Ops have a 'cost' of 1 unless otherwise specified.


## err

- Opcode: 0x00 
- Pops: _None_
- Pushes: _None_
- Error. Panic immediately. This is primarily a fencepost against accidental zero bytes getting compiled into programs.

## sha256

- Opcode: 0x01 
- Pops: *... stack*, []byte
- Pushes: []byte
- SHA256 hash of value, yields [32]byte
- **Cost**: 7

## keccak256

- Opcode: 0x02 
- Pops: *... stack*, []byte
- Pushes: []byte
- Keccak256 hash of value, yields [32]byte
- **Cost**: 26

## sha512_256

- Opcode: 0x03 
- Pops: *... stack*, []byte
- Pushes: []byte
- SHA512_256 hash of value, yields [32]byte
- **Cost**: 9

## ed25519verify

- Opcode: 0x04 
- Pops: *... stack*, {[]byte A}, {[]byte B}, {[]byte C}
- Pushes: uint64
- for (data, signature, pubkey) verify the signature of ("ProgData" || program_hash || data) against the pubkey => {0 or 1}
- **Cost**: 1900

## +

- Opcode: 0x08 
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64
- A plus B. Panic on overflow.

## -

- Opcode: 0x09 
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64
- A minus B. Panic if B > A.

## /

- Opcode: 0x0a 
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64
- A divided by B. Panic if B == 0.

## *

- Opcode: 0x0b 
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64
- A times B. Panic on overflow.

It is worth noting that there are 10,000,000,000,000,000 micro-Algos in the total supply, or a bit less than 2^54. When doing rational math, e.g. (A * (N/D)) as ((A * N) / D) one should limit the numerator to less than 2^10 to be completely sure there won't be overflow.

## <

- Opcode: 0x0c 
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64
- A less than B => {0 or 1}

## >

- Opcode: 0x0d 
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64
- A greater than B => {0 or 1}

## <=

- Opcode: 0x0e 
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64
- A less than or equal to B => {0 or 1}

## >=

- Opcode: 0x0f 
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64
- A greater than or equal to B => {0 or 1}

## &&

- Opcode: 0x10 
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64
- A is not zero and B is not zero => {0 or 1}

## ||

- Opcode: 0x11 
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64
- A is not zero or B is not zero => {0 or 1}

## ==

- Opcode: 0x12 
- Pops: *... stack*, {any A}, {any B}
- Pushes: uint64
- A is equal to B => {0 or 1}

## !=

- Opcode: 0x13 
- Pops: *... stack*, {any A}, {any B}
- Pushes: uint64
- A is not equal to B => {0 or 1}

## !

- Opcode: 0x14 
- Pops: *... stack*, uint64
- Pushes: uint64
- X == 0 yields 1; else 0

## len

- Opcode: 0x15 
- Pops: *... stack*, []byte
- Pushes: uint64
- yields length of byte value

## itob

- Opcode: 0x16 
- Pops: *... stack*, uint64
- Pushes: []byte
- converts uint64 to big endian bytes

## btoi

- Opcode: 0x17 
- Pops: *... stack*, []byte
- Pushes: uint64
- converts bytes as big endian to uint64

`btoi` panics if the input is longer than 8 bytes

## %

- Opcode: 0x18 
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64
- A modulo B. Panic if B == 0.

## |

- Opcode: 0x19 
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64
- A bitwise-or B

## &

- Opcode: 0x1a 
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64
- A bitwise-and B

## ^

- Opcode: 0x1b 
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64
- A bitwise-xor B

## ~

- Opcode: 0x1c 
- Pops: *... stack*, uint64
- Pushes: uint64
- bitwise invert value

## mulw

- Opcode: 0x1d 
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64, uint64
- A times B out to 128-bit long result as low (top) and high uint64 values on the stack

## intcblock

- Opcode: 0x20 {varuint length} [{varuint value}, ...]
- Pops: _None_
- Pushes: _None_
- load block of uint64 constants

`intcblock` loads following program bytes into an array of integer constants in the evaluator. These integer constants can be referred to by `intc` and `intc_*` which will push the value onto the stack.

## intc

- Opcode: 0x21 {uint8 int constant index}
- Pops: _None_
- Pushes: uint64
- push value from uint64 constants to stack by index into constants

## intc_0

- Opcode: 0x22 
- Pops: _None_
- Pushes: uint64
- push uint64 constant 0 to stack

## intc_1

- Opcode: 0x23 
- Pops: _None_
- Pushes: uint64
- push uint64 constant 1 to stack

## intc_2

- Opcode: 0x24 
- Pops: _None_
- Pushes: uint64
- push uint64 constant 2 to stack

## intc_3

- Opcode: 0x25 
- Pops: _None_
- Pushes: uint64
- push uint64 constant 3 to stack

## bytecblock

- Opcode: 0x26 {varuint length} [({varuint value length} bytes), ...]
- Pops: _None_
- Pushes: _None_
- load block of byte-array constants

`bytecblock` loads the following program bytes into an array of byte string constants in the evaluator. These constants can be referred to by `bytec` and `bytec_*` which will push the value onto the stack.

## bytec

- Opcode: 0x27 {uint8 byte constant index}
- Pops: _None_
- Pushes: []byte
- push bytes constant to stack by index into constants

## bytec_0

- Opcode: 0x28 
- Pops: _None_
- Pushes: []byte
- push bytes constant 0 to stack

## bytec_1

- Opcode: 0x29 
- Pops: _None_
- Pushes: []byte
- push bytes constant 1 to stack

## bytec_2

- Opcode: 0x2a 
- Pops: _None_
- Pushes: []byte
- push bytes constant 2 to stack

## bytec_3

- Opcode: 0x2b 
- Pops: _None_
- Pushes: []byte
- push bytes constant 3 to stack

## arg

- Opcode: 0x2c {uint8 arg index N}
- Pops: _None_
- Pushes: []byte
- push LogicSig.Args[N] value to stack by index

## arg_0

- Opcode: 0x2d 
- Pops: _None_
- Pushes: []byte
- push LogicSig.Args[0] to stack

## arg_1

- Opcode: 0x2e 
- Pops: _None_
- Pushes: []byte
- push LogicSig.Args[1] to stack

## arg_2

- Opcode: 0x2f 
- Pops: _None_
- Pushes: []byte
- push LogicSig.Args[2] to stack

## arg_3

- Opcode: 0x30 
- Pops: _None_
- Pushes: []byte
- push LogicSig.Args[3] to stack

## txn

- Opcode: 0x31 {uint8 transaction field index}
- Pops: _None_
- Pushes: any
- push field from current transaction to stack

`txn` Fields:

| Index | Name | Type |
| --- | --- | --- |
| 0 | Sender | []byte |
| 1 | Fee | uint64 |
| 2 | FirstValid | uint64 |
| 3 | FirstValidTime | uint64 |
| 4 | LastValid | uint64 |
| 5 | Note | []byte |
| 6 | Lease | []byte |
| 7 | Receiver | []byte |
| 8 | Amount | uint64 |
| 9 | CloseRemainderTo | []byte |
| 10 | VotePK | []byte |
| 11 | SelectionPK | []byte |
| 12 | VoteFirst | uint64 |
| 13 | VoteLast | uint64 |
| 14 | VoteKeyDilution | uint64 |
| 15 | Type | []byte |
| 16 | TypeEnum | uint64 |
| 17 | XferAsset | uint64 |
| 18 | AssetAmount | uint64 |
| 19 | AssetSender | []byte |
| 20 | AssetReceiver | []byte |
| 21 | AssetCloseTo | []byte |
| 22 | GroupIndex | uint64 |
| 23 | TxID | []byte |


TypeEnum mapping:

| Index | "Type" string | Description |
| --- | --- | --- |
| 0 | unknown | Unknown type. Invalid transaction. |
| 1 | pay | Payment |
| 2 | keyreg | Key Registration |
| 3 | acfg | Asset Config |
| 4 | axfer | Asset Transfer |
| 5 | afrz | Asset Freeze |


FirstValidTime is actually the time of the round at FirstValid-1. Subtle implementation details make it much faster to serve details of an already completed round.

## global

- Opcode: 0x32 {uint8 global field index}
- Pops: _None_
- Pushes: any
- push value from globals to stack

`global` Fields:

| Index | Name | Type |
| --- | --- | --- |
| 0 | MinTxnFee | uint64 |
| 1 | MinBalance | uint64 |
| 2 | MaxTxnLife | uint64 |
| 3 | ZeroAddress | []byte |
| 4 | GroupSize | uint64 |


## gtxn

- Opcode: 0x33 {uint8 transaction group index}{uint8 transaction field index}
- Pops: _None_
- Pushes: any
- push field to the stack from a transaction in the current transaction group

for notes on transaction fields available, see `txn`

## load

- Opcode: 0x34 {uint8 position in scratch space to load from}
- Pops: _None_
- Pushes: any
- copy a value from scratch space to the stack

## store

- Opcode: 0x35 {uint8 position in scratch space to store to}
- Pops: *... stack*, any
- Pushes: _None_
- pop a value from the stack and store to scratch space

## bnz

- Opcode: 0x40 {0..0x7fff forward branch offset, big endian}
- Pops: *... stack*, uint64
- Pushes: _None_
- branch if value is not zero

For a bnz instruction at `pc`, if the last element of the stack is not zero then branch to instruction at `pc + 3 + N`, else proceed to next instruction at `pc + 3`. Branch targets must be well aligned instructions. (e.g. Branching to the second byte of a 2 byte op will be rejected.)

## pop

- Opcode: 0x48 
- Pops: *... stack*, any
- Pushes: _None_
- discard value from stack

## dup

- Opcode: 0x49 
- Pops: *... stack*, any
- Pushes: any, any
- duplicate last value on stack
