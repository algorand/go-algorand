# v1 Opcodes

Ops have a 'cost' of 1 unless otherwise specified.


## err

- Bytecode: 0x00
- Stack: ... &rarr; _exits_
- Fail immediately.

## sha256

- Bytecode: 0x01
- Stack: ..., A: []byte &rarr; ..., [32]byte
- SHA256 hash of value A, yields [32]byte
- **Cost**: 7

## keccak256

- Bytecode: 0x02
- Stack: ..., A: []byte &rarr; ..., [32]byte
- Keccak256 hash of value A, yields [32]byte
- **Cost**: 26

## sha512_256

- Bytecode: 0x03
- Stack: ..., A: []byte &rarr; ..., [32]byte
- SHA512_256 hash of value A, yields [32]byte
- **Cost**: 9

## ed25519verify

- Bytecode: 0x04
- Stack: ..., A: []byte, B: [64]byte, C: [32]byte &rarr; ..., bool
- for (data A, signature B, pubkey C) verify the signature of ("ProgData" || program_hash || data) against the pubkey => {0 or 1}
- **Cost**: 1900
- Mode: Signature

The 32 byte public key is the last element on the stack, preceded by the 64 byte signature at the second-to-last element on the stack, preceded by the data which was signed at the third-to-last element on the stack.

## +

- Bytecode: 0x08
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A plus B. Fail on overflow.

Overflow is an error condition which halts execution and fails the transaction. Full precision is available from `addw`.

## -

- Bytecode: 0x09
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A minus B. Fail if B > A.

## /

- Bytecode: 0x0a
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A divided by B (truncated division). Fail if B == 0.

`divmodw` is available to divide the two-element values produced by `mulw` and `addw`.

## *

- Bytecode: 0x0b
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A times B. Fail on overflow.

Overflow is an error condition which halts execution and fails the transaction. Full precision is available from `mulw`.

## <

- Bytecode: 0x0c
- Stack: ..., A: uint64, B: uint64 &rarr; ..., bool
- A less than B => {0 or 1}

## >

- Bytecode: 0x0d
- Stack: ..., A: uint64, B: uint64 &rarr; ..., bool
- A greater than B => {0 or 1}

## <=

- Bytecode: 0x0e
- Stack: ..., A: uint64, B: uint64 &rarr; ..., bool
- A less than or equal to B => {0 or 1}

## >=

- Bytecode: 0x0f
- Stack: ..., A: uint64, B: uint64 &rarr; ..., bool
- A greater than or equal to B => {0 or 1}

## &&

- Bytecode: 0x10
- Stack: ..., A: uint64, B: uint64 &rarr; ..., bool
- A is not zero and B is not zero => {0 or 1}

## ||

- Bytecode: 0x11
- Stack: ..., A: uint64, B: uint64 &rarr; ..., bool
- A is not zero or B is not zero => {0 or 1}

## ==

- Bytecode: 0x12
- Stack: ..., A, B &rarr; ..., bool
- A is equal to B => {0 or 1}

## !=

- Bytecode: 0x13
- Stack: ..., A, B &rarr; ..., bool
- A is not equal to B => {0 or 1}

## !

- Bytecode: 0x14
- Stack: ..., A: uint64 &rarr; ..., uint64
- A == 0 yields 1; else 0

## len

- Bytecode: 0x15
- Stack: ..., A: []byte &rarr; ..., uint64
- yields length of byte value A

## itob

- Bytecode: 0x16
- Stack: ..., A: uint64 &rarr; ..., [8]byte
- converts uint64 A to big-endian byte array, always of length 8

## btoi

- Bytecode: 0x17
- Stack: ..., A: []byte &rarr; ..., uint64
- converts big-endian byte array A to uint64. Fails if len(A) > 8. Padded by leading 0s if len(A) < 8.

`btoi` fails if the input is longer than 8 bytes.

## %

- Bytecode: 0x18
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A modulo B. Fail if B == 0.

## |

- Bytecode: 0x19
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A bitwise-or B

## &

- Bytecode: 0x1a
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A bitwise-and B

## ^

- Bytecode: 0x1b
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A bitwise-xor B

## ~

- Bytecode: 0x1c
- Stack: ..., A: uint64 &rarr; ..., uint64
- bitwise invert value A

## mulw

- Bytecode: 0x1d
- Stack: ..., A: uint64, B: uint64 &rarr; ..., X: uint64, Y: uint64
- A times B as a 128-bit result in two uint64s. X is the high 64 bits, Y is the low

## intcblock

- Syntax: `intcblock UINT ...` where UINT ...: a block of int constant values
- Bytecode: 0x20 {varuint count, [varuint ...]}
- Stack: ... &rarr; ...
- prepare block of uint64 constants for use by intc

`intcblock` loads following program bytes into an array of integer constants in the evaluator. These integer constants can be referred to by `intc` and `intc_*` which will push the value onto the stack. Subsequent calls to `intcblock` reset and replace the integer constants available to the script.

## intc

- Syntax: `intc I` where I: an index in the intcblock
- Bytecode: 0x21 {uint8}
- Stack: ... &rarr; ..., uint64
- Ith constant from intcblock

## intc_0

- Bytecode: 0x22
- Stack: ... &rarr; ..., uint64
- constant 0 from intcblock

## intc_1

- Bytecode: 0x23
- Stack: ... &rarr; ..., uint64
- constant 1 from intcblock

## intc_2

- Bytecode: 0x24
- Stack: ... &rarr; ..., uint64
- constant 2 from intcblock

## intc_3

- Bytecode: 0x25
- Stack: ... &rarr; ..., uint64
- constant 3 from intcblock

## bytecblock

- Syntax: `bytecblock BYTES ...` where BYTES ...: a block of byte constant values
- Bytecode: 0x26 {varuint count, [varuint length, bytes ...]}
- Stack: ... &rarr; ...
- prepare block of byte-array constants for use by bytec

`bytecblock` loads the following program bytes into an array of byte-array constants in the evaluator. These constants can be referred to by `bytec` and `bytec_*` which will push the value onto the stack. Subsequent calls to `bytecblock` reset and replace the bytes constants available to the script.

## bytec

- Syntax: `bytec I` where I: an index in the bytecblock
- Bytecode: 0x27 {uint8}
- Stack: ... &rarr; ..., []byte
- Ith constant from bytecblock

## bytec_0

- Bytecode: 0x28
- Stack: ... &rarr; ..., []byte
- constant 0 from bytecblock

## bytec_1

- Bytecode: 0x29
- Stack: ... &rarr; ..., []byte
- constant 1 from bytecblock

## bytec_2

- Bytecode: 0x2a
- Stack: ... &rarr; ..., []byte
- constant 2 from bytecblock

## bytec_3

- Bytecode: 0x2b
- Stack: ... &rarr; ..., []byte
- constant 3 from bytecblock

## arg

- Syntax: `arg N` where N: an arg index
- Bytecode: 0x2c {uint8}
- Stack: ... &rarr; ..., []byte
- Nth LogicSig argument
- Mode: Signature

## arg_0

- Bytecode: 0x2d
- Stack: ... &rarr; ..., []byte
- LogicSig argument 0
- Mode: Signature

## arg_1

- Bytecode: 0x2e
- Stack: ... &rarr; ..., []byte
- LogicSig argument 1
- Mode: Signature

## arg_2

- Bytecode: 0x2f
- Stack: ... &rarr; ..., []byte
- LogicSig argument 2
- Mode: Signature

## arg_3

- Bytecode: 0x30
- Stack: ... &rarr; ..., []byte
- LogicSig argument 3
- Mode: Signature

## txn

- Syntax: `txn F` where F: [txn](#field-group-txn)
- Bytecode: 0x31 {uint8}
- Stack: ... &rarr; ..., any
- field F of current transaction

### txn

Fields (see [transaction reference](https://developer.algorand.org/docs/reference/transactions/))

| Index | Name | Type | Notes |
| - | ------ | -- | --------- |
| 0 | Sender | address | 32 byte address |
| 1 | Fee | uint64 | microalgos |
| 2 | FirstValid | uint64 | round number |
| 4 | LastValid | uint64 | round number |
| 5 | Note | []byte | Any data up to 1024 bytes |
| 6 | Lease | [32]byte | 32 byte lease value |
| 7 | Receiver | address | 32 byte address |
| 8 | Amount | uint64 | microalgos |
| 9 | CloseRemainderTo | address | 32 byte address |
| 10 | VotePK | [32]byte | 32 byte address |
| 11 | SelectionPK | [32]byte | 32 byte address |
| 12 | VoteFirst | uint64 | The first round that the participation key is valid. |
| 13 | VoteLast | uint64 | The last round that the participation key is valid. |
| 14 | VoteKeyDilution | uint64 | Dilution for the 2-level participation key |
| 15 | Type | []byte | Transaction type as bytes |
| 16 | TypeEnum | uint64 | Transaction type as integer |
| 17 | XferAsset | uint64 | Asset ID |
| 18 | AssetAmount | uint64 | value in Asset's units |
| 19 | AssetSender | address | 32 byte address. Source of assets if Sender is the Asset's Clawback address. |
| 20 | AssetReceiver | address | 32 byte address |
| 21 | AssetCloseTo | address | 32 byte address |
| 22 | GroupIndex | uint64 | Position of this transaction within an atomic transaction group. A stand-alone transaction is implicitly element 0 in a group of 1 |
| 23 | TxID | [32]byte | The computed ID for this transaction. 32 bytes. |


## global

- Syntax: `global F` where F: [global](#field-group-global)
- Bytecode: 0x32 {uint8}
- Stack: ... &rarr; ..., any
- global field F

### global

Fields

| Index | Name | Type | Notes |
| - | ------ | -- | --------- |
| 0 | MinTxnFee | uint64 | microalgos |
| 1 | MinBalance | uint64 | microalgos |
| 2 | MaxTxnLife | uint64 | rounds |
| 3 | ZeroAddress | address | 32 byte address of all zero bytes |
| 4 | GroupSize | uint64 | Number of transactions in this atomic transaction group. At least 1 |


## gtxn

- Syntax: `gtxn T F` where T: transaction group index, F: [txn](#field-group-txn)
- Bytecode: 0x33 {uint8}, {uint8}
- Stack: ... &rarr; ..., any
- field F of the Tth transaction in the current group

for notes on transaction fields available, see `txn`. If this transaction is _i_ in the group, `gtxn i field` is equivalent to `txn field`.

## load

- Syntax: `load I` where I: position in scratch space to load from
- Bytecode: 0x34 {uint8}
- Stack: ... &rarr; ..., any
- Ith scratch space value. All scratch spaces are 0 at program start.

## store

- Syntax: `store I` where I: position in scratch space to store to
- Bytecode: 0x35 {uint8}
- Stack: ..., A &rarr; ...
- store A to the Ith scratch space

## bnz

- Syntax: `bnz TARGET` where TARGET: branch offset
- Bytecode: 0x40 {int16 (big-endian)}
- Stack: ..., A: uint64 &rarr; ...
- branch to TARGET if value A is not zero

The `bnz` instruction opcode 0x40 is followed by two immediate data bytes which are a high byte first and low byte second which together form a 16 bit offset which the instruction may branch to. For a bnz instruction at `pc`, if the last element of the stack is not zero then branch to instruction at `pc + 3 + N`, else proceed to next instruction at `pc + 3`. Branch targets must be aligned instructions. (e.g. Branching to the second byte of a 2 byte op will be rejected.) Starting at v4, the offset is treated as a signed 16 bit integer allowing for backward branches and looping. In prior version (v1 to v3), branch offsets are limited to forward branches only, 0-0x7fff.

At v2 it became allowed to branch to the end of the program exactly after the last instruction: bnz to byte N (with 0-indexing) was illegal for a TEAL program with N bytes before v2, and is legal after it. This change eliminates the need for a last instruction of no-op as a branch target at the end. (Branching beyond the end--in other words, to a byte larger than N--is still illegal and will cause the program to fail.)

## pop

- Bytecode: 0x48
- Stack: ..., A &rarr; ...
- discard A

## dup

- Bytecode: 0x49
- Stack: ..., A &rarr; ..., A, A
- duplicate A
