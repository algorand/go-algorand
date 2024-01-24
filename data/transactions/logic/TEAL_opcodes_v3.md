# v3 Opcodes

Ops have a 'cost' of 1 unless otherwise specified.


## err

- Bytecode: 0x00
- Stack: ... &rarr; _exits_
- Fail immediately.

## sha256

- Bytecode: 0x01
- Stack: ..., A: []byte &rarr; ..., [32]byte
- SHA256 hash of value A, yields [32]byte
- **Cost**: 35

## keccak256

- Bytecode: 0x02
- Stack: ..., A: []byte &rarr; ..., [32]byte
- Keccak256 hash of value A, yields [32]byte
- **Cost**: 130

## sha512_256

- Bytecode: 0x03
- Stack: ..., A: []byte &rarr; ..., [32]byte
- SHA512_256 hash of value A, yields [32]byte
- **Cost**: 45

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

## addw

- Bytecode: 0x1e
- Stack: ..., A: uint64, B: uint64 &rarr; ..., X: uint64, Y: uint64
- A plus B as a 128-bit result. X is the carry-bit, Y is the low-order 64 bits.
- Availability: v2

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

| Index | Name | Type | In | Notes |
| - | ------ | -- | - | --------- |
| 0 | Sender | address |      | 32 byte address |
| 1 | Fee | uint64 |      | microalgos |
| 2 | FirstValid | uint64 |      | round number |
| 4 | LastValid | uint64 |      | round number |
| 5 | Note | []byte |      | Any data up to 1024 bytes |
| 6 | Lease | [32]byte |      | 32 byte lease value |
| 7 | Receiver | address |      | 32 byte address |
| 8 | Amount | uint64 |      | microalgos |
| 9 | CloseRemainderTo | address |      | 32 byte address |
| 10 | VotePK | [32]byte |      | 32 byte address |
| 11 | SelectionPK | [32]byte |      | 32 byte address |
| 12 | VoteFirst | uint64 |      | The first round that the participation key is valid. |
| 13 | VoteLast | uint64 |      | The last round that the participation key is valid. |
| 14 | VoteKeyDilution | uint64 |      | Dilution for the 2-level participation key |
| 15 | Type | []byte |      | Transaction type as bytes |
| 16 | TypeEnum | uint64 |      | Transaction type as integer |
| 17 | XferAsset | uint64 |      | Asset ID |
| 18 | AssetAmount | uint64 |      | value in Asset's units |
| 19 | AssetSender | address |      | 32 byte address. Source of assets if Sender is the Asset's Clawback address. |
| 20 | AssetReceiver | address |      | 32 byte address |
| 21 | AssetCloseTo | address |      | 32 byte address |
| 22 | GroupIndex | uint64 |      | Position of this transaction within an atomic transaction group. A stand-alone transaction is implicitly element 0 in a group of 1 |
| 23 | TxID | [32]byte |      | The computed ID for this transaction. 32 bytes. |
| 24 | ApplicationID | uint64 | v2  | ApplicationID from ApplicationCall transaction |
| 25 | OnCompletion | uint64 | v2  | ApplicationCall transaction on completion action |
| 27 | NumAppArgs | uint64 | v2  | Number of ApplicationArgs |
| 29 | NumAccounts | uint64 | v2  | Number of Accounts |
| 30 | ApprovalProgram | []byte | v2  | Approval program |
| 31 | ClearStateProgram | []byte | v2  | Clear state program |
| 32 | RekeyTo | address | v2  | 32 byte Sender's new AuthAddr |
| 33 | ConfigAsset | uint64 | v2  | Asset ID in asset config transaction |
| 34 | ConfigAssetTotal | uint64 | v2  | Total number of units of this asset created |
| 35 | ConfigAssetDecimals | uint64 | v2  | Number of digits to display after the decimal place when displaying the asset |
| 36 | ConfigAssetDefaultFrozen | bool | v2  | Whether the asset's slots are frozen by default or not, 0 or 1 |
| 37 | ConfigAssetUnitName | []byte | v2  | Unit name of the asset |
| 38 | ConfigAssetName | []byte | v2  | The asset name |
| 39 | ConfigAssetURL | []byte | v2  | URL |
| 40 | ConfigAssetMetadataHash | [32]byte | v2  | 32 byte commitment to unspecified asset metadata |
| 41 | ConfigAssetManager | address | v2  | 32 byte address |
| 42 | ConfigAssetReserve | address | v2  | 32 byte address |
| 43 | ConfigAssetFreeze | address | v2  | 32 byte address |
| 44 | ConfigAssetClawback | address | v2  | 32 byte address |
| 45 | FreezeAsset | uint64 | v2  | Asset ID being frozen or un-frozen |
| 46 | FreezeAssetAccount | address | v2  | 32 byte address of the account whose asset slot is being frozen or un-frozen |
| 47 | FreezeAssetFrozen | bool | v2  | The new frozen value, 0 or 1 |
| 49 | NumAssets | uint64 | v3  | Number of Assets |
| 51 | NumApplications | uint64 | v3  | Number of Applications |
| 52 | GlobalNumUint | uint64 | v3  | Number of global state integers in ApplicationCall |
| 53 | GlobalNumByteSlice | uint64 | v3  | Number of global state byteslices in ApplicationCall |
| 54 | LocalNumUint | uint64 | v3  | Number of local state integers in ApplicationCall |
| 55 | LocalNumByteSlice | uint64 | v3  | Number of local state byteslices in ApplicationCall |


## global

- Syntax: `global F` where F: [global](#field-group-global)
- Bytecode: 0x32 {uint8}
- Stack: ... &rarr; ..., any
- global field F

### global

Fields

| Index | Name | Type | In | Notes |
| - | ------ | -- | - | --------- |
| 0 | MinTxnFee | uint64 |      | microalgos |
| 1 | MinBalance | uint64 |      | microalgos |
| 2 | MaxTxnLife | uint64 |      | rounds |
| 3 | ZeroAddress | address |      | 32 byte address of all zero bytes |
| 4 | GroupSize | uint64 |      | Number of transactions in this atomic transaction group. At least 1 |
| 5 | LogicSigVersion | uint64 | v2  | Maximum supported version |
| 6 | Round | uint64 | v2  | Current round number. Application mode only. |
| 7 | LatestTimestamp | uint64 | v2  | Last confirmed block UNIX timestamp. Fails if negative. Application mode only. |
| 8 | CurrentApplicationID | uint64 | v2  | ID of current application executing. Application mode only. |
| 9 | CreatorAddress | address | v3  | Address of the creator of the current application. Application mode only. |


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

## txna

- Syntax: `txna F I` where F: [txna](#field-group-txna), I: transaction field array index
- Bytecode: 0x36 {uint8}, {uint8}
- Stack: ... &rarr; ..., any
- Ith value of the array field F of the current transaction<br />`txna` can be called using `txn` with 2 immediates.
- Availability: v2

### txna

Fields (see [transaction reference](https://developer.algorand.org/docs/reference/transactions/))

| Index | Name | Type | In | Notes |
| - | ------ | -- | - | --------- |
| 26 | ApplicationArgs | []byte | v2  | Arguments passed to the application in the ApplicationCall transaction |
| 28 | Accounts | address | v2  | Accounts listed in the ApplicationCall transaction |
| 48 | Assets | uint64 | v3  | Foreign Assets listed in the ApplicationCall transaction |
| 50 | Applications | uint64 | v3  | Foreign Apps listed in the ApplicationCall transaction |


## gtxna

- Syntax: `gtxna T F I` where T: transaction group index, F: [txna](#field-group-txna), I: transaction field array index
- Bytecode: 0x37 {uint8}, {uint8}, {uint8}
- Stack: ... &rarr; ..., any
- Ith value of the array field F from the Tth transaction in the current group<br />`gtxna` can be called using `gtxn` with 3 immediates.
- Availability: v2

## gtxns

- Syntax: `gtxns F` where F: [txn](#field-group-txn)
- Bytecode: 0x38 {uint8}
- Stack: ..., A: uint64 &rarr; ..., any
- field F of the Ath transaction in the current group
- Availability: v3

for notes on transaction fields available, see `txn`. If top of stack is _i_, `gtxns field` is equivalent to `gtxn _i_ field`. gtxns exists so that _i_ can be calculated, often based on the index of the current transaction.

## gtxnsa

- Syntax: `gtxnsa F I` where F: [txna](#field-group-txna), I: transaction field array index
- Bytecode: 0x39 {uint8}, {uint8}
- Stack: ..., A: uint64 &rarr; ..., any
- Ith value of the array field F from the Ath transaction in the current group<br />`gtxnsa` can be called using `gtxns` with 2 immediates.
- Availability: v3

## bnz

- Syntax: `bnz TARGET` where TARGET: branch offset
- Bytecode: 0x40 {int16 (big-endian)}
- Stack: ..., A: uint64 &rarr; ...
- branch to TARGET if value A is not zero

The `bnz` instruction opcode 0x40 is followed by two immediate data bytes which are a high byte first and low byte second which together form a 16 bit offset which the instruction may branch to. For a bnz instruction at `pc`, if the last element of the stack is not zero then branch to instruction at `pc + 3 + N`, else proceed to next instruction at `pc + 3`. Branch targets must be aligned instructions. (e.g. Branching to the second byte of a 2 byte op will be rejected.) Starting at v4, the offset is treated as a signed 16 bit integer allowing for backward branches and looping. In prior version (v1 to v3), branch offsets are limited to forward branches only, 0-0x7fff.

At v2 it became allowed to branch to the end of the program exactly after the last instruction: bnz to byte N (with 0-indexing) was illegal for a TEAL program with N bytes before v2, and is legal after it. This change eliminates the need for a last instruction of no-op as a branch target at the end. (Branching beyond the end--in other words, to a byte larger than N--is still illegal and will cause the program to fail.)

## bz

- Syntax: `bz TARGET` where TARGET: branch offset
- Bytecode: 0x41 {int16 (big-endian)}
- Stack: ..., A: uint64 &rarr; ...
- branch to TARGET if value A is zero
- Availability: v2

See `bnz` for details on how branches work. `bz` inverts the behavior of `bnz`.

## b

- Syntax: `b TARGET` where TARGET: branch offset
- Bytecode: 0x42 {int16 (big-endian)}
- Stack: ... &rarr; ...
- branch unconditionally to TARGET
- Availability: v2

See `bnz` for details on how branches work. `b` always jumps to the offset.

## return

- Bytecode: 0x43
- Stack: ..., A: uint64 &rarr; _exits_
- use A as success value; end
- Availability: v2

## assert

- Bytecode: 0x44
- Stack: ..., A: uint64 &rarr; ...
- immediately fail unless A is a non-zero number
- Availability: v3

## pop

- Bytecode: 0x48
- Stack: ..., A &rarr; ...
- discard A

## dup

- Bytecode: 0x49
- Stack: ..., A &rarr; ..., A, A
- duplicate A

## dup2

- Bytecode: 0x4a
- Stack: ..., A, B &rarr; ..., A, B, A, B
- duplicate A and B
- Availability: v2

## dig

- Syntax: `dig N` where N: depth
- Bytecode: 0x4b {uint8}
- Stack: ..., A, [N items] &rarr; ..., A, [N items], A
- Nth value from the top of the stack. dig 0 is equivalent to dup
- Availability: v3

## swap

- Bytecode: 0x4c
- Stack: ..., A, B &rarr; ..., B, A
- swaps A and B on stack
- Availability: v3

## select

- Bytecode: 0x4d
- Stack: ..., A, B, C: uint64 &rarr; ..., A or B
- selects one of two values based on top-of-stack: B if C != 0, else A
- Availability: v3

## concat

- Bytecode: 0x50
- Stack: ..., A: []byte, B: []byte &rarr; ..., []byte
- join A and B
- Availability: v2

`concat` fails if the result would be greater than 4096 bytes.

## substring

- Syntax: `substring S E` where S: start position, E: end position
- Bytecode: 0x51 {uint8}, {uint8}
- Stack: ..., A: []byte &rarr; ..., []byte
- A range of bytes from A starting at S up to but not including E. If E < S, or either is larger than the array length, the program fails
- Availability: v2

## substring3

- Bytecode: 0x52
- Stack: ..., A: []byte, B: uint64, C: uint64 &rarr; ..., []byte
- A range of bytes from A starting at B up to but not including C. If C < B, or either is larger than the array length, the program fails
- Availability: v2

## getbit

- Bytecode: 0x53
- Stack: ..., A, B: uint64 &rarr; ..., uint64
- Bth bit of (byte-array or integer) A. If B is greater than or equal to the bit length of the value (8*byte length), the program fails
- Availability: v3

see explanation of bit ordering in setbit

## setbit

- Bytecode: 0x54
- Stack: ..., A, B: uint64, C: uint64 &rarr; ..., any
- Copy of (byte-array or integer) A, with the Bth bit set to (0 or 1) C. If B is greater than or equal to the bit length of the value (8*byte length), the program fails
- Availability: v3

When A is a uint64, index 0 is the least significant bit. Setting bit 3 to 1 on the integer 0 yields 8, or 2^3. When A is a byte array, index 0 is the leftmost bit of the leftmost byte. Setting bits 0 through 11 to 1 in a 4-byte-array of 0s yields the byte array 0xfff00000. Setting bit 3 to 1 on the 1-byte-array 0x00 yields the byte array 0x10.

## getbyte

- Bytecode: 0x55
- Stack: ..., A: []byte, B: uint64 &rarr; ..., uint64
- Bth byte of A, as an integer. If B is greater than or equal to the array length, the program fails
- Availability: v3

## setbyte

- Bytecode: 0x56
- Stack: ..., A: []byte, B: uint64, C: uint64 &rarr; ..., []byte
- Copy of A with the Bth byte set to small integer (between 0..255) C. If B is greater than or equal to the array length, the program fails
- Availability: v3

## balance

- Bytecode: 0x60
- Stack: ..., A: uint64 &rarr; ..., uint64
- balance for account A, in microalgos. The balance is observed after the effects of previous transactions in the group, and after the fee for the current transaction is deducted. Changes caused by inner transactions are observable immediately following `itxn_submit`
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset). Return: value.

## app_opted_in

- Bytecode: 0x61
- Stack: ..., A: uint64, B: uint64 &rarr; ..., bool
- 1 if account A is opted in to application B, else 0
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset). Return: 1 if opted in and 0 otherwise.

## app_local_get

- Bytecode: 0x62
- Stack: ..., A: uint64, B: stateKey &rarr; ..., any
- local state of the key B in the current application in account A
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), state key. Return: value. The value is zero (of type uint64) if the key does not exist.

## app_local_get_ex

- Bytecode: 0x63
- Stack: ..., A: uint64, B: uint64, C: stateKey &rarr; ..., X: any, Y: bool
- X is the local state of application B, key C in account A. Y is 1 if key existed, else 0
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset), state key. Return: did_exist flag (top of the stack, 1 if the application and key existed and 0 otherwise), value. The value is zero (of type uint64) if the key does not exist.

## app_global_get

- Bytecode: 0x64
- Stack: ..., A: stateKey &rarr; ..., any
- global state of the key A in the current application
- Availability: v2
- Mode: Application

params: state key. Return: value. The value is zero (of type uint64) if the key does not exist.

## app_global_get_ex

- Bytecode: 0x65
- Stack: ..., A: uint64, B: stateKey &rarr; ..., X: any, Y: bool
- X is the global state of application A, key B. Y is 1 if key existed, else 0
- Availability: v2
- Mode: Application

params: Txn.ForeignApps offset (or, since v4, an _available_ application id), state key. Return: did_exist flag (top of the stack, 1 if the application and key existed and 0 otherwise), value. The value is zero (of type uint64) if the key does not exist.

## app_local_put

- Bytecode: 0x66
- Stack: ..., A: uint64, B: stateKey, C &rarr; ...
- write C to key B in account A's local state of the current application
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), state key, value.

## app_global_put

- Bytecode: 0x67
- Stack: ..., A: stateKey, B &rarr; ...
- write B to key A in the global state of the current application
- Availability: v2
- Mode: Application

## app_local_del

- Bytecode: 0x68
- Stack: ..., A: uint64, B: stateKey &rarr; ...
- delete key B from account A's local state of the current application
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), state key.

Deleting a key which is already absent has no effect on the application local state. (In particular, it does _not_ cause the program to fail.)

## app_global_del

- Bytecode: 0x69
- Stack: ..., A: stateKey &rarr; ...
- delete key A from the global state of the current application
- Availability: v2
- Mode: Application

params: state key.

Deleting a key which is already absent has no effect on the application global state. (In particular, it does _not_ cause the program to fail.)

## asset_holding_get

- Syntax: `asset_holding_get F` where F: [asset_holding](#field-group-asset_holding)
- Bytecode: 0x70 {uint8}
- Stack: ..., A: uint64, B: uint64 &rarr; ..., X: any, Y: bool
- X is field F from account A's holding of asset B. Y is 1 if A is opted into B, else 0
- Availability: v2
- Mode: Application

### asset_holding

Fields

| Index | Name | Type | Notes |
| - | ------ | -- | --------- |
| 0 | AssetBalance | uint64 | Amount of the asset unit held by this account |
| 1 | AssetFrozen | bool | Is the asset frozen or not |


params: Txn.Accounts offset (or, since v4, an _available_ address), asset id (or, since v4, a Txn.ForeignAssets offset). Return: did_exist flag (1 if the asset existed and 0 otherwise), value.

## asset_params_get

- Syntax: `asset_params_get F` where F: [asset_params](#field-group-asset_params)
- Bytecode: 0x71 {uint8}
- Stack: ..., A: uint64 &rarr; ..., X: any, Y: bool
- X is field F from asset A. Y is 1 if A exists, else 0
- Availability: v2
- Mode: Application

### asset_params

Fields

| Index | Name | Type | Notes |
| - | ------ | -- | --------- |
| 0 | AssetTotal | uint64 | Total number of units of this asset |
| 1 | AssetDecimals | uint64 | See AssetParams.Decimals |
| 2 | AssetDefaultFrozen | bool | Frozen by default or not |
| 3 | AssetUnitName | []byte | Asset unit name |
| 4 | AssetName | []byte | Asset name |
| 5 | AssetURL | []byte | URL with additional info about the asset |
| 6 | AssetMetadataHash | [32]byte | Arbitrary commitment |
| 7 | AssetManager | address | Manager address |
| 8 | AssetReserve | address | Reserve address |
| 9 | AssetFreeze | address | Freeze address |
| 10 | AssetClawback | address | Clawback address |


params: Txn.ForeignAssets offset (or, since v4, an _available_ asset id. Return: did_exist flag (1 if the asset existed and 0 otherwise), value.

## min_balance

- Bytecode: 0x78
- Stack: ..., A: uint64 &rarr; ..., uint64
- minimum required balance for account A, in microalgos. Required balance is affected by ASA, App, and Box usage. When creating or opting into an app, the minimum balance grows before the app code runs, therefore the increase is visible there. When deleting or closing out, the minimum balance decreases after the app executes. Changes caused by inner transactions or box usage are observable immediately following the opcode effecting the change.
- Availability: v3
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset). Return: value.

## pushbytes

- Syntax: `pushbytes BYTES` where BYTES: a byte constant
- Bytecode: 0x80 {varuint length, bytes}
- Stack: ... &rarr; ..., []byte
- immediate BYTES
- Availability: v3

pushbytes args are not added to the bytecblock during assembly processes

## pushint

- Syntax: `pushint UINT` where UINT: an int constant
- Bytecode: 0x81 {varuint}
- Stack: ... &rarr; ..., uint64
- immediate UINT
- Availability: v3

pushint args are not added to the intcblock during assembly processes
