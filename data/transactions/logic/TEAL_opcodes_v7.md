# v7 Opcodes

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

The 32 byte public key is the last element on the stack, preceded by the 64 byte signature at the second-to-last element on the stack, preceded by the data which was signed at the third-to-last element on the stack.

## ecdsa_verify

- Syntax: `ecdsa_verify V` where V: [ECDSA](#field-group-ecdsa)
- Bytecode: 0x05 {uint8}
- Stack: ..., A: [32]byte, B: []byte, C: []byte, D: []byte, E: []byte &rarr; ..., bool
- for (data A, signature B, C and pubkey D, E) verify the signature of the data against the pubkey => {0 or 1}
- **Cost**: Secp256k1=1700; Secp256r1=2500
- Availability: v5

### ECDSA

Curves

| Index | Name | In | Notes |
| - | ------ | - | --------- |
| 0 | Secp256k1 |      | secp256k1 curve, used in Bitcoin |
| 1 | Secp256r1 | v7  | secp256r1 curve, NIST standard |


The 32 byte Y-component of a public key is the last element on the stack, preceded by X-component of a pubkey, preceded by S and R components of a signature, preceded by the data that is fifth element on the stack. All values are big-endian encoded. The signed data must be 32 bytes long, and signatures in lower-S form are only accepted.

## ecdsa_pk_decompress

- Syntax: `ecdsa_pk_decompress V` where V: [ECDSA](#field-group-ecdsa)
- Bytecode: 0x06 {uint8}
- Stack: ..., A: []byte &rarr; ..., X: []byte, Y: []byte
- decompress pubkey A into components X, Y
- **Cost**: Secp256k1=650; Secp256r1=2400
- Availability: v5

The 33 byte public key in a compressed form to be decompressed into X and Y (top) components. All values are big-endian encoded.

## ecdsa_pk_recover

- Syntax: `ecdsa_pk_recover V` where V: [ECDSA](#field-group-ecdsa)
- Bytecode: 0x07 {uint8}
- Stack: ..., A: [32]byte, B: uint64, C: [32]byte, D: [32]byte &rarr; ..., X: []byte, Y: []byte
- for (data A, recovery id B, signature C, D) recover a public key
- **Cost**: 2000
- Availability: v5

S (top) and R elements of a signature, recovery id and data (bottom) are expected on the stack and used to deriver a public key. All values are big-endian encoded. The signed data must be 32 bytes long.

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
- Stack: ..., A: uint64 &rarr; ..., []byte
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

## divmodw

- Bytecode: 0x1f
- Stack: ..., A: uint64, B: uint64, C: uint64, D: uint64 &rarr; ..., W: uint64, X: uint64, Y: uint64, Z: uint64
- W,X = (A,B / C,D); Y,Z = (A,B modulo C,D)
- **Cost**: 20
- Availability: v4

The notation J,K indicates that two uint64 values J and K are interpreted as a uint128 value, with J as the high uint64 and K the low.

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
| 3 | FirstValidTime | uint64 | v7  | UNIX timestamp of block before txn.FirstValid. Fails if negative |
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
| 56 | ExtraProgramPages | uint64 | v4  | Number of additional pages for each of the application's approval and clear state programs. An ExtraProgramPages of 1 means 2048 more total bytes, or 1024 for each program. |
| 57 | Nonparticipation | bool | v5  | Marks an account nonparticipating for rewards |
| 59 | NumLogs | uint64 | v5  | Number of Logs (only with `itxn` in v5). Application mode only |
| 60 | CreatedAssetID | uint64 | v5  | Asset ID allocated by the creation of an ASA (only with `itxn` in v5). Application mode only |
| 61 | CreatedApplicationID | uint64 | v5  | ApplicationID allocated by the creation of an application (only with `itxn` in v5). Application mode only |
| 62 | LastLog | []byte | v6  | The last message emitted. Empty bytes if none were emitted. Application mode only |
| 63 | StateProofPK | []byte | v6  | 64 byte state proof public key |
| 65 | NumApprovalProgramPages | uint64 | v7  | Number of Approval Program pages |
| 67 | NumClearStateProgramPages | uint64 | v7  | Number of ClearState Program pages |


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
| 10 | CurrentApplicationAddress | address | v5  | Address that the current application controls. Application mode only. |
| 11 | GroupID | [32]byte | v5  | ID of the transaction group. 32 zero bytes if the transaction is not part of a group. |
| 12 | OpcodeBudget | uint64 | v6  | The remaining cost that can be spent by opcodes in this program. |
| 13 | CallerApplicationID | uint64 | v6  | The application ID of the application that called this application. 0 if this application is at the top-level. Application mode only. |
| 14 | CallerApplicationAddress | address | v6  | The application address of the application that called this application. ZeroAddress if this application is at the top-level. Application mode only. |


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
| 58 | Logs | []byte | v5  | Log messages emitted by an application call (only with `itxn` in v5). Application mode only |
| 64 | ApprovalProgramPages | []byte | v7  | Approval Program as an array of pages |
| 66 | ClearStateProgramPages | []byte | v7  | ClearState Program as an array of pages |


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

## gload

- Syntax: `gload T I` where T: transaction group index, I: position in scratch space to load from
- Bytecode: 0x3a {uint8}, {uint8}
- Stack: ... &rarr; ..., any
- Ith scratch space value of the Tth transaction in the current group
- Availability: v4
- Mode: Application

`gload` fails unless the requested transaction is an ApplicationCall and T < GroupIndex.

## gloads

- Syntax: `gloads I` where I: position in scratch space to load from
- Bytecode: 0x3b {uint8}
- Stack: ..., A: uint64 &rarr; ..., any
- Ith scratch space value of the Ath transaction in the current group
- Availability: v4
- Mode: Application

`gloads` fails unless the requested transaction is an ApplicationCall and A < GroupIndex.

## gaid

- Syntax: `gaid T` where T: transaction group index
- Bytecode: 0x3c {uint8}
- Stack: ... &rarr; ..., uint64
- ID of the asset or application created in the Tth transaction of the current group
- Availability: v4
- Mode: Application

`gaid` fails unless the requested transaction created an asset or application and T < GroupIndex.

## gaids

- Bytecode: 0x3d
- Stack: ..., A: uint64 &rarr; ..., uint64
- ID of the asset or application created in the Ath transaction of the current group
- Availability: v4
- Mode: Application

`gaids` fails unless the requested transaction created an asset or application and A < GroupIndex.

## loads

- Bytecode: 0x3e
- Stack: ..., A: uint64 &rarr; ..., any
- Ath scratch space value.  All scratch spaces are 0 at program start.
- Availability: v5

## stores

- Bytecode: 0x3f
- Stack: ..., A: uint64, B &rarr; ...
- store B to the Ath scratch space
- Availability: v5

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

## cover

- Syntax: `cover N` where N: depth
- Bytecode: 0x4e {uint8}
- Stack: ..., [N items], A &rarr; ..., A, [N items]
- remove top of stack, and place it deeper in the stack such that N elements are above it. Fails if stack depth <= N.
- Availability: v5

## uncover

- Syntax: `uncover N` where N: depth
- Bytecode: 0x4f {uint8}
- Stack: ..., A, [N items] &rarr; ..., [N items], A
- remove the value at depth N in the stack and shift above items down so the Nth deep value is on top of the stack. Fails if stack depth <= N.
- Availability: v5

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

## extract

- Syntax: `extract S L` where S: start position, L: length
- Bytecode: 0x57 {uint8}, {uint8}
- Stack: ..., A: []byte &rarr; ..., []byte
- A range of bytes from A starting at S up to but not including S+L. If L is 0, then extract to the end of the string. If S or S+L is larger than the array length, the program fails
- Availability: v5

## extract3

- Bytecode: 0x58
- Stack: ..., A: []byte, B: uint64, C: uint64 &rarr; ..., []byte
- A range of bytes from A starting at B up to but not including B+C. If B+C is larger than the array length, the program fails<br />`extract3` can be called using `extract` with no immediates.
- Availability: v5

## extract_uint16

- Bytecode: 0x59
- Stack: ..., A: []byte, B: uint64 &rarr; ..., uint64
- A uint16 formed from a range of big-endian bytes from A starting at B up to but not including B+2. If B+2 is larger than the array length, the program fails
- Availability: v5

## extract_uint32

- Bytecode: 0x5a
- Stack: ..., A: []byte, B: uint64 &rarr; ..., uint64
- A uint32 formed from a range of big-endian bytes from A starting at B up to but not including B+4. If B+4 is larger than the array length, the program fails
- Availability: v5

## extract_uint64

- Bytecode: 0x5b
- Stack: ..., A: []byte, B: uint64 &rarr; ..., uint64
- A uint64 formed from a range of big-endian bytes from A starting at B up to but not including B+8. If B+8 is larger than the array length, the program fails
- Availability: v5

## replace2

- Syntax: `replace2 S` where S: start position
- Bytecode: 0x5c {uint8}
- Stack: ..., A: []byte, B: []byte &rarr; ..., []byte
- Copy of A with the bytes starting at S replaced by the bytes of B. Fails if S+len(B) exceeds len(A)<br />`replace2` can be called using `replace` with 1 immediate.
- Availability: v7

## replace3

- Bytecode: 0x5d
- Stack: ..., A: []byte, B: uint64, C: []byte &rarr; ..., []byte
- Copy of A with the bytes starting at B replaced by the bytes of C. Fails if B+len(C) exceeds len(A)<br />`replace3` can be called using `replace` with no immediates.
- Availability: v7

## base64_decode

- Syntax: `base64_decode E` where E: [base64](#field-group-base64)
- Bytecode: 0x5e {uint8}
- Stack: ..., A: []byte &rarr; ..., []byte
- decode A which was base64-encoded using _encoding_ E. Fail if A is not base64 encoded with encoding E
- **Cost**: 1 + 1 per 16 bytes of A
- Availability: v7

### base64

Encodings

| Index | Name | Notes |
| - | ------ | --------- |
| 0 | URLEncoding |  |
| 1 | StdEncoding |  |


*Warning*: Usage should be restricted to very rare use cases. In almost all cases, smart contracts should directly handle non-encoded byte-strings.	This opcode should only be used in cases where base64 is the only available option, e.g. interoperability with a third-party that only signs base64 strings.

 Decodes A using the base64 encoding E. Specify the encoding with an immediate arg either as URL and Filename Safe (`URLEncoding`) or Standard (`StdEncoding`). See [RFC 4648 sections 4 and 5](https://rfc-editor.org/rfc/rfc4648.html#section-4). It is assumed that the encoding ends with the exact number of `=` padding characters as required by the RFC. When padding occurs, any unused pad bits in the encoding must be set to zero or the decoding will fail. The special cases of `\n` and `\r` are allowed but completely ignored. An error will result when attempting to decode a string with a character that is not in the encoding alphabet or not one of `=`, `\r`, or `\n`.

## json_ref

- Syntax: `json_ref R` where R: [json_ref](#field-group-json_ref)
- Bytecode: 0x5f {uint8}
- Stack: ..., A: []byte, B: []byte &rarr; ..., any
- key B's value, of type R, from a [valid](jsonspec.md) utf-8 encoded json object A
- **Cost**: 25 + 2 per 7 bytes of A
- Availability: v7

### json_ref

Types

| Index | Name | Type | Notes |
| - | ------ | -- | --------- |
| 0 | JSONString | []byte |  |
| 1 | JSONUint64 | uint64 |  |
| 2 | JSONObject | []byte |  |


*Warning*: Usage should be restricted to very rare use cases, as JSON decoding is expensive and quite limited. In addition, JSON objects are large and not optimized for size.

Almost all smart contracts should use simpler and smaller methods (such as the [ABI](https://arc.algorand.foundation/ARCs/arc-0004). This opcode should only be used in cases where JSON is only available option, e.g. when a third-party only signs JSON.

## balance

- Bytecode: 0x60
- Stack: ..., A &rarr; ..., uint64
- balance for account A, in microalgos. The balance is observed after the effects of previous transactions in the group, and after the fee for the current transaction is deducted. Changes caused by inner transactions are observable immediately following `itxn_submit`
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset). Return: value.

## app_opted_in

- Bytecode: 0x61
- Stack: ..., A, B: uint64 &rarr; ..., bool
- 1 if account A is opted in to application B, else 0
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset). Return: 1 if opted in and 0 otherwise.

## app_local_get

- Bytecode: 0x62
- Stack: ..., A, B: []byte &rarr; ..., any
- local state of the key B in the current application in account A
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), state key. Return: value. The value is zero (of type uint64) if the key does not exist.

## app_local_get_ex

- Bytecode: 0x63
- Stack: ..., A, B: uint64, C: []byte &rarr; ..., X: any, Y: bool
- X is the local state of application B, key C in account A. Y is 1 if key existed, else 0
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset), state key. Return: did_exist flag (top of the stack, 1 if the application and key existed and 0 otherwise), value. The value is zero (of type uint64) if the key does not exist.

## app_global_get

- Bytecode: 0x64
- Stack: ..., A: []byte &rarr; ..., any
- global state of the key A in the current application
- Availability: v2
- Mode: Application

params: state key. Return: value. The value is zero (of type uint64) if the key does not exist.

## app_global_get_ex

- Bytecode: 0x65
- Stack: ..., A: uint64, B: []byte &rarr; ..., X: any, Y: bool
- X is the global state of application A, key B. Y is 1 if key existed, else 0
- Availability: v2
- Mode: Application

params: Txn.ForeignApps offset (or, since v4, an _available_ application id), state key. Return: did_exist flag (top of the stack, 1 if the application and key existed and 0 otherwise), value. The value is zero (of type uint64) if the key does not exist.

## app_local_put

- Bytecode: 0x66
- Stack: ..., A, B: []byte, C &rarr; ...
- write C to key B in account A's local state of the current application
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), state key, value.

## app_global_put

- Bytecode: 0x67
- Stack: ..., A: []byte, B &rarr; ...
- write B to key A in the global state of the current application
- Availability: v2
- Mode: Application

## app_local_del

- Bytecode: 0x68
- Stack: ..., A, B: []byte &rarr; ...
- delete key B from account A's local state of the current application
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), state key.

Deleting a key which is already absent has no effect on the application local state. (In particular, it does _not_ cause the program to fail.)

## app_global_del

- Bytecode: 0x69
- Stack: ..., A: []byte &rarr; ...
- delete key A from the global state of the current application
- Availability: v2
- Mode: Application

params: state key.

Deleting a key which is already absent has no effect on the application global state. (In particular, it does _not_ cause the program to fail.)

## asset_holding_get

- Syntax: `asset_holding_get F` where F: [asset_holding](#field-group-asset_holding)
- Bytecode: 0x70 {uint8}
- Stack: ..., A, B: uint64 &rarr; ..., X: any, Y: bool
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

| Index | Name | Type | In | Notes |
| - | ------ | -- | - | --------- |
| 0 | AssetTotal | uint64 |      | Total number of units of this asset |
| 1 | AssetDecimals | uint64 |      | See AssetParams.Decimals |
| 2 | AssetDefaultFrozen | bool |      | Frozen by default or not |
| 3 | AssetUnitName | []byte |      | Asset unit name |
| 4 | AssetName | []byte |      | Asset name |
| 5 | AssetURL | []byte |      | URL with additional info about the asset |
| 6 | AssetMetadataHash | [32]byte |      | Arbitrary commitment |
| 7 | AssetManager | address |      | Manager address |
| 8 | AssetReserve | address |      | Reserve address |
| 9 | AssetFreeze | address |      | Freeze address |
| 10 | AssetClawback | address |      | Clawback address |
| 11 | AssetCreator | address | v5  | Creator address |


params: Txn.ForeignAssets offset (or, since v4, an _available_ asset id. Return: did_exist flag (1 if the asset existed and 0 otherwise), value.

## app_params_get

- Syntax: `app_params_get F` where F: [app_params](#field-group-app_params)
- Bytecode: 0x72 {uint8}
- Stack: ..., A: uint64 &rarr; ..., X: any, Y: bool
- X is field F from app A. Y is 1 if A exists, else 0
- Availability: v5
- Mode: Application

### app_params

Fields

| Index | Name | Type | Notes |
| - | ------ | -- | --------- |
| 0 | AppApprovalProgram | []byte | Bytecode of Approval Program |
| 1 | AppClearStateProgram | []byte | Bytecode of Clear State Program |
| 2 | AppGlobalNumUint | uint64 | Number of uint64 values allowed in Global State |
| 3 | AppGlobalNumByteSlice | uint64 | Number of byte array values allowed in Global State |
| 4 | AppLocalNumUint | uint64 | Number of uint64 values allowed in Local State |
| 5 | AppLocalNumByteSlice | uint64 | Number of byte array values allowed in Local State |
| 6 | AppExtraProgramPages | uint64 | Number of Extra Program Pages of code space |
| 7 | AppCreator | address | Creator address |
| 8 | AppAddress | address | Address for which this application has authority |


params: Txn.ForeignApps offset or an _available_ app id. Return: did_exist flag (1 if the application existed and 0 otherwise), value.

## acct_params_get

- Syntax: `acct_params_get F` where F: [acct_params](#field-group-acct_params)
- Bytecode: 0x73 {uint8}
- Stack: ..., A &rarr; ..., X: any, Y: bool
- X is field F from account A. Y is 1 if A owns positive algos, else 0
- Availability: v6
- Mode: Application

### acct_params

Fields

| Index | Name | Type | Notes |
| - | ------ | -- | --------- |
| 0 | AcctBalance | uint64 | Account balance in microalgos |
| 1 | AcctMinBalance | uint64 | Minimum required balance for account, in microalgos |
| 2 | AcctAuthAddr | address | Address the account is rekeyed to. |


## min_balance

- Bytecode: 0x78
- Stack: ..., A &rarr; ..., uint64
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

## ed25519verify_bare

- Bytecode: 0x84
- Stack: ..., A: []byte, B: [64]byte, C: [32]byte &rarr; ..., bool
- for (data A, signature B, pubkey C) verify the signature of the data against the pubkey => {0 or 1}
- **Cost**: 1900
- Availability: v7

## callsub

- Syntax: `callsub TARGET` where TARGET: branch offset
- Bytecode: 0x88 {int16 (big-endian)}
- Stack: ... &rarr; ...
- branch unconditionally to TARGET, saving the next instruction on the call stack
- Availability: v4

The call stack is separate from the data stack. Only `callsub`, `retsub`, and `proto` manipulate it.

## retsub

- Bytecode: 0x89
- Stack: ... &rarr; ...
- pop the top instruction from the call stack and branch to it
- Availability: v4

If the current frame was prepared by `proto A R`, `retsub` will remove the 'A' arguments from the stack, move the `R` return values down, and pop any stack locations above the relocated return values.

## shl

- Bytecode: 0x90
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A times 2^B, modulo 2^64
- Availability: v4

## shr

- Bytecode: 0x91
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A divided by 2^B
- Availability: v4

## sqrt

- Bytecode: 0x92
- Stack: ..., A: uint64 &rarr; ..., uint64
- The largest integer I such that I^2 <= A
- **Cost**: 4
- Availability: v4

## bitlen

- Bytecode: 0x93
- Stack: ..., A &rarr; ..., uint64
- The highest set bit in A. If A is a byte-array, it is interpreted as a big-endian unsigned integer. bitlen of 0 is 0, bitlen of 8 is 4
- Availability: v4

bitlen interprets arrays as big-endian integers, unlike setbit/getbit

## exp

- Bytecode: 0x94
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A raised to the Bth power. Fail if A == B == 0 and on overflow
- Availability: v4

## expw

- Bytecode: 0x95
- Stack: ..., A: uint64, B: uint64 &rarr; ..., X: uint64, Y: uint64
- A raised to the Bth power as a 128-bit result in two uint64s. X is the high 64 bits, Y is the low. Fail if A == B == 0 or if the results exceeds 2^128-1
- **Cost**: 10
- Availability: v4

## bsqrt

- Bytecode: 0x96
- Stack: ..., A: []byte &rarr; ..., []byte
- The largest integer I such that I^2 <= A. A and I are interpreted as big-endian unsigned integers
- **Cost**: 40
- Availability: v6

## divw

- Bytecode: 0x97
- Stack: ..., A: uint64, B: uint64, C: uint64 &rarr; ..., uint64
- A,B / C. Fail if C == 0 or if result overflows.
- Availability: v6

The notation A,B indicates that A and B are interpreted as a uint128 value, with A as the high uint64 and B the low.

## sha3_256

- Bytecode: 0x98
- Stack: ..., A: []byte &rarr; ..., []byte
- SHA3_256 hash of value A, yields [32]byte
- **Cost**: 130
- Availability: v7

## b+

- Bytecode: 0xa0
- Stack: ..., A: bigint, B: bigint &rarr; ..., []byte
- A plus B. A and B are interpreted as big-endian unsigned integers
- **Cost**: 10
- Availability: v4

## b-

- Bytecode: 0xa1
- Stack: ..., A: bigint, B: bigint &rarr; ..., bigint
- A minus B. A and B are interpreted as big-endian unsigned integers. Fail on underflow.
- **Cost**: 10
- Availability: v4

## b/

- Bytecode: 0xa2
- Stack: ..., A: bigint, B: bigint &rarr; ..., bigint
- A divided by B (truncated division). A and B are interpreted as big-endian unsigned integers. Fail if B is zero.
- **Cost**: 20
- Availability: v4

## b*

- Bytecode: 0xa3
- Stack: ..., A: bigint, B: bigint &rarr; ..., []byte
- A times B. A and B are interpreted as big-endian unsigned integers.
- **Cost**: 20
- Availability: v4

## b<

- Bytecode: 0xa4
- Stack: ..., A: bigint, B: bigint &rarr; ..., bool
- 1 if A is less than B, else 0. A and B are interpreted as big-endian unsigned integers
- Availability: v4

## b>

- Bytecode: 0xa5
- Stack: ..., A: bigint, B: bigint &rarr; ..., bool
- 1 if A is greater than B, else 0. A and B are interpreted as big-endian unsigned integers
- Availability: v4

## b<=

- Bytecode: 0xa6
- Stack: ..., A: bigint, B: bigint &rarr; ..., bool
- 1 if A is less than or equal to B, else 0. A and B are interpreted as big-endian unsigned integers
- Availability: v4

## b>=

- Bytecode: 0xa7
- Stack: ..., A: bigint, B: bigint &rarr; ..., bool
- 1 if A is greater than or equal to B, else 0. A and B are interpreted as big-endian unsigned integers
- Availability: v4

## b==

- Bytecode: 0xa8
- Stack: ..., A: bigint, B: bigint &rarr; ..., bool
- 1 if A is equal to B, else 0. A and B are interpreted as big-endian unsigned integers
- Availability: v4

## b!=

- Bytecode: 0xa9
- Stack: ..., A: bigint, B: bigint &rarr; ..., bool
- 0 if A is equal to B, else 1. A and B are interpreted as big-endian unsigned integers
- Availability: v4

## b%

- Bytecode: 0xaa
- Stack: ..., A: []byte, B: []byte &rarr; ..., []byte
- A modulo B. A and B are interpreted as big-endian unsigned integers. Fail if B is zero.
- **Cost**: 20
- Availability: v4

## b|

- Bytecode: 0xab
- Stack: ..., A: []byte, B: []byte &rarr; ..., []byte
- A bitwise-or B. A and B are zero-left extended to the greater of their lengths
- **Cost**: 6
- Availability: v4

## b&

- Bytecode: 0xac
- Stack: ..., A: []byte, B: []byte &rarr; ..., []byte
- A bitwise-and B. A and B are zero-left extended to the greater of their lengths
- **Cost**: 6
- Availability: v4

## b^

- Bytecode: 0xad
- Stack: ..., A: []byte, B: []byte &rarr; ..., []byte
- A bitwise-xor B. A and B are zero-left extended to the greater of their lengths
- **Cost**: 6
- Availability: v4

## b~

- Bytecode: 0xae
- Stack: ..., A: []byte &rarr; ..., []byte
- A with all bits inverted
- **Cost**: 4
- Availability: v4

## bzero

- Bytecode: 0xaf
- Stack: ..., A: uint64 &rarr; ..., []byte
- zero filled byte-array of length A
- Availability: v4

## log

- Bytecode: 0xb0
- Stack: ..., A: []byte &rarr; ...
- write A to log state of the current application
- Availability: v5
- Mode: Application

`log` fails if called more than MaxLogCalls times in a program, or if the sum of logged bytes exceeds 1024 bytes.

## itxn_begin

- Bytecode: 0xb1
- Stack: ... &rarr; ...
- begin preparation of a new inner transaction in a new transaction group
- Availability: v5
- Mode: Application

`itxn_begin` initializes Sender to the application address; Fee to the minimum allowable, taking into account MinTxnFee and credit from overpaying in earlier transactions; FirstValid/LastValid to the values in the invoking transaction, and all other fields to zero or empty values.

## itxn_field

- Syntax: `itxn_field F` where F: [txn](#field-group-txn)
- Bytecode: 0xb2 {uint8}
- Stack: ..., A &rarr; ...
- set field F of the current inner transaction to A
- Availability: v5
- Mode: Application

`itxn_field` fails if A is of the wrong type for F, including a byte array of the wrong size for use as an address when F is an address field. `itxn_field` also fails if A is an account, asset, or app that is not _available_, or an attempt is made extend an array field beyond the limit imposed by consensus parameters. (Addresses set into asset params of acfg transactions need not be _available_.)

## itxn_submit

- Bytecode: 0xb3
- Stack: ... &rarr; ...
- execute the current inner transaction group. Fail if executing this group would exceed the inner transaction limit, or if any transaction in the group fails.
- Availability: v5
- Mode: Application

`itxn_submit` resets the current transaction so that it can not be resubmitted. A new `itxn_begin` is required to prepare another inner transaction.

## itxn

- Syntax: `itxn F` where F: [txn](#field-group-txn)
- Bytecode: 0xb4 {uint8}
- Stack: ... &rarr; ..., any
- field F of the last inner transaction
- Availability: v5
- Mode: Application

## itxna

- Syntax: `itxna F I` where F: [txna](#field-group-txna), I: a transaction field array index
- Bytecode: 0xb5 {uint8}, {uint8}
- Stack: ... &rarr; ..., any
- Ith value of the array field F of the last inner transaction
- Availability: v5
- Mode: Application

## itxn_next

- Bytecode: 0xb6
- Stack: ... &rarr; ...
- begin preparation of a new inner transaction in the same transaction group
- Availability: v6
- Mode: Application

`itxn_next` initializes the transaction exactly as `itxn_begin` does

## gitxn

- Syntax: `gitxn T F` where T: transaction group index, F: [txn](#field-group-txn)
- Bytecode: 0xb7 {uint8}, {uint8}
- Stack: ... &rarr; ..., any
- field F of the Tth transaction in the last inner group submitted
- Availability: v6
- Mode: Application

## gitxna

- Syntax: `gitxna T F I` where T: transaction group index, F: [txna](#field-group-txna), I: transaction field array index
- Bytecode: 0xb8 {uint8}, {uint8}, {uint8}
- Stack: ... &rarr; ..., any
- Ith value of the array field F from the Tth transaction in the last inner group submitted
- Availability: v6
- Mode: Application

## txnas

- Syntax: `txnas F` where F: [txna](#field-group-txna)
- Bytecode: 0xc0 {uint8}
- Stack: ..., A: uint64 &rarr; ..., any
- Ath value of the array field F of the current transaction
- Availability: v5

## gtxnas

- Syntax: `gtxnas T F` where T: transaction group index, F: [txna](#field-group-txna)
- Bytecode: 0xc1 {uint8}, {uint8}
- Stack: ..., A: uint64 &rarr; ..., any
- Ath value of the array field F from the Tth transaction in the current group
- Availability: v5

## gtxnsas

- Syntax: `gtxnsas F` where F: [txna](#field-group-txna)
- Bytecode: 0xc2 {uint8}
- Stack: ..., A: uint64, B: uint64 &rarr; ..., any
- Bth value of the array field F from the Ath transaction in the current group
- Availability: v5

## args

- Bytecode: 0xc3
- Stack: ..., A: uint64 &rarr; ..., []byte
- Ath LogicSig argument
- Availability: v5
- Mode: Signature

## gloadss

- Bytecode: 0xc4
- Stack: ..., A: uint64, B: uint64 &rarr; ..., any
- Bth scratch space value of the Ath transaction in the current group
- Availability: v6
- Mode: Application

## itxnas

- Syntax: `itxnas F` where F: [txna](#field-group-txna)
- Bytecode: 0xc5 {uint8}
- Stack: ..., A: uint64 &rarr; ..., any
- Ath value of the array field F of the last inner transaction
- Availability: v6
- Mode: Application

## gitxnas

- Syntax: `gitxnas T F` where T: transaction group index, F: [txna](#field-group-txna)
- Bytecode: 0xc6 {uint8}, {uint8}
- Stack: ..., A: uint64 &rarr; ..., any
- Ath value of the array field F from the Tth transaction in the last inner group submitted
- Availability: v6
- Mode: Application

## vrf_verify

- Syntax: `vrf_verify S` where S: [vrf_verify](#field-group-vrf_verify)
- Bytecode: 0xd0 {uint8}
- Stack: ..., A: []byte, B: [80]byte, C: [32]byte &rarr; ..., X: []byte, Y: bool
- Verify the proof B of message A against pubkey C. Returns vrf output and verification flag.
- **Cost**: 5700
- Availability: v7

### vrf_verify

Standards

| Index | Name | Notes |
| - | ------ | --------- |
| 0 | VrfAlgorand |  |


`VrfAlgorand` is the VRF used in Algorand. It is ECVRF-ED25519-SHA512-Elligator2, specified in the IETF internet draft [draft-irtf-cfrg-vrf-03](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vrf/03/).

## block

- Syntax: `block F` where F: [block](#field-group-block)
- Bytecode: 0xd1 {uint8}
- Stack: ..., A: uint64 &rarr; ..., any
- field F of block A. Fail unless A falls between txn.LastValid-1002 and txn.FirstValid (exclusive)
- Availability: v7

### block

Fields

| Index | Name | Type | Notes |
| - | ------ | -- | --------- |
| 0 | BlkSeed | []byte |  |
| 1 | BlkTimestamp | uint64 |  |

