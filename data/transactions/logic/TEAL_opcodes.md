# Opcodes

Ops have a 'cost' of 1 unless otherwise specified.


## err

- Opcode: 0x00
- Stack: ... &rarr; _exits_
- Fail immediately.

## sha256

- Opcode: 0x01
- Stack: ..., A: []byte &rarr; ..., []byte
- SHA256 hash of value A, yields [32]byte
- **Cost**:
    - 7 (v1)
    - 35 (since v2)

## keccak256

- Opcode: 0x02
- Stack: ..., A: []byte &rarr; ..., []byte
- Keccak256 hash of value A, yields [32]byte
- **Cost**:
    - 26 (v1)
    - 130 (since v2)

## sha512_256

- Opcode: 0x03
- Stack: ..., A: []byte &rarr; ..., []byte
- SHA512_256 hash of value A, yields [32]byte
- **Cost**:
    - 9 (v1)
    - 45 (since v2)

## ed25519verify

- Opcode: 0x04
- Stack: ..., A: []byte, B: []byte, C: []byte &rarr; ..., uint64
- for (data A, signature B, pubkey C) verify the signature of ("ProgData" || program_hash || data) against the pubkey => {0 or 1}
- **Cost**: 1900

The 32 byte public key is the last element on the stack, preceded by the 64 byte signature at the second-to-last element on the stack, preceded by the data which was signed at the third-to-last element on the stack.

## ecdsa_verify v

- Opcode: 0x05 {uint8 curve index}
- Stack: ..., A: []byte, B: []byte, C: []byte, D: []byte, E: []byte &rarr; ..., uint64
- for (data A, signature B, C and pubkey D, E) verify the signature of the data against the pubkey => {0 or 1}
- **Cost**:  Secp256k1=1700 Secp256r1=2500
- Availability: v5

`ECDSA` Curves:

| Index | Name | In | Notes |
| - | ------ | - | --------- |
| 0 | Secp256k1 |      | secp256k1 curve, used in Bitcoin |
| 1 | Secp256r1 | v7  | secp256r1 curve, NIST standard |


The 32 byte Y-component of a public key is the last element on the stack, preceded by X-component of a pubkey, preceded by S and R components of a signature, preceded by the data that is fifth element on the stack. All values are big-endian encoded. The signed data must be 32 bytes long, and signatures in lower-S form are only accepted.

## ecdsa_pk_decompress v

- Opcode: 0x06 {uint8 curve index}
- Stack: ..., A: []byte &rarr; ..., X: []byte, Y: []byte
- decompress pubkey A into components X, Y
- **Cost**:  Secp256k1=650 Secp256r1=2400
- Availability: v5

The 33 byte public key in a compressed form to be decompressed into X and Y (top) components. All values are big-endian encoded.

## ecdsa_pk_recover v

- Opcode: 0x07 {uint8 curve index}
- Stack: ..., A: []byte, B: uint64, C: []byte, D: []byte &rarr; ..., X: []byte, Y: []byte
- for (data A, recovery id B, signature C, D) recover a public key
- **Cost**: 2000
- Availability: v5

S (top) and R elements of a signature, recovery id and data (bottom) are expected on the stack and used to deriver a public key. All values are big-endian encoded. The signed data must be 32 bytes long.

## +

- Opcode: 0x08
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A plus B. Fail on overflow.

Overflow is an error condition which halts execution and fails the transaction. Full precision is available from `addw`.

## -

- Opcode: 0x09
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A minus B. Fail if B > A.

## /

- Opcode: 0x0a
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A divided by B (truncated division). Fail if B == 0.

`divmodw` is available to divide the two-element values produced by `mulw` and `addw`.

## *

- Opcode: 0x0b
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A times B. Fail on overflow.

Overflow is an error condition which halts execution and fails the transaction. Full precision is available from `mulw`.

## <

- Opcode: 0x0c
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A less than B => {0 or 1}

## >

- Opcode: 0x0d
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A greater than B => {0 or 1}

## <=

- Opcode: 0x0e
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A less than or equal to B => {0 or 1}

## >=

- Opcode: 0x0f
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A greater than or equal to B => {0 or 1}

## &&

- Opcode: 0x10
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A is not zero and B is not zero => {0 or 1}

## ||

- Opcode: 0x11
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A is not zero or B is not zero => {0 or 1}

## ==

- Opcode: 0x12
- Stack: ..., A, B &rarr; ..., uint64
- A is equal to B => {0 or 1}

## !=

- Opcode: 0x13
- Stack: ..., A, B &rarr; ..., uint64
- A is not equal to B => {0 or 1}

## !

- Opcode: 0x14
- Stack: ..., A: uint64 &rarr; ..., uint64
- A == 0 yields 1; else 0

## len

- Opcode: 0x15
- Stack: ..., A: []byte &rarr; ..., uint64
- yields length of byte value A

## itob

- Opcode: 0x16
- Stack: ..., A: uint64 &rarr; ..., []byte
- converts uint64 A to big-endian byte array, always of length 8

## btoi

- Opcode: 0x17
- Stack: ..., A: []byte &rarr; ..., uint64
- converts big-endian byte array A to uint64. Fails if len(A) > 8. Padded by leading 0s if len(A) < 8.

`btoi` fails if the input is longer than 8 bytes.

## %

- Opcode: 0x18
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A modulo B. Fail if B == 0.

## |

- Opcode: 0x19
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A bitwise-or B

## &

- Opcode: 0x1a
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A bitwise-and B

## ^

- Opcode: 0x1b
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A bitwise-xor B

## ~

- Opcode: 0x1c
- Stack: ..., A: uint64 &rarr; ..., uint64
- bitwise invert value A

## mulw

- Opcode: 0x1d
- Stack: ..., A: uint64, B: uint64 &rarr; ..., X: uint64, Y: uint64
- A times B as a 128-bit result in two uint64s. X is the high 64 bits, Y is the low

## addw

- Opcode: 0x1e
- Stack: ..., A: uint64, B: uint64 &rarr; ..., X: uint64, Y: uint64
- A plus B as a 128-bit result. X is the carry-bit, Y is the low-order 64 bits.
- Availability: v2

## divmodw

- Opcode: 0x1f
- Stack: ..., A: uint64, B: uint64, C: uint64, D: uint64 &rarr; ..., W: uint64, X: uint64, Y: uint64, Z: uint64
- W,X = (A,B / C,D); Y,Z = (A,B modulo C,D)
- **Cost**: 20
- Availability: v4

The notation J,K indicates that two uint64 values J and K are interpreted as a uint128 value, with J as the high uint64 and K the low.

## intcblock uint ...

- Opcode: 0x20 {varuint length} [{varuint value}, ...]
- Stack: ... &rarr; ...
- prepare block of uint64 constants for use by intc

`intcblock` loads following program bytes into an array of integer constants in the evaluator. These integer constants can be referred to by `intc` and `intc_*` which will push the value onto the stack. Subsequent calls to `intcblock` reset and replace the integer constants available to the script.

## intc i

- Opcode: 0x21 {uint8 int constant index}
- Stack: ... &rarr; ..., uint64
- Ith constant from intcblock

## intc_0

- Opcode: 0x22
- Stack: ... &rarr; ..., uint64
- constant 0 from intcblock

## intc_1

- Opcode: 0x23
- Stack: ... &rarr; ..., uint64
- constant 1 from intcblock

## intc_2

- Opcode: 0x24
- Stack: ... &rarr; ..., uint64
- constant 2 from intcblock

## intc_3

- Opcode: 0x25
- Stack: ... &rarr; ..., uint64
- constant 3 from intcblock

## bytecblock bytes ...

- Opcode: 0x26 {varuint length} [({varuint value length} bytes), ...]
- Stack: ... &rarr; ...
- prepare block of byte-array constants for use by bytec

`bytecblock` loads the following program bytes into an array of byte-array constants in the evaluator. These constants can be referred to by `bytec` and `bytec_*` which will push the value onto the stack. Subsequent calls to `bytecblock` reset and replace the bytes constants available to the script.

## bytec i

- Opcode: 0x27 {uint8 byte constant index}
- Stack: ... &rarr; ..., []byte
- Ith constant from bytecblock

## bytec_0

- Opcode: 0x28
- Stack: ... &rarr; ..., []byte
- constant 0 from bytecblock

## bytec_1

- Opcode: 0x29
- Stack: ... &rarr; ..., []byte
- constant 1 from bytecblock

## bytec_2

- Opcode: 0x2a
- Stack: ... &rarr; ..., []byte
- constant 2 from bytecblock

## bytec_3

- Opcode: 0x2b
- Stack: ... &rarr; ..., []byte
- constant 3 from bytecblock

## arg n

- Opcode: 0x2c {uint8 arg index N}
- Stack: ... &rarr; ..., []byte
- Nth LogicSig argument
- Mode: Signature

## arg_0

- Opcode: 0x2d
- Stack: ... &rarr; ..., []byte
- LogicSig argument 0
- Mode: Signature

## arg_1

- Opcode: 0x2e
- Stack: ... &rarr; ..., []byte
- LogicSig argument 1
- Mode: Signature

## arg_2

- Opcode: 0x2f
- Stack: ... &rarr; ..., []byte
- LogicSig argument 2
- Mode: Signature

## arg_3

- Opcode: 0x30
- Stack: ... &rarr; ..., []byte
- LogicSig argument 3
- Mode: Signature

## txn f

- Opcode: 0x31 {uint8 transaction field index}
- Stack: ... &rarr; ..., any
- field F of current transaction

`txn` Fields (see [transaction reference](https://developer.algorand.org/docs/reference/transactions/)):

| Index | Name | Type | In | Notes |
| - | ------ | -- | - | --------- |
| 0 | Sender | []byte |      | 32 byte address |
| 1 | Fee | uint64 |      | microalgos |
| 2 | FirstValid | uint64 |      | round number |
| 3 | FirstValidTime | uint64 |      | Causes program to fail; reserved for future use |
| 4 | LastValid | uint64 |      | round number |
| 5 | Note | []byte |      | Any data up to 1024 bytes |
| 6 | Lease | []byte |      | 32 byte lease value |
| 7 | Receiver | []byte |      | 32 byte address |
| 8 | Amount | uint64 |      | microalgos |
| 9 | CloseRemainderTo | []byte |      | 32 byte address |
| 10 | VotePK | []byte |      | 32 byte address |
| 11 | SelectionPK | []byte |      | 32 byte address |
| 12 | VoteFirst | uint64 |      | The first round that the participation key is valid. |
| 13 | VoteLast | uint64 |      | The last round that the participation key is valid. |
| 14 | VoteKeyDilution | uint64 |      | Dilution for the 2-level participation key |
| 15 | Type | []byte |      | Transaction type as bytes |
| 16 | TypeEnum | uint64 |      | See table below |
| 17 | XferAsset | uint64 |      | Asset ID |
| 18 | AssetAmount | uint64 |      | value in Asset's units |
| 19 | AssetSender | []byte |      | 32 byte address. Moves asset from AssetSender if Sender is the Clawback address of the asset. |
| 20 | AssetReceiver | []byte |      | 32 byte address |
| 21 | AssetCloseTo | []byte |      | 32 byte address |
| 22 | GroupIndex | uint64 |      | Position of this transaction within an atomic transaction group. A stand-alone transaction is implicitly element 0 in a group of 1 |
| 23 | TxID | []byte |      | The computed ID for this transaction. 32 bytes. |
| 24 | ApplicationID | uint64 | v2  | ApplicationID from ApplicationCall transaction |
| 25 | OnCompletion | uint64 | v2  | ApplicationCall transaction on completion action |
| 26 | ApplicationArgs | []byte | v2  | Arguments passed to the application in the ApplicationCall transaction |
| 27 | NumAppArgs | uint64 | v2  | Number of ApplicationArgs |
| 28 | Accounts | []byte | v2  | Accounts listed in the ApplicationCall transaction |
| 29 | NumAccounts | uint64 | v2  | Number of Accounts |
| 30 | ApprovalProgram | []byte | v2  | Approval program |
| 31 | ClearStateProgram | []byte | v2  | Clear state program |
| 32 | RekeyTo | []byte | v2  | 32 byte Sender's new AuthAddr |
| 33 | ConfigAsset | uint64 | v2  | Asset ID in asset config transaction |
| 34 | ConfigAssetTotal | uint64 | v2  | Total number of units of this asset created |
| 35 | ConfigAssetDecimals | uint64 | v2  | Number of digits to display after the decimal place when displaying the asset |
| 36 | ConfigAssetDefaultFrozen | uint64 | v2  | Whether the asset's slots are frozen by default or not, 0 or 1 |
| 37 | ConfigAssetUnitName | []byte | v2  | Unit name of the asset |
| 38 | ConfigAssetName | []byte | v2  | The asset name |
| 39 | ConfigAssetURL | []byte | v2  | URL |
| 40 | ConfigAssetMetadataHash | []byte | v2  | 32 byte commitment to unspecified asset metadata |
| 41 | ConfigAssetManager | []byte | v2  | 32 byte address |
| 42 | ConfigAssetReserve | []byte | v2  | 32 byte address |
| 43 | ConfigAssetFreeze | []byte | v2  | 32 byte address |
| 44 | ConfigAssetClawback | []byte | v2  | 32 byte address |
| 45 | FreezeAsset | uint64 | v2  | Asset ID being frozen or un-frozen |
| 46 | FreezeAssetAccount | []byte | v2  | 32 byte address of the account whose asset slot is being frozen or un-frozen |
| 47 | FreezeAssetFrozen | uint64 | v2  | The new frozen value, 0 or 1 |
| 48 | Assets | uint64 | v3  | Foreign Assets listed in the ApplicationCall transaction |
| 49 | NumAssets | uint64 | v3  | Number of Assets |
| 50 | Applications | uint64 | v3  | Foreign Apps listed in the ApplicationCall transaction |
| 51 | NumApplications | uint64 | v3  | Number of Applications |
| 52 | GlobalNumUint | uint64 | v3  | Number of global state integers in ApplicationCall |
| 53 | GlobalNumByteSlice | uint64 | v3  | Number of global state byteslices in ApplicationCall |
| 54 | LocalNumUint | uint64 | v3  | Number of local state integers in ApplicationCall |
| 55 | LocalNumByteSlice | uint64 | v3  | Number of local state byteslices in ApplicationCall |
| 56 | ExtraProgramPages | uint64 | v4  | Number of additional pages for each of the application's approval and clear state programs. An ExtraProgramPages of 1 means 2048 more total bytes, or 1024 for each program. |
| 57 | Nonparticipation | uint64 | v5  | Marks an account nonparticipating for rewards |
| 58 | Logs | []byte | v5  | Log messages emitted by an application call (only with `itxn` in v5). Application mode only |
| 59 | NumLogs | uint64 | v5  | Number of Logs (only with `itxn` in v5). Application mode only |
| 60 | CreatedAssetID | uint64 | v5  | Asset ID allocated by the creation of an ASA (only with `itxn` in v5). Application mode only |
| 61 | CreatedApplicationID | uint64 | v5  | ApplicationID allocated by the creation of an application (only with `itxn` in v5). Application mode only |
| 62 | LastLog | []byte | v6  | The last message emitted. Empty bytes if none were emitted. Application mode only |
| 63 | StateProofPK | []byte | v6  | 64 byte state proof public key commitment |


FirstValidTime causes the program to fail. The field is reserved for future use.

## global f

- Opcode: 0x32 {uint8 global field index}
- Stack: ... &rarr; ..., any
- global field F

`global` Fields:

| Index | Name | Type | In | Notes |
| - | ------ | -- | - | --------- |
| 0 | MinTxnFee | uint64 |      | microalgos |
| 1 | MinBalance | uint64 |      | microalgos |
| 2 | MaxTxnLife | uint64 |      | rounds |
| 3 | ZeroAddress | []byte |      | 32 byte address of all zero bytes |
| 4 | GroupSize | uint64 |      | Number of transactions in this atomic transaction group. At least 1 |
| 5 | LogicSigVersion | uint64 | v2  | Maximum supported version |
| 6 | Round | uint64 | v2  | Current round number. Application mode only. |
| 7 | LatestTimestamp | uint64 | v2  | Last confirmed block UNIX timestamp. Fails if negative. Application mode only. |
| 8 | CurrentApplicationID | uint64 | v2  | ID of current application executing. Application mode only. |
| 9 | CreatorAddress | []byte | v3  | Address of the creator of the current application. Application mode only. |
| 10 | CurrentApplicationAddress | []byte | v5  | Address that the current application controls. Application mode only. |
| 11 | GroupID | []byte | v5  | ID of the transaction group. 32 zero bytes if the transaction is not part of a group. |
| 12 | OpcodeBudget | uint64 | v6  | The remaining cost that can be spent by opcodes in this program. |
| 13 | CallerApplicationID | uint64 | v6  | The application ID of the application that called this application. 0 if this application is at the top-level. Application mode only. |
| 14 | CallerApplicationAddress | []byte | v6  | The application address of the application that called this application. ZeroAddress if this application is at the top-level. Application mode only. |


## gtxn t f

- Opcode: 0x33 {uint8 transaction group index} {uint8 transaction field index}
- Stack: ... &rarr; ..., any
- field F of the Tth transaction in the current group

for notes on transaction fields available, see `txn`. If this transaction is _i_ in the group, `gtxn i field` is equivalent to `txn field`.

## load i

- Opcode: 0x34 {uint8 position in scratch space to load from}
- Stack: ... &rarr; ..., any
- Ith scratch space value. All scratch spaces are 0 at program start.

## store i

- Opcode: 0x35 {uint8 position in scratch space to store to}
- Stack: ..., A &rarr; ...
- store A to the Ith scratch space

## txna f i

- Opcode: 0x36 {uint8 transaction field index} {uint8 transaction field array index}
- Stack: ... &rarr; ..., any
- Ith value of the array field F of the current transaction
- Availability: v2

## gtxna t f i

- Opcode: 0x37 {uint8 transaction group index} {uint8 transaction field index} {uint8 transaction field array index}
- Stack: ... &rarr; ..., any
- Ith value of the array field F from the Tth transaction in the current group
- Availability: v2

## gtxns f

- Opcode: 0x38 {uint8 transaction field index}
- Stack: ..., A: uint64 &rarr; ..., any
- field F of the Ath transaction in the current group
- Availability: v3

for notes on transaction fields available, see `txn`. If top of stack is _i_, `gtxns field` is equivalent to `gtxn _i_ field`. gtxns exists so that _i_ can be calculated, often based on the index of the current transaction.

## gtxnsa f i

- Opcode: 0x39 {uint8 transaction field index} {uint8 transaction field array index}
- Stack: ..., A: uint64 &rarr; ..., any
- Ith value of the array field F from the Ath transaction in the current group
- Availability: v3

## gload t i

- Opcode: 0x3a {uint8 transaction group index} {uint8 position in scratch space to load from}
- Stack: ... &rarr; ..., any
- Ith scratch space value of the Tth transaction in the current group
- Availability: v4
- Mode: Application

`gload` fails unless the requested transaction is an ApplicationCall and T < GroupIndex.

## gloads i

- Opcode: 0x3b {uint8 position in scratch space to load from}
- Stack: ..., A: uint64 &rarr; ..., any
- Ith scratch space value of the Ath transaction in the current group
- Availability: v4
- Mode: Application

`gloads` fails unless the requested transaction is an ApplicationCall and A < GroupIndex.

## gaid t

- Opcode: 0x3c {uint8 transaction group index}
- Stack: ... &rarr; ..., uint64
- ID of the asset or application created in the Tth transaction of the current group
- Availability: v4
- Mode: Application

`gaid` fails unless the requested transaction created an asset or application and T < GroupIndex.

## gaids

- Opcode: 0x3d
- Stack: ..., A: uint64 &rarr; ..., uint64
- ID of the asset or application created in the Ath transaction of the current group
- Availability: v4
- Mode: Application

`gaids` fails unless the requested transaction created an asset or application and A < GroupIndex.

## loads

- Opcode: 0x3e
- Stack: ..., A: uint64 &rarr; ..., any
- Ath scratch space value.  All scratch spaces are 0 at program start.
- Availability: v5

## stores

- Opcode: 0x3f
- Stack: ..., A: uint64, B &rarr; ...
- store B to the Ath scratch space
- Availability: v5

## bnz target

- Opcode: 0x40 {int16 branch offset, big-endian}
- Stack: ..., A: uint64 &rarr; ...
- branch to TARGET if value A is not zero

The `bnz` instruction opcode 0x40 is followed by two immediate data bytes which are a high byte first and low byte second which together form a 16 bit offset which the instruction may branch to. For a bnz instruction at `pc`, if the last element of the stack is not zero then branch to instruction at `pc + 3 + N`, else proceed to next instruction at `pc + 3`. Branch targets must be aligned instructions. (e.g. Branching to the second byte of a 2 byte op will be rejected.) Starting at v4, the offset is treated as a signed 16 bit integer allowing for backward branches and looping. In prior version (v1 to v3), branch offsets are limited to forward branches only, 0-0x7fff.

At v2 it became allowed to branch to the end of the program exactly after the last instruction: bnz to byte N (with 0-indexing) was illegal for a TEAL program with N bytes before v2, and is legal after it. This change eliminates the need for a last instruction of no-op as a branch target at the end. (Branching beyond the end--in other words, to a byte larger than N--is still illegal and will cause the program to fail.)

## bz target

- Opcode: 0x41 {int16 branch offset, big-endian}
- Stack: ..., A: uint64 &rarr; ...
- branch to TARGET if value A is zero
- Availability: v2

See `bnz` for details on how branches work. `bz` inverts the behavior of `bnz`.

## b target

- Opcode: 0x42 {int16 branch offset, big-endian}
- Stack: ... &rarr; ...
- branch unconditionally to TARGET
- Availability: v2

See `bnz` for details on how branches work. `b` always jumps to the offset.

## return

- Opcode: 0x43
- Stack: ..., A: uint64 &rarr; _exits_
- use A as success value; end
- Availability: v2

## assert

- Opcode: 0x44
- Stack: ..., A: uint64 &rarr; ...
- immediately fail unless A is a non-zero number
- Availability: v3

## pop

- Opcode: 0x48
- Stack: ..., A &rarr; ...
- discard A

## dup

- Opcode: 0x49
- Stack: ..., A &rarr; ..., A, A
- duplicate A

## dup2

- Opcode: 0x4a
- Stack: ..., A, B &rarr; ..., A, B, A, B
- duplicate A and B
- Availability: v2

## dig n

- Opcode: 0x4b {uint8 depth}
- Stack: ..., A, [N items] &rarr; ..., A, [N items], A
- Nth value from the top of the stack. dig 0 is equivalent to dup
- Availability: v3

## swap

- Opcode: 0x4c
- Stack: ..., A, B &rarr; ..., B, A
- swaps A and B on stack
- Availability: v3

## select

- Opcode: 0x4d
- Stack: ..., A, B, C: uint64 &rarr; ..., A or B
- selects one of two values based on top-of-stack: B if C != 0, else A
- Availability: v3

## cover n

- Opcode: 0x4e {uint8 depth}
- Stack: ..., [N items], A &rarr; ..., A, [N items]
- remove top of stack, and place it deeper in the stack such that N elements are above it. Fails if stack depth <= N.
- Availability: v5

## uncover n

- Opcode: 0x4f {uint8 depth}
- Stack: ..., A, [N items] &rarr; ..., [N items], A
- remove the value at depth N in the stack and shift above items down so the Nth deep value is on top of the stack. Fails if stack depth <= N.
- Availability: v5

## concat

- Opcode: 0x50
- Stack: ..., A: []byte, B: []byte &rarr; ..., []byte
- join A and B
- Availability: v2

`concat` fails if the result would be greater than 4096 bytes.

## substring s e

- Opcode: 0x51 {uint8 start position} {uint8 end position}
- Stack: ..., A: []byte &rarr; ..., []byte
- A range of bytes from A starting at S up to but not including E. If E < S, or either is larger than the array length, the program fails
- Availability: v2

## substring3

- Opcode: 0x52
- Stack: ..., A: []byte, B: uint64, C: uint64 &rarr; ..., []byte
- A range of bytes from A starting at B up to but not including C. If C < B, or either is larger than the array length, the program fails
- Availability: v2

## getbit

- Opcode: 0x53
- Stack: ..., A, B: uint64 &rarr; ..., uint64
- Bth bit of (byte-array or integer) A. If B is greater than or equal to the bit length of the value (8*byte length), the program fails
- Availability: v3

see explanation of bit ordering in setbit

## setbit

- Opcode: 0x54
- Stack: ..., A, B: uint64, C: uint64 &rarr; ..., any
- Copy of (byte-array or integer) A, with the Bth bit set to (0 or 1) C. If B is greater than or equal to the bit length of the value (8*byte length), the program fails
- Availability: v3

When A is a uint64, index 0 is the least significant bit. Setting bit 3 to 1 on the integer 0 yields 8, or 2^3. When A is a byte array, index 0 is the leftmost bit of the leftmost byte. Setting bits 0 through 11 to 1 in a 4-byte-array of 0s yields the byte array 0xfff00000. Setting bit 3 to 1 on the 1-byte-array 0x00 yields the byte array 0x10.

## getbyte

- Opcode: 0x55
- Stack: ..., A: []byte, B: uint64 &rarr; ..., uint64
- Bth byte of A, as an integer. If B is greater than or equal to the array length, the program fails
- Availability: v3

## setbyte

- Opcode: 0x56
- Stack: ..., A: []byte, B: uint64, C: uint64 &rarr; ..., []byte
- Copy of A with the Bth byte set to small integer (between 0..255) C. If B is greater than or equal to the array length, the program fails
- Availability: v3

## extract s l

- Opcode: 0x57 {uint8 start position} {uint8 length}
- Stack: ..., A: []byte &rarr; ..., []byte
- A range of bytes from A starting at S up to but not including S+L. If L is 0, then extract to the end of the string. If S or S+L is larger than the array length, the program fails
- Availability: v5

## extract3

- Opcode: 0x58
- Stack: ..., A: []byte, B: uint64, C: uint64 &rarr; ..., []byte
- A range of bytes from A starting at B up to but not including B+C. If B+C is larger than the array length, the program fails
- Availability: v5

## extract_uint16

- Opcode: 0x59
- Stack: ..., A: []byte, B: uint64 &rarr; ..., uint64
- A uint16 formed from a range of big-endian bytes from A starting at B up to but not including B+2. If B+2 is larger than the array length, the program fails
- Availability: v5

## extract_uint32

- Opcode: 0x5a
- Stack: ..., A: []byte, B: uint64 &rarr; ..., uint64
- A uint32 formed from a range of big-endian bytes from A starting at B up to but not including B+4. If B+4 is larger than the array length, the program fails
- Availability: v5

## extract_uint64

- Opcode: 0x5b
- Stack: ..., A: []byte, B: uint64 &rarr; ..., uint64
- A uint64 formed from a range of big-endian bytes from A starting at B up to but not including B+8. If B+8 is larger than the array length, the program fails
- Availability: v5

## base64_decode e

- Opcode: 0x5c {uint8 encoding index}
- Stack: ..., A: []byte &rarr; ..., []byte
- decode A which was base64-encoded using _encoding_ E. Fail if A is not base64 encoded with encoding E
- **Cost**: 1 + 1 per 16 bytes of A
- Availability: v7

`base64` Encodings:

| Index | Name | Notes |
| - | ------ | --------- |
| 0 | URLEncoding |  |
| 1 | StdEncoding |  |


Decodes A using the base64 encoding E. Specify the encoding with an immediate arg either as URL and Filename Safe (`URLEncoding`) or Standard (`StdEncoding`). See <a href="https://rfc-editor.org/rfc/rfc4648.html#section-4">RFC 4648</a> (sections 4 and 5). It is assumed that the encoding ends with the exact number of `=` padding characters as required by the RFC. When padding occurs, any unused pad bits in the encoding must be set to zero or the decoding will fail. The special cases of `\n` and `\r` are allowed but completely ignored. An error will result when attempting to decode a string with a character that is not in the encoding alphabet or not one of `=`, `\r`, or `\n`.

## json_ref r

- Opcode: 0x5d {string return type}
- Stack: ..., A: []byte, B: []byte &rarr; ..., any
- return key B's value from a [valid](jsonspec.md) utf-8 encoded json object A
- **Cost**: 25 + 2 per 7 bytes of A
- Availability: v7

`json_ref` Types:

| Index | Name | Type | Notes |
| - | ------ | -- | --------- |
| 0 | JSONString | []byte |  |
| 1 | JSONUint64 | uint64 |  |
| 2 | JSONObject | []byte |  |


specify the return type with an immediate arg either as JSONUint64 or JSONString or JSONObject.

## balance

- Opcode: 0x60
- Stack: ..., A &rarr; ..., uint64
- get balance for account A, in microalgos. The balance is observed after the effects of previous transactions in the group, and after the fee for the current transaction is deducted.
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset). Return: value.

## app_opted_in

- Opcode: 0x61
- Stack: ..., A, B: uint64 &rarr; ..., uint64
- 1 if account A is opted in to application B, else 0
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset). Return: 1 if opted in and 0 otherwise.

## app_local_get

- Opcode: 0x62
- Stack: ..., A, B: []byte &rarr; ..., any
- local state of the key B in the current application in account A
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), state key. Return: value. The value is zero (of type uint64) if the key does not exist.

## app_local_get_ex

- Opcode: 0x63
- Stack: ..., A, B: uint64, C: []byte &rarr; ..., X: any, Y: uint64
- X is the local state of application B, key C in account A. Y is 1 if key existed, else 0
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset), state key. Return: did_exist flag (top of the stack, 1 if the application and key existed and 0 otherwise), value. The value is zero (of type uint64) if the key does not exist.

## app_global_get

- Opcode: 0x64
- Stack: ..., A: []byte &rarr; ..., any
- global state of the key A in the current application
- Availability: v2
- Mode: Application

params: state key. Return: value. The value is zero (of type uint64) if the key does not exist.

## app_global_get_ex

- Opcode: 0x65
- Stack: ..., A: uint64, B: []byte &rarr; ..., X: any, Y: uint64
- X is the global state of application A, key B. Y is 1 if key existed, else 0
- Availability: v2
- Mode: Application

params: Txn.ForeignApps offset (or, since v4, an _available_ application id), state key. Return: did_exist flag (top of the stack, 1 if the application and key existed and 0 otherwise), value. The value is zero (of type uint64) if the key does not exist.

## app_local_put

- Opcode: 0x66
- Stack: ..., A, B: []byte, C &rarr; ...
- write C to key B in account A's local state of the current application
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), state key, value.

## app_global_put

- Opcode: 0x67
- Stack: ..., A: []byte, B &rarr; ...
- write B to key A in the global state of the current application
- Availability: v2
- Mode: Application

## app_local_del

- Opcode: 0x68
- Stack: ..., A, B: []byte &rarr; ...
- delete key B from account A's local state of the current application
- Availability: v2
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), state key.

Deleting a key which is already absent has no effect on the application local state. (In particular, it does _not_ cause the program to fail.)

## app_global_del

- Opcode: 0x69
- Stack: ..., A: []byte &rarr; ...
- delete key A from the global state of the current application
- Availability: v2
- Mode: Application

params: state key.

Deleting a key which is already absent has no effect on the application global state. (In particular, it does _not_ cause the program to fail.)

## asset_holding_get f

- Opcode: 0x70 {uint8 asset holding field index}
- Stack: ..., A, B: uint64 &rarr; ..., X: any, Y: uint64
- X is field F from account A's holding of asset B. Y is 1 if A is opted into B, else 0
- Availability: v2
- Mode: Application

`asset_holding` Fields:

| Index | Name | Type | Notes |
| - | ------ | -- | --------- |
| 0 | AssetBalance | uint64 | Amount of the asset unit held by this account |
| 1 | AssetFrozen | uint64 | Is the asset frozen or not |


params: Txn.Accounts offset (or, since v4, an _available_ address), asset id (or, since v4, a Txn.ForeignAssets offset). Return: did_exist flag (1 if the asset existed and 0 otherwise), value.

## asset_params_get f

- Opcode: 0x71 {uint8 asset params field index}
- Stack: ..., A: uint64 &rarr; ..., X: any, Y: uint64
- X is field F from asset A. Y is 1 if A exists, else 0
- Availability: v2
- Mode: Application

`asset_params` Fields:

| Index | Name | Type | In | Notes |
| - | ------ | -- | - | --------- |
| 0 | AssetTotal | uint64 |      | Total number of units of this asset |
| 1 | AssetDecimals | uint64 |      | See AssetParams.Decimals |
| 2 | AssetDefaultFrozen | uint64 |      | Frozen by default or not |
| 3 | AssetUnitName | []byte |      | Asset unit name |
| 4 | AssetName | []byte |      | Asset name |
| 5 | AssetURL | []byte |      | URL with additional info about the asset |
| 6 | AssetMetadataHash | []byte |      | Arbitrary commitment |
| 7 | AssetManager | []byte |      | Manager address |
| 8 | AssetReserve | []byte |      | Reserve address |
| 9 | AssetFreeze | []byte |      | Freeze address |
| 10 | AssetClawback | []byte |      | Clawback address |
| 11 | AssetCreator | []byte | v5  | Creator address |


params: Txn.ForeignAssets offset (or, since v4, an _available_ asset id. Return: did_exist flag (1 if the asset existed and 0 otherwise), value.

## app_params_get f

- Opcode: 0x72 {uint8 app params field index}
- Stack: ..., A: uint64 &rarr; ..., X: any, Y: uint64
- X is field F from app A. Y is 1 if A exists, else 0
- Availability: v5
- Mode: Application

`app_params` Fields:

| Index | Name | Type | Notes |
| - | ------ | -- | --------- |
| 0 | AppApprovalProgram | []byte | Bytecode of Approval Program |
| 1 | AppClearStateProgram | []byte | Bytecode of Clear State Program |
| 2 | AppGlobalNumUint | uint64 | Number of uint64 values allowed in Global State |
| 3 | AppGlobalNumByteSlice | uint64 | Number of byte array values allowed in Global State |
| 4 | AppLocalNumUint | uint64 | Number of uint64 values allowed in Local State |
| 5 | AppLocalNumByteSlice | uint64 | Number of byte array values allowed in Local State |
| 6 | AppExtraProgramPages | uint64 | Number of Extra Program Pages of code space |
| 7 | AppCreator | []byte | Creator address |
| 8 | AppAddress | []byte | Address for which this application has authority |


params: Txn.ForeignApps offset or an _available_ app id. Return: did_exist flag (1 if the application existed and 0 otherwise), value.

## acct_params_get f

- Opcode: 0x73 {uint8 account params field index}
- Stack: ..., A &rarr; ..., X: any, Y: uint64
- X is field F from account A. Y is 1 if A owns positive algos, else 0
- Availability: v6
- Mode: Application

`acct_params` Fields:

| Index | Name | Type | Notes |
| - | ------ | -- | --------- |
| 0 | AcctBalance | uint64 | Account balance in microalgos |
| 1 | AcctMinBalance | uint64 | Minimum required blance for account, in microalgos |
| 2 | AcctAuthAddr | []byte | Address the account is rekeyed to. |


## min_balance

- Opcode: 0x78
- Stack: ..., A &rarr; ..., uint64
- get minimum required balance for account A, in microalgos. Required balance is affected by [ASA](https://developer.algorand.org/docs/features/asa/#assets-overview) and [App](https://developer.algorand.org/docs/features/asc1/stateful/#minimum-balance-requirement-for-a-smart-contract) usage. When creating or opting into an app, the minimum balance grows before the app code runs, therefore the increase is visible there. When deleting or closing out, the minimum balance decreases after the app executes.
- Availability: v3
- Mode: Application

params: Txn.Accounts offset (or, since v4, an _available_ account address), _available_ application id (or, since v4, a Txn.ForeignApps offset). Return: value.

## pushbytes bytes

- Opcode: 0x80 {varuint length} {bytes}
- Stack: ... &rarr; ..., []byte
- immediate BYTES
- Availability: v3

pushbytes args are not added to the bytecblock during assembly processes

## pushint uint

- Opcode: 0x81 {varuint int}
- Stack: ... &rarr; ..., uint64
- immediate UINT
- Availability: v3

pushint args are not added to the intcblock during assembly processes

## ed25519verify_bare

- Opcode: 0x84
- Stack: ..., A: []byte, B: []byte, C: []byte &rarr; ..., uint64
- for (data A, signature B, pubkey C) verify the signature of the data against the pubkey => {0 or 1}
- **Cost**: 1900
- Availability: v7

## callsub target

- Opcode: 0x88 {int16 branch offset, big-endian}
- Stack: ... &rarr; ...
- branch unconditionally to TARGET, saving the next instruction on the call stack
- Availability: v4

The call stack is separate from the data stack. Only `callsub` and `retsub` manipulate it.

## retsub

- Opcode: 0x89
- Stack: ... &rarr; ...
- pop the top instruction from the call stack and branch to it
- Availability: v4

The call stack is separate from the data stack. Only `callsub` and `retsub` manipulate it.

## shl

- Opcode: 0x90
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A times 2^B, modulo 2^64
- Availability: v4

## shr

- Opcode: 0x91
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A divided by 2^B
- Availability: v4

## sqrt

- Opcode: 0x92
- Stack: ..., A: uint64 &rarr; ..., uint64
- The largest integer I such that I^2 <= A
- **Cost**: 4
- Availability: v4

## bitlen

- Opcode: 0x93
- Stack: ..., A &rarr; ..., uint64
- The highest set bit in A. If A is a byte-array, it is interpreted as a big-endian unsigned integer. bitlen of 0 is 0, bitlen of 8 is 4
- Availability: v4

bitlen interprets arrays as big-endian integers, unlike setbit/getbit

## exp

- Opcode: 0x94
- Stack: ..., A: uint64, B: uint64 &rarr; ..., uint64
- A raised to the Bth power. Fail if A == B == 0 and on overflow
- Availability: v4

## expw

- Opcode: 0x95
- Stack: ..., A: uint64, B: uint64 &rarr; ..., X: uint64, Y: uint64
- A raised to the Bth power as a 128-bit result in two uint64s. X is the high 64 bits, Y is the low. Fail if A == B == 0 or if the results exceeds 2^128-1
- **Cost**: 10
- Availability: v4

## bsqrt

- Opcode: 0x96
- Stack: ..., A: []byte &rarr; ..., []byte
- The largest integer I such that I^2 <= A. A and I are interpreted as big-endian unsigned integers
- **Cost**: 40
- Availability: v6

## divw

- Opcode: 0x97
- Stack: ..., A: uint64, B: uint64, C: uint64 &rarr; ..., uint64
- A,B / C. Fail if C == 0 or if result overflows.
- Availability: v6

The notation A,B indicates that A and B are interpreted as a uint128 value, with A as the high uint64 and B the low.

## sha3_256

- Opcode: 0x98
- Stack: ..., A: []byte &rarr; ..., []byte
- SHA3_256 hash of value A, yields [32]byte
- **Cost**: 130
- Availability: v7

## bn256_add

- Opcode: 0x99
- Stack: ..., A: []byte, B: []byte &rarr; ..., []byte
- for (curve points A and B) return the curve point A + B
- **Cost**: 70
- Availability: v7

A, B are curve points in G1 group. Each point consists of (X, Y) where X and Y are 256 bit integers, big-endian encoded. The encoded point is 64 bytes from concatenation of 32 byte X and 32 byte Y.

## bn256_scalar_mul

- Opcode: 0x9a
- Stack: ..., A: []byte, B: []byte &rarr; ..., []byte
- for (curve point A, scalar K) return the curve point KA
- **Cost**: 970
- Availability: v7

A is a curve point in G1 Group and encoded as described in `bn256_add`. Scalar K is a big-endian encoded big integer that has no padding zeros.

## bn256_pairing

- Opcode: 0x9b
- Stack: ..., A: []byte, B: []byte &rarr; ..., uint64
- for (points in G1 group G1s, points in G2 group G2s), return whether they are paired => {0 or 1}
- **Cost**: 8700
- Availability: v7

G1s are encoded by the concatenation of encoded G1 points, as described in `bn256_add`. G2s are encoded by the concatenation of encoded G2 points. Each G2 is in form (XA0+i*XA1, YA0+i*YA1) and encoded by big-endian field element XA0, XA1, YA0 and YA1 in sequence.

## b+

- Opcode: 0xa0
- Stack: ..., A: []byte, B: []byte &rarr; ..., []byte
- A plus B. A and B are interpreted as big-endian unsigned integers
- **Cost**: 10
- Availability: v4

## b-

- Opcode: 0xa1
- Stack: ..., A: []byte, B: []byte &rarr; ..., []byte
- A minus B. A and B are interpreted as big-endian unsigned integers. Fail on underflow.
- **Cost**: 10
- Availability: v4

## b/

- Opcode: 0xa2
- Stack: ..., A: []byte, B: []byte &rarr; ..., []byte
- A divided by B (truncated division). A and B are interpreted as big-endian unsigned integers. Fail if B is zero.
- **Cost**: 20
- Availability: v4

## b*

- Opcode: 0xa3
- Stack: ..., A: []byte, B: []byte &rarr; ..., []byte
- A times B. A and B are interpreted as big-endian unsigned integers.
- **Cost**: 20
- Availability: v4

## b<

- Opcode: 0xa4
- Stack: ..., A: []byte, B: []byte &rarr; ..., uint64
- 1 if A is less than B, else 0. A and B are interpreted as big-endian unsigned integers
- Availability: v4

## b>

- Opcode: 0xa5
- Stack: ..., A: []byte, B: []byte &rarr; ..., uint64
- 1 if A is greater than B, else 0. A and B are interpreted as big-endian unsigned integers
- Availability: v4

## b<=

- Opcode: 0xa6
- Stack: ..., A: []byte, B: []byte &rarr; ..., uint64
- 1 if A is less than or equal to B, else 0. A and B are interpreted as big-endian unsigned integers
- Availability: v4

## b>=

- Opcode: 0xa7
- Stack: ..., A: []byte, B: []byte &rarr; ..., uint64
- 1 if A is greater than or equal to B, else 0. A and B are interpreted as big-endian unsigned integers
- Availability: v4

## b==

- Opcode: 0xa8
- Stack: ..., A: []byte, B: []byte &rarr; ..., uint64
- 1 if A is equal to B, else 0. A and B are interpreted as big-endian unsigned integers
- Availability: v4

## b!=

- Opcode: 0xa9
- Stack: ..., A: []byte, B: []byte &rarr; ..., uint64
- 0 if A is equal to B, else 1. A and B are interpreted as big-endian unsigned integers
- Availability: v4

## b%

- Opcode: 0xaa
- Stack: ..., A: []byte, B: []byte &rarr; ..., []byte
- A modulo B. A and B are interpreted as big-endian unsigned integers. Fail if B is zero.
- **Cost**: 20
- Availability: v4

## b|

- Opcode: 0xab
- Stack: ..., A: []byte, B: []byte &rarr; ..., []byte
- A bitwise-or B. A and B are zero-left extended to the greater of their lengths
- **Cost**: 6
- Availability: v4

## b&

- Opcode: 0xac
- Stack: ..., A: []byte, B: []byte &rarr; ..., []byte
- A bitwise-and B. A and B are zero-left extended to the greater of their lengths
- **Cost**: 6
- Availability: v4

## b^

- Opcode: 0xad
- Stack: ..., A: []byte, B: []byte &rarr; ..., []byte
- A bitwise-xor B. A and B are zero-left extended to the greater of their lengths
- **Cost**: 6
- Availability: v4

## b~

- Opcode: 0xae
- Stack: ..., A: []byte &rarr; ..., []byte
- A with all bits inverted
- **Cost**: 4
- Availability: v4

## bzero

- Opcode: 0xaf
- Stack: ..., A: uint64 &rarr; ..., []byte
- zero filled byte-array of length A
- Availability: v4

## log

- Opcode: 0xb0
- Stack: ..., A: []byte &rarr; ...
- write A to log state of the current application
- Availability: v5
- Mode: Application

`log` fails if called more than MaxLogCalls times in a program, or if the sum of logged bytes exceeds 1024 bytes.

## itxn_begin

- Opcode: 0xb1
- Stack: ... &rarr; ...
- begin preparation of a new inner transaction in a new transaction group
- Availability: v5
- Mode: Application

`itxn_begin` initializes Sender to the application address; Fee to the minimum allowable, taking into account MinTxnFee and credit from overpaying in earlier transactions; FirstValid/LastValid to the values in the invoking transaction, and all other fields to zero or empty values.

## itxn_field f

- Opcode: 0xb2 {uint8 transaction field index}
- Stack: ..., A &rarr; ...
- set field F of the current inner transaction to A
- Availability: v5
- Mode: Application

`itxn_field` fails if A is of the wrong type for F, including a byte array of the wrong size for use as an address when F is an address field. `itxn_field` also fails if A is an account, asset, or app that is not _available_, or an attempt is made extend an array field beyond the limit imposed by consensus parameters. (Addresses set into asset params of acfg transactions need not be _available_.)

## itxn_submit

- Opcode: 0xb3
- Stack: ... &rarr; ...
- execute the current inner transaction group. Fail if executing this group would exceed the inner transaction limit, or if any transaction in the group fails.
- Availability: v5
- Mode: Application

`itxn_submit` resets the current transaction so that it can not be resubmitted. A new `itxn_begin` is required to prepare another inner transaction.

## itxn f

- Opcode: 0xb4 {uint8 transaction field index}
- Stack: ... &rarr; ..., any
- field F of the last inner transaction
- Availability: v5
- Mode: Application

## itxna f i

- Opcode: 0xb5 {uint8 transaction field index} {uint8 transaction field array index}
- Stack: ... &rarr; ..., any
- Ith value of the array field F of the last inner transaction
- Availability: v5
- Mode: Application

## itxn_next

- Opcode: 0xb6
- Stack: ... &rarr; ...
- begin preparation of a new inner transaction in the same transaction group
- Availability: v6
- Mode: Application

`itxn_next` initializes the transaction exactly as `itxn_begin` does

## gitxn t f

- Opcode: 0xb7 {uint8 transaction group index} {uint8 transaction field index}
- Stack: ... &rarr; ..., any
- field F of the Tth transaction in the last inner group submitted
- Availability: v6
- Mode: Application

## gitxna t f i

- Opcode: 0xb8 {uint8 transaction group index} {uint8 transaction field index} {uint8 transaction field array index}
- Stack: ... &rarr; ..., any
- Ith value of the array field F from the Tth transaction in the last inner group submitted
- Availability: v6
- Mode: Application

## txnas f

- Opcode: 0xc0 {uint8 transaction field index}
- Stack: ..., A: uint64 &rarr; ..., any
- Ath value of the array field F of the current transaction
- Availability: v5

## gtxnas t f

- Opcode: 0xc1 {uint8 transaction group index} {uint8 transaction field index}
- Stack: ..., A: uint64 &rarr; ..., any
- Ath value of the array field F from the Tth transaction in the current group
- Availability: v5

## gtxnsas f

- Opcode: 0xc2 {uint8 transaction field index}
- Stack: ..., A: uint64, B: uint64 &rarr; ..., any
- Bth value of the array field F from the Ath transaction in the current group
- Availability: v5

## args

- Opcode: 0xc3
- Stack: ..., A: uint64 &rarr; ..., []byte
- Ath LogicSig argument
- Availability: v5
- Mode: Signature

## gloadss

- Opcode: 0xc4
- Stack: ..., A: uint64, B: uint64 &rarr; ..., any
- Bth scratch space value of the Ath transaction in the current group
- Availability: v6
- Mode: Application

## itxnas f

- Opcode: 0xc5 {uint8 transaction field index}
- Stack: ..., A: uint64 &rarr; ..., any
- Ath value of the array field F of the last inner transaction
- Availability: v6
- Mode: Application

## gitxnas t f

- Opcode: 0xc6 {uint8 transaction group index} {uint8 transaction field index}
- Stack: ..., A: uint64 &rarr; ..., any
- Ath value of the array field F from the Tth transaction in the last inner group submitted
- Availability: v6
- Mode: Application
