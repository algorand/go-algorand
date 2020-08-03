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
- SHA256 hash of value X, yields [32]byte
- **Cost**:
   - 7 (LogicSigVersion = 1)
   - 35 (LogicSigVersion = 2)

## keccak256

- Opcode: 0x02
- Pops: *... stack*, []byte
- Pushes: []byte
- Keccak256 hash of value X, yields [32]byte
- **Cost**:
   - 26 (LogicSigVersion = 1)
   - 130 (LogicSigVersion = 2)

## sha512_256

- Opcode: 0x03
- Pops: *... stack*, []byte
- Pushes: []byte
- SHA512_256 hash of value X, yields [32]byte
- **Cost**:
   - 9 (LogicSigVersion = 1)
   - 45 (LogicSigVersion = 2)

## ed25519verify

- Opcode: 0x04
- Pops: *... stack*, {[]byte A}, {[]byte B}, {[]byte C}
- Pushes: uint64
- for (data A, signature B, pubkey C) verify the signature of ("ProgData" || program_hash || data) against the pubkey => {0 or 1}
- **Cost**: 1900
- Mode: Signature

The 32 byte public key is the last element on the stack, preceded by the 64 byte signature at the second-to-last element on the stack, preceded by the data which was signed at the third-to-last element on the stack.

## +

- Opcode: 0x08
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64
- A plus B. Panic on overflow.

Overflow is an error condition which halts execution and fails the transaction. Full precision is available from `addw`.

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

Overflow is an error condition which halts execution and fails the transaction. Full precision is available from `mulw`.

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
- yields length of byte value X

## itob

- Opcode: 0x16
- Pops: *... stack*, uint64
- Pushes: []byte
- converts uint64 X to big endian bytes

## btoi

- Opcode: 0x17
- Pops: *... stack*, []byte
- Pushes: uint64
- converts bytes X as big endian to uint64

`btoi` panics if the input is longer than 8 bytes.

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
- bitwise invert value X

## mulw

- Opcode: 0x1d
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64, uint64
- A times B out to 128-bit long result as low (top) and high uint64 values on the stack

## addw

- Opcode: 0x1e
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64, uint64
- A plus B out to 128-bit long result as sum (top) and carry-bit uint64 values on the stack
- LogicSigVersion >= 2

## intcblock

- Opcode: 0x20 {varuint length} [{varuint value}, ...]
- Pops: _None_
- Pushes: _None_
- load block of uint64 constants

`intcblock` loads following program bytes into an array of integer constants in the evaluator. These integer constants can be referred to by `intc` and `intc_*` which will push the value onto the stack. Subsequent calls to `intcblock` reset and replace the integer constants available to the script.

## intc

- Opcode: 0x21 {uint8 int constant index}
- Pops: _None_
- Pushes: uint64
- push value from uint64 constants to stack by index into constants

## intc_0

- Opcode: 0x22
- Pops: _None_
- Pushes: uint64
- push constant 0 from intcblock to stack

## intc_1

- Opcode: 0x23
- Pops: _None_
- Pushes: uint64
- push constant 1 from intcblock to stack

## intc_2

- Opcode: 0x24
- Pops: _None_
- Pushes: uint64
- push constant 2 from intcblock to stack

## intc_3

- Opcode: 0x25
- Pops: _None_
- Pushes: uint64
- push constant 3 from intcblock to stack

## bytecblock

- Opcode: 0x26 {varuint length} [({varuint value length} bytes), ...]
- Pops: _None_
- Pushes: _None_
- load block of byte-array constants

`bytecblock` loads the following program bytes into an array of byte string constants in the evaluator. These constants can be referred to by `bytec` and `bytec_*` which will push the value onto the stack. Subsequent calls to `bytecblock` reset and replace the bytes constants available to the script.

## bytec

- Opcode: 0x27 {uint8 byte constant index}
- Pops: _None_
- Pushes: []byte
- push bytes constant to stack by index into constants

## bytec_0

- Opcode: 0x28
- Pops: _None_
- Pushes: []byte
- push constant 0 from bytecblock to stack

## bytec_1

- Opcode: 0x29
- Pops: _None_
- Pushes: []byte
- push constant 1 from bytecblock to stack

## bytec_2

- Opcode: 0x2a
- Pops: _None_
- Pushes: []byte
- push constant 2 from bytecblock to stack

## bytec_3

- Opcode: 0x2b
- Pops: _None_
- Pushes: []byte
- push constant 3 from bytecblock to stack

## arg

- Opcode: 0x2c {uint8 arg index N}
- Pops: _None_
- Pushes: []byte
- push Args[N] value to stack by index
- Mode: Signature

## arg_0

- Opcode: 0x2d
- Pops: _None_
- Pushes: []byte
- push Args[0] to stack
- Mode: Signature

## arg_1

- Opcode: 0x2e
- Pops: _None_
- Pushes: []byte
- push Args[1] to stack
- Mode: Signature

## arg_2

- Opcode: 0x2f
- Pops: _None_
- Pushes: []byte
- push Args[2] to stack
- Mode: Signature

## arg_3

- Opcode: 0x30
- Pops: _None_
- Pushes: []byte
- push Args[3] to stack
- Mode: Signature

## txn

- Opcode: 0x31 {uint8 transaction field index}
- Pops: _None_
- Pushes: any
- push field from current transaction to stack

`txn` Fields:

| Index | Name | Type | Notes |
| --- | --- | --- | --- |
| 0 | Sender | []byte | 32 byte address |
| 1 | Fee | uint64 | micro-Algos |
| 2 | FirstValid | uint64 | round number |
| 3 | FirstValidTime | uint64 | Causes program to fail; reserved for future use |
| 4 | LastValid | uint64 | round number |
| 5 | Note | []byte |  |
| 6 | Lease | []byte |  |
| 7 | Receiver | []byte | 32 byte address |
| 8 | Amount | uint64 | micro-Algos |
| 9 | CloseRemainderTo | []byte | 32 byte address |
| 10 | VotePK | []byte | 32 byte address |
| 11 | SelectionPK | []byte | 32 byte address |
| 12 | VoteFirst | uint64 |  |
| 13 | VoteLast | uint64 |  |
| 14 | VoteKeyDilution | uint64 |  |
| 15 | Type | []byte |  |
| 16 | TypeEnum | uint64 | See table below |
| 17 | XferAsset | uint64 | Asset ID |
| 18 | AssetAmount | uint64 | value in Asset's units |
| 19 | AssetSender | []byte | 32 byte address. Causes clawback of all value of asset from AssetSender if Sender is the Clawback address of the asset. |
| 20 | AssetReceiver | []byte | 32 byte address |
| 21 | AssetCloseTo | []byte | 32 byte address |
| 22 | GroupIndex | uint64 | Position of this transaction within an atomic transaction group. A stand-alone transaction is implicitly element 0 in a group of 1 |
| 23 | TxID | []byte | The computed ID for this transaction. 32 bytes. |
| 24 | ApplicationID | uint64 | ApplicationID from ApplicationCall transaction. LogicSigVersion >= 2. |
| 25 | OnCompletion | uint64 | ApplicationCall transaction on completion action. LogicSigVersion >= 2. |
| 26 | ApplicationArgs | []byte | Arguments passed to the application in the ApplicationCall transaction. LogicSigVersion >= 2. |
| 27 | NumAppArgs | uint64 | Number of ApplicationArgs. LogicSigVersion >= 2. |
| 28 | Accounts | []byte | Accounts listed in the ApplicationCall transaction. LogicSigVersion >= 2. |
| 29 | NumAccounts | uint64 | Number of Accounts. LogicSigVersion >= 2. |
| 30 | ApprovalProgram | []byte | Approval program. LogicSigVersion >= 2. |
| 31 | ClearStateProgram | []byte | Clear state program. LogicSigVersion >= 2. |
| 32 | RekeyTo | []byte | 32 byte Sender's new AuthAddr. LogicSigVersion >= 2. |
| 33 | ConfigAsset | uint64 | Asset ID in asset config transaction. LogicSigVersion >= 2. |
| 34 | ConfigAssetTotal | uint64 | Total number of units of this asset created. LogicSigVersion >= 2. |
| 35 | ConfigAssetDecimals | uint64 | Number of digits to display after the decimal place when displaying the asset. LogicSigVersion >= 2. |
| 36 | ConfigAssetDefaultFrozen | uint64 | Whether the asset's slots are frozen by default or not, 0 or 1. LogicSigVersion >= 2. |
| 37 | ConfigAssetUnitName | []byte | Unit name of the asset. LogicSigVersion >= 2. |
| 38 | ConfigAssetName | []byte | The asset name. LogicSigVersion >= 2. |
| 39 | ConfigAssetURL | []byte | URL. LogicSigVersion >= 2. |
| 40 | ConfigAssetMetadataHash | []byte | 32 byte commitment to some unspecified asset metadata. LogicSigVersion >= 2. |
| 41 | ConfigAssetManager | []byte | 32 byte address. LogicSigVersion >= 2. |
| 42 | ConfigAssetReserve | []byte | 32 byte address. LogicSigVersion >= 2. |
| 43 | ConfigAssetFreeze | []byte | 32 byte address. LogicSigVersion >= 2. |
| 44 | ConfigAssetClawback | []byte | 32 byte address. LogicSigVersion >= 2. |
| 45 | FreezeAsset | uint64 | Asset ID being frozen or un-frozen. LogicSigVersion >= 2. |
| 46 | FreezeAssetAccount | []byte | 32 byte address of the account whose asset slot is being frozen or un-frozen. LogicSigVersion >= 2. |
| 47 | FreezeAssetFrozen | uint64 | The new frozen value, 0 or 1. LogicSigVersion >= 2. |


TypeEnum mapping:

| Index | "Type" string | Description |
| --- | --- | --- |
| 0 | unknown | Unknown type. Invalid transaction |
| 1 | pay | Payment |
| 2 | keyreg | KeyRegistration |
| 3 | acfg | AssetConfig |
| 4 | axfer | AssetTransfer |
| 5 | afrz | AssetFreeze |
| 6 | appl | ApplicationCall |


FirstValidTime causes the program to fail. The field is reserved for future use.

## global

- Opcode: 0x32 {uint8 global field index}
- Pops: _None_
- Pushes: any
- push value from globals to stack

`global` Fields:

| Index | Name | Type | Notes |
| --- | --- | --- | --- |
| 0 | MinTxnFee | uint64 | micro Algos |
| 1 | MinBalance | uint64 | micro Algos |
| 2 | MaxTxnLife | uint64 | rounds |
| 3 | ZeroAddress | []byte | 32 byte address of all zero bytes |
| 4 | GroupSize | uint64 | Number of transactions in this atomic transaction group. At least 1 |
| 5 | LogicSigVersion | uint64 | Maximum supported TEAL version. LogicSigVersion >= 2. |
| 6 | Round | uint64 | Current round number. LogicSigVersion >= 2. |
| 7 | LatestTimestamp | uint64 | Last confirmed block UNIX timestamp. Fails if negative. LogicSigVersion >= 2. |
| 8 | CurrentApplicationID | uint64 | ID of current application executing. Fails if no such application is executing. LogicSigVersion >= 2. |


## gtxn

- Opcode: 0x33 {uint8 transaction group index}{uint8 transaction field index}
- Pops: _None_
- Pushes: any
- push field to the stack from a transaction in the current transaction group

for notes on transaction fields available, see `txn`. If this transaction is _i_ in the group, `gtxn i field` is equivalent to `txn field`.

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

## txna

- Opcode: 0x36 {uint8 transaction field index}{uint8 transaction field array index}
- Pops: _None_
- Pushes: any
- push value of an array field from current transaction to stack
- LogicSigVersion >= 2

## gtxna

- Opcode: 0x37 {uint8 transaction group index}{uint8 transaction field index}{uint8 transaction field array index}
- Pops: _None_
- Pushes: any
- push value of a field to the stack from a transaction in the current transaction group
- LogicSigVersion >= 2

## bnz

- Opcode: 0x40 {0..0x7fff forward branch offset, big endian}
- Pops: *... stack*, uint64
- Pushes: _None_
- branch if value X is not zero

The `bnz` instruction opcode 0x40 is followed by two immediate data bytes which are a high byte first and low byte second which together form a 16 bit offset which the instruction may branch to. For a bnz instruction at `pc`, if the last element of the stack is not zero then branch to instruction at `pc + 3 + N`, else proceed to next instruction at `pc + 3`. Branch targets must be well aligned instructions. (e.g. Branching to the second byte of a 2 byte op will be rejected.) Branch offsets are currently limited to forward branches only, 0-0x7fff. A future expansion might make this a signed 16 bit integer allowing for backward branches and looping.

At LogicSigVersion 2 it became allowed to branch to the end of the program exactly after the last instruction: bnz to byte N (with 0-indexing) was illegal for a TEAL program with N bytes before LogicSigVersion 2, and is legal after it. This change eliminates the need for a last instruction of no-op as a branch target at the end. (Branching beyond the end--in other words, to a byte larger than N--is still illegal and will cause the program to fail.)

## bz

- Opcode: 0x41 {0..0x7fff forward branch offset, big endian}
- Pops: *... stack*, uint64
- Pushes: _None_
- branch if value X is zero
- LogicSigVersion >= 2

See `bnz` for details on how branches work. `bz` inverts the behavior of `bnz`.

## b

- Opcode: 0x42 {0..0x7fff forward branch offset, big endian}
- Pops: _None_
- Pushes: _None_
- branch unconditionally to offset
- LogicSigVersion >= 2

See `bnz` for details on how branches work. `b` always jumps to the offset.

## return

- Opcode: 0x43
- Pops: *... stack*, uint64
- Pushes: _None_
- use last value on stack as success value; end
- LogicSigVersion >= 2

## pop

- Opcode: 0x48
- Pops: *... stack*, any
- Pushes: _None_
- discard value X from stack

## dup

- Opcode: 0x49
- Pops: *... stack*, any
- Pushes: any, any
- duplicate last value on stack

## dup2

- Opcode: 0x4a
- Pops: *... stack*, {any A}, {any B}
- Pushes: any, any, any, any
- duplicate two last values on stack: A, B -> A, B, A, B
- LogicSigVersion >= 2

## concat

- Opcode: 0x50
- Pops: *... stack*, {[]byte A}, {[]byte B}
- Pushes: []byte
- pop two byte strings A and B and join them, push the result
- LogicSigVersion >= 2

`concat` panics if the result would be greater than 4096 bytes.

## substring

- Opcode: 0x51 {uint8 start position}{uint8 end position}
- Pops: *... stack*, []byte
- Pushes: []byte
- pop a byte string X. For immediate values in 0..255 M and N: extract a range of bytes from it starting at M up to but not including N, push the substring result. If N < M, or either is larger than the string length, the program fails
- LogicSigVersion >= 2

## substring3

- Opcode: 0x52
- Pops: *... stack*, {[]byte A}, {uint64 B}, {uint64 C}
- Pushes: []byte
- pop a byte string A and two integers B and C. Extract a range of bytes from A starting at B up to but not including C, push the substring result. If C < B, or either is larger than the string length, the program fails
- LogicSigVersion >= 2

## balance

- Opcode: 0x60
- Pops: *... stack*, uint64
- Pushes: uint64
- get balance for the requested account specified by Txn.Accounts[A] in microalgos. A is specified as an account index in the Accounts field of the ApplicationCall transaction, zero index means the sender
- LogicSigVersion >= 2
- Mode: Application

## app_opted_in

- Opcode: 0x61
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64
- check if account specified by Txn.Accounts[A] opted in for the application B => {0 or 1}
- LogicSigVersion >= 2
- Mode: Application

params: account index, application id (top of the stack on opcode entry). Return: 1 if opted in and 0 otherwise.

## app_local_get

- Opcode: 0x62
- Pops: *... stack*, {uint64 A}, {[]byte B}
- Pushes: any
- read from account specified by Txn.Accounts[A] from local state of the current application key B => value
- LogicSigVersion >= 2
- Mode: Application

params: account index, state key. Return: value. The value is zero if the key does not exist.

## app_local_get_ex

- Opcode: 0x63
- Pops: *... stack*, {uint64 A}, {uint64 B}, {[]byte C}
- Pushes: uint64, any
- read from account specified by Txn.Accounts[A] from local state of the application B key C => {0 or 1 (top), value}
- LogicSigVersion >= 2
- Mode: Application

params: account index, application id, state key. Return: did_exist flag (top of the stack, 1 if exist and 0 otherwise), value.

## app_global_get

- Opcode: 0x64
- Pops: *... stack*, []byte
- Pushes: any
- read key A from global state of a current application => value
- LogicSigVersion >= 2
- Mode: Application

params: state key. Return: value. The value is zero if the key does not exist.

## app_global_get_ex

- Opcode: 0x65
- Pops: *... stack*, {uint64 A}, {[]byte B}
- Pushes: uint64, any
- read from application Txn.ForeignApps[A] global state key B => {0 or 1 (top), value}. A is specified as an account index in the ForeignApps field of the ApplicationCall transaction, zero index means this app
- LogicSigVersion >= 2
- Mode: Application

params: application index, state key. Return: value. Application index is

## app_local_put

- Opcode: 0x66
- Pops: *... stack*, {uint64 A}, {[]byte B}, {any C}
- Pushes: _None_
- write to account specified by Txn.Accounts[A] to local state of a current application key B with value C
- LogicSigVersion >= 2
- Mode: Application

params: account index, state key, value.

## app_global_put

- Opcode: 0x67
- Pops: *... stack*, {[]byte A}, {any B}
- Pushes: _None_
- write key A and value B to global state of the current application
- LogicSigVersion >= 2
- Mode: Application

## app_local_del

- Opcode: 0x68
- Pops: *... stack*, {uint64 A}, {[]byte B}
- Pushes: _None_
- delete from account specified by Txn.Accounts[A] local state key B of the current application
- LogicSigVersion >= 2
- Mode: Application

params: account index, state key.

## app_global_del

- Opcode: 0x69
- Pops: *... stack*, []byte
- Pushes: _None_
- delete key A from a global state of the current application
- LogicSigVersion >= 2
- Mode: Application

params: state key.

## asset_holding_get

- Opcode: 0x70 {uint8 asset holding field index}
- Pops: *... stack*, {uint64 A}, {uint64 B}
- Pushes: uint64, any
- read from account specified by Txn.Accounts[A] and asset B holding field X (imm arg) => {0 or 1 (top), value}
- LogicSigVersion >= 2
- Mode: Application

`asset_holding_get` Fields:

| Index | Name | Type | Notes |
| --- | --- | --- | --- |
| 0 | AssetBalance | uint64 | Amount of the asset unit held by this account |
| 1 | AssetFrozen | uint64 | Is the asset frozen or not |


params: account index, asset id. Return: did_exist flag (1 if exist and 0 otherwise), value.

## asset_params_get

- Opcode: 0x71 {uint8 asset params field index}
- Pops: *... stack*, uint64
- Pushes: uint64, any
- read from asset Txn.ForeignAssets[A] params field X (imm arg) => {0 or 1 (top), value}
- LogicSigVersion >= 2
- Mode: Application

`asset_params_get` Fields:

| Index | Name | Type | Notes |
| --- | --- | --- | --- |
| 0 | AssetTotal | uint64 | Total number of units of this asset |
| 1 | AssetDecimals | uint64 | See AssetParams.Decimals |
| 2 | AssetDefaultFrozen | uint64 | Frozen by default or not |
| 3 | AssetUnitName | []byte | Asset unit name |
| 4 | AssetName | []byte | Asset name |
| 5 | AssetURL | []byte | URL with additional info about the asset |
| 6 | AssetMetadataHash | []byte | Arbitrary commitment |
| 7 | AssetManager | []byte | Manager commitment |
| 8 | AssetReserve | []byte | Reserve address |
| 9 | AssetFreeze | []byte | Freeze address |
| 10 | AssetClawback | []byte | Clawback address |


params: txn.ForeignAssets offset. Return: did_exist flag (1 if exist and 0 otherwise), value.
