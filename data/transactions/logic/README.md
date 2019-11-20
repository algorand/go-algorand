# Transaction Execution Approval Language (TEAL)

TEAL is a bytecode based stack language that executes inside Algorand transactions to check the parameters of the transaction and approve the transaction as if by a signature. Programs have read-only access to the transaction they are attached to, transactions in their atomic transaction group, and a few global values. Programs cannot modify or create transactions, only reject or approve them. Approval is signaled by finishing with the stack containing a single non-zero uint64 value.

TEAL programs should be short and run fast as they are run in-line along with signature checking, transaction balance rule checking, and other checks during block assembly and validation. Many useful programs are less than 100 instructions.

## The Stack

The stack starts empty and contains values of either uint64 or bytes (`bytes` are implemented in Go as a []byte slice). Most operations act on the stack, popping arguments from it and pushing results to it.

The maximum stack depth is currently 1000.

## Scratch Space

In addition to the stack there are 256 positions of scratch space, also uint64-bytes union values, accessed by the `load` and `store` ops moving data from or to scratch space, respectively.

## Execution Environment

TEAL runs in Algorand nodes as part of testing a proposed transaction to see if it is valid and authorized to be committed into a block.

If an authorized program executes and finishes with a single non-zero uint64 value on the stack then that program has validated the transaction it is attached to.

The TEAL program has access to data from the transaction it is attached to (`txn` op), any transactions in a transaction group it is part of (`gtxn` op), and a few global values like consensus parameters (`global` op). Some "Args" may be attached to a transaction being validated by a TEAL program. Args are an array of byte strings. A common pattern would be to have the key to unlock some contract as an Arg. Args are recorded on the blockchain and publicly visible when the transaction is submitted to the network.

A program can either authorize some delegated action on a normal private key signed or multisig account or be wholly in charge of a contract account.

* If the account has signed the program (an ed25519 signature on "Program" concatenated with the program bytes) then if the program returns true the transaction is authorized as if the account had signed it. This allows an account to hand out a signed program so that other users can carry out delegated actions which are approved by the program.
* If the SHA512_256 hash of the program (prefixed by "Program") is equal to the transaction Sender address then this is a contract account wholly controlled by the program. No other signature is necessary or possible. The only way to execute a transaction against the contract account is for the program to approve it.

The TEAL bytecode plus the length of any Args must add up to less than 1000 bytes (consensus parameter LogicSigMaxSize). Each TEAL op has an associated cost estimate and the program cost estimate must total less than 20000 (consensus parameter LogicSigMaxCost). Most ops have an estimated cost of 1, but a few slow crypto ops are much higher.



## Constants

Constants are loaded into the environment into storage separate from the stack. They can then be pushed onto the stack by referring to the type and index. This makes for efficient re-use of byte constants used for account addresses, etc.

The assembler will hide most of this, allowing simple use of `int 1234` and `byte 0xcafed00d`. These constants will automatically get assembled into int and byte pages of constants, de-duplicated, and operations to load them from constant storage space inserted.

Constants are loaded into the environment by two opcodes, `intcblock` and `bytecblock`. Both of these use [proto-buf style variable length unsigned int](https://developers.google.com/protocol-buffers/docs/encoding#varint), reproduced [here](#varuint). The `intcblock` opcode is followed by a varuint specifying the length of the array and then that number of varuint. The `bytecblock` opcode is followed by a varuint array length then that number of pairs of (varuint, bytes) length prefixed byte strings. This should efficiently load 32 and 64 byte constants which will be common as addresses, hashes, and signatures.

Constants are pushed onto the stack by `intc`, `intc_[0123]`, `bytec`, and `bytec_[0123]`. The assembler will handle converting `int N` or `byte N` into the appropriate form of the instruction needed.

## Operations

Most operations work with only one type of argument, uint64 or bytes, and panic if the wrong type value is on the stack.
The instruction set was designed to execute calculator-like expressions.
What might be a one line expression with various parenthesized clauses should be efficiently representable in TEAL.

Looping is not possible, by design, to ensure predictably fast execution.
There is a branch instruction (`bnz`, branch if not zero) which allows forward branching only so that some code may be skipped.

Many programs need only a few dozen instructions. The instruction set has some optimization built in. `intc`, `bytec`, and `arg` take an immediate value byte, making a 2-byte op to load a value onto the stack, but they also have single byte versions for loading the most common constant values. Any program will benefit from having a few common values loaded with a smaller one byte opcode. Cryptographic hashes and `ed25519verify` are single byte opcodes with powerful libraries behind them. These operations still take more time than other ops (and this is reflected in the cost of each op and the cost limit of a program) but are efficient in compiled code space.

This summary is supplemented by more detail in the [opcodes document](TEAL_opcodes.md).

Some operations 'panic' and immediately end execution of the program.
A transaction checked by a program that panics is not valid.
A contract account governed by a buggy program might not have a way to get assets back out of it. Code carefully.

### Arithmetic, Logic, and Cryptographic Operations

For one-argument ops, `X` is the last element on the stack, which is typically replaced by a new value.

For two-argument ops, `A` is the previous element on the stack and `B` is the last element on the stack. These typically result in popping A and B from the stack and pushing the result.

`ed25519verify` is currently the only 3 argument opcode and is described in detail in the opcode refrence.

| Op | Description |
| --- | --- |
| `sha256` | SHA256 hash of value X, yields [32]byte |
| `keccak256` | Keccak256 hash of value X, yields [32]byte |
| `sha512_256` | SHA512_256 hash of value X, yields [32]byte |
| `ed25519verify` | for (data A, signature B, pubkey C) verify the signature of ("ProgData" \|\| program_hash \|\| data) against the pubkey => {0 or 1} |
| `+` | A plus B. Panic on overflow. |
| `-` | A minus B. Panic if B > A. |
| `/` | A divided by B. Panic if B == 0. |
| `*` | A times B. Panic on overflow. |
| `<` | A less than B => {0 or 1} |
| `>` | A greater than B => {0 or 1} |
| `<=` | A less than or equal to B => {0 or 1} |
| `>=` | A greater than or equal to B => {0 or 1} |
| `&&` | A is not zero and B is not zero => {0 or 1} |
| `\|\|` | A is not zero or B is not zero => {0 or 1} |
| `==` | A is equal to B => {0 or 1} |
| `!=` | A is not equal to B => {0 or 1} |
| `!` | X == 0 yields 1; else 0 |
| `len` | yields length of byte value X |
| `itob` | converts uint64 X to big endian bytes |
| `btoi` | converts bytes X as big endian to uint64 |
| `%` | A modulo B. Panic if B == 0. |
| `\|` | A bitwise-or B |
| `&` | A bitwise-and B |
| `^` | A bitwise-xor B |
| `~` | bitwise invert value X |
| `mulw` | A times B out to 128-bit long result as low (top) and high uint64 values on the stack |

### Loading Values

Opcodes for getting data onto the stack.

Some of these have immediate data in the byte or bytes after the opcode.

| Op | Description |
| --- | --- |
| `intcblock` | load block of uint64 constants |
| `intc` | push value from uint64 constants to stack by index into constants |
| `intc_0` | push constant 0 from intcblock to stack |
| `intc_1` | push constant 1 from intcblock to stack |
| `intc_2` | push constant 2 from intcblock to stack |
| `intc_3` | push constant 3 from intcblock to stack |
| `bytecblock` | load block of byte-array constants |
| `bytec` | push bytes constant to stack by index into constants |
| `bytec_0` | push constant 0 from bytecblock to stack |
| `bytec_1` | push constant 1 from bytecblock to stack |
| `bytec_2` | push constant 2 from bytecblock to stack |
| `bytec_3` | push constant 3 from bytecblock to stack |
| `arg` | push Args[N] value to stack by index |
| `arg_0` | push Args[0] to stack |
| `arg_1` | push Args[1] to stack |
| `arg_2` | push Args[2] to stack |
| `arg_3` | push Args[3] to stack |
| `txn` | push field from current transaction to stack |
| `gtxn` | push field to the stack from a transaction in the current transaction group |
| `global` | push value from globals to stack |
| `load` | copy a value from scratch space to the stack |
| `store` | pop a value from the stack and store to scratch space |

**Transaction Fields**

| Index | Name | Type | Notes |
| --- | --- | --- | --- |
| 0 | Sender | []byte | 32 byte address |
| 1 | Fee | uint64 | micro-Algos |
| 2 | FirstValid | uint64 | round number |
| 3 | FirstValidTime | uint64 | Causes program to fail; reserved for future use. |
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
| 22 | GroupIndex | uint64 | Position of this transaction within an atomic transaction group. A stand-alone transaction is implicitly element 0 in a group of 1. |
| 23 | TxID | []byte | The computed ID for this transaction. 32 bytes. |


Additional details in the [opcodes document](TEAL_opcodes.md#txn) on the `txn` op.

**Global Fields**

Global fields are fields that are common to all the transactions in the group. In particular it includes consensus parameters.

| Index | Name | Type | Notes |
| --- | --- | --- | --- |
| 0 | MinTxnFee | uint64 | micro Algos |
| 1 | MinBalance | uint64 | micro Algos |
| 2 | MaxTxnLife | uint64 | rounds |
| 3 | ZeroAddress | []byte | 32 byte address of all zero bytes |
| 4 | GroupSize | uint64 | Number of transactions in this atomic transaction group. At least 1. |



### Flow Control

| Op | Description |
| --- | --- |
| `err` | Error. Panic immediately. This is primarily a fencepost against accidental zero bytes getting compiled into programs. |
| `bnz` | branch if value X is not zero |
| `pop` | discard value X from stack |
| `dup` | duplicate last value on stack |

# Assembler Syntax

The assembler parses line by line. Ops that just use the stack appear on a line by themselves. Ops that take arguments are the op and then whitespace and then any argument or arguments.

"`//`" prefixes a line comment.

## Constants and Pseudo-Ops

A few pseudo-ops simplify writing code. `int` and `byte` and `addr` followed by a constant record the constant to a `intcblock` or `bytecblock` at the beginning of code and insert an `intc` or `bytec` reference where the instruction appears to load that value. `addr` parses an Algorand account address base32 and converts it to a regular bytes constant.

`byte` constants are:
```
byte base64 AAAA...
byte b64 AAAA...
byte base64(AAAA...)
byte b64(AAAA...)
byte base32 AAAA...
byte b32 AAAA...
byte base32(AAAA...)
byte b32(AAAA...)
byte 0x0123456789abcdef...
```

`int` constants may be `0x` prefixed for hex, `0` prefixed for octal, or decimal numbers.

`intcblock` may be explictly assembled. It will conflict with the assembler gathering `int` pseudo-ops into a `intcblock` program prefix, but may be used if code only has explicit `intc` references. `intcblock` should be followed by space separated int constants all on one line.

`bytecblock` may be explicitly assembled. It will conflict with the assembler if there are any `byte` pseudo-ops but may be used if only explicit `bytec` references are used. `bytecblock` should be followed with byte constants all on one line, either 'encoding value' pairs (`b64 AAA...`) or 0x prefix or function-style values (`base64(...)`).

## Labels and Branches

A label is defined by any string not some other op or keyword and ending in ':'. A label can be an argument (without the trailing ':') to a branch instruction.

Example:
```
int 1
bnz safe
err
safe:
pop
```

# Encoding and Versioning

A program starts with a varuint declaring the version of the compiled code. Any addition, removal, or change of opcode behavior increments the version. For the most part opcode behavior should not change, addition will be infrequent (not likely more often than every three months and less often as the language matures), and removal should be very rare.

For version 1, subsequent bytes after the varuint are program opcode bytes. Future versions could put other metadata following the version identifier.

## Varuint

A '[proto-buf style variable length unsigned int](https://developers.google.com/protocol-buffers/docs/encoding#varint)' is encoded with 7 data bits per byte and the high bit is 1 if there is a following byte and 0 for the last byte. The lowest order 7 bits are in the first byte, followed by successively higher groups of 7 bits.

# What TEAL Cannot Do

Current design and implementation limitations to be aware of.

* TEAL cannot create or change a transaction, only approve or reject.
* TEAL cannot lookup balances of Algos or other assets. (Standard transaction accounting will apply after TEAL has run and authorized a transaction. A TEAL-approved transaction could still be invalid by other accounting rules just as a standard signed transaction could be invalid. e.g. I can't give away money I don't have.)
* TEAL cannot access information in previous blocks. TEAL cannot access most information in other transactions in the current block. (TEAL can access fields of the transaction it is attached to and the transactions in an atomic transaction group.)
* TEAL cannot know exactly what round the current transaction will commit in (but it is somewhere in FirstValid through LastValid).
* TEAL cannot know exactly what time its transaction is committed.
* TEAL cannot loop. Its branch instruction `bnz` "branch if not zero" can only branch forward so as to skip some code.
* TEAL cannot recurse. There is no subroutine jump operation.
