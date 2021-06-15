# Transaction Execution Approval Language (TEAL)

TEAL is a bytecode based stack language that executes inside Algorand transactions. TEAL programs can be used to check the parameters of the transaction and approve the transaction as if by a signature. This use of TEAL is called a _LogicSig_. Starting with v2, TEAL programs may
also execute as _Applications_ which are invoked with explicit application call transactions. Programs have read-only access to the transaction they are attached to, transactions in their atomic transaction group, and a few global values. In addition, _Application_ programs have access to limited state that is global to the application and per-account local state for each account that has opted-in to the application. Programs cannot modify or create transactions, only reject or approve them. For both types of program, approval is signaled by finishing with the stack containing a single non-zero uint64 value.

## The Stack

The stack starts empty and contains values of either uint64 or bytes (`bytes` are implemented in Go as a []byte slice). Most operations act on the stack, popping arguments from it and pushing results to it.

The maximum stack depth is currently 1000.

## Scratch Space

In addition to the stack there are 256 positions of scratch space, also uint64-bytes union values, accessed by the `load` and `store` ops moving data from or to scratch space, respectively.

## Execution Modes

Starting from version 2 TEAL evaluator can run programs in two modes:
1. LogicSig (stateless)
2. Application run (stateful)

Differences between modes include:
1. Max program length (consensus parameters LogicSigMaxSize, MaxAppTotalProgramLen & MaxExtraAppProgramPages)
2. Max program cost (consensus parameters LogicSigMaxCost, MaxAppProgramCost)
3. Opcode availability. For example, all stateful operations are only available in stateful mode. Refer to [opcodes document](TEAL_opcodes.md) for details.

## Execution Environment for LogicSigs

TEAL LogicSigs run in Algorand nodes as part of testing a proposed transaction to see if it is valid and authorized to be committed into a block.

If an authorized program executes and finishes with a single non-zero uint64 value on the stack then that program has validated the transaction it is attached to.

The TEAL program has access to data from the transaction it is attached to (`txn` op), any transactions in a transaction group it is part of (`gtxn` op), and a few global values like consensus parameters (`global` op). Some "Args" may be attached to a transaction being validated by a TEAL program. Args are an array of byte strings. A common pattern would be to have the key to unlock some contract as an Arg. Args are recorded on the blockchain and publicly visible when the transaction is submitted to the network.

A program can either authorize some delegated action on a normal private key signed or multisig account or be wholly in charge of a contract account.

* If the account has signed the program (an ed25519 signature on "Program" concatenated with the program bytes) then if the program returns true the transaction is authorized as if the account had signed it. This allows an account to hand out a signed program so that other users can carry out delegated actions which are approved by the program.
* If the SHA512_256 hash of the program (prefixed by "Program") is equal to the transaction Sender address then this is a contract account wholly controlled by the program. No other signature is necessary or possible. The only way to execute a transaction against the contract account is for the program to approve it.

The TEAL bytecode plus the length of any Args must add up to less than 1000 bytes (consensus parameter LogicSigMaxSize). Each TEAL op has an associated cost and the program cost must total less than 20000 (consensus parameter LogicSigMaxCost). Most ops have a cost of 1, but a few slow crypto ops are much higher. Prior to v4, the program's cost was estimated as the static sum of all the opcode costs in the program (whether they were actually executed or not). Beginning with v4, the program's cost is tracked dynamically, while being evaluated. If the program exceeds its budget, it fails.

## Constants

Constants are loaded into the environment into storage separate from the stack. They can then be pushed onto the stack by referring to the type and index. This makes for efficient re-use of byte constants used for account addresses, etc. Constants that are not reused can be pushed with `pushint` or `pushbytes`.

The assembler will hide most of this, allowing simple use of `int 1234` and `byte 0xcafed00d`. These constants will automatically get assembled into int and byte pages of constants, de-duplicated, and operations to load them from constant storage space inserted.

Constants are loaded into the environment by two opcodes, `intcblock` and `bytecblock`. Both of these use [proto-buf style variable length unsigned int](https://developers.google.com/protocol-buffers/docs/encoding#varint), reproduced [here](#varuint). The `intcblock` opcode is followed by a varuint specifying the length of the array and then that number of varuint. The `bytecblock` opcode is followed by a varuint array length then that number of pairs of (varuint, bytes) length prefixed byte strings. This should efficiently load 32 and 64 byte constants which will be common as addresses, hashes, and signatures.

Constants are pushed onto the stack by `intc`, `intc_[0123]`, `pushint`, `bytec`, `bytec_[0123]`, and `pushbytes`. The assembler will handle converting `int N` or `byte N` into the appropriate form of the instruction needed.

### Named Integer Constants

@@ named_integer_constants.md @@

## Operations

Most operations work with only one type of argument, uint64 or bytes, and panic if the wrong type value is on the stack.

Many instructions accept values to designate Accounts, Assets, or Applications. Beginning with TEAL v4, these values may always be given as an _offset_ in the corresponding Txn fields (Txn.Accounts, Txn.ForeignAssets, Txn.ForeignApps) _or_ as the value itself (a bytes address for Accounts, or a uint64 ID). The values, however, must still be present in the Txn fields. Before TEAL v4, most opcodes required the use of an offset, except for reading account local values of assets or applications, which accepted the IDs directly and did not require the ID to be present in they corresponding _Foreign_ array. (Note that beginning with TEAL v4, those IDs are required to be present in their corresponding _Foreign_ array.) See individual opcodes for details. In the case of account offsets or application offsets, 0 is specially defined to Txn.Sender or the ID of the current application, respectively.

Many programs need only a few dozen instructions. The instruction set has some optimization built in. `intc`, `bytec`, and `arg` take an immediate value byte, making a 2-byte op to load a value onto the stack, but they also have single byte versions for loading the most common constant values. Any program will benefit from having a few common values loaded with a smaller one byte opcode. Cryptographic hashes and `ed25519verify` are single byte opcodes with powerful libraries behind them. These operations still take more time than other ops (and this is reflected in the cost of each op and the cost limit of a program) but are efficient in compiled code space.

This summary is supplemented by more detail in the [opcodes document](TEAL_opcodes.md).

Some operations 'panic' and immediately end execution of the program.
A transaction checked by a program that panics is not valid.
A contract account governed by a buggy program might not have a way to get assets back out of it. Code carefully.

### Arithmetic, Logic, and Cryptographic Operations

For one-argument ops, `X` is the last element on the stack, which is typically replaced by a new value.

For two-argument ops, `A` is the penultimate element on the stack and `B` is the top of the stack. These typically result in popping A and B from the stack and pushing the result.

For three-argument ops, `A` is the element two below the top, `B` is the penultimate stack element and `C` is the top of the stack. These operations typically pop A, B, and C from the stack and push the result.

@@ Arithmetic.md @@

These opcodes take byte-array values that are interpreted as
big-endian unsigned integers.  For mathematical operators, the
returned values are the shortest byte-array that can represent the
returned value.  For example, the zero value is the empty
byte-array. For comparison operators, the returned value is a uint64

Input lengths are limited to a maximum length 64 bytes, which
represents a 512 bit unsigned integer. Output lengths are not
explicitly restricted, though only `b*` and `b+` can produce a larger
output than their inputs, so there is an implicit length limit of 128
bytes on outputs.

@@ Byteslice_Arithmetic.md @@

These opcodes operate on the bits of byte-array values.  The shorter
array is interpeted as though left padded with zeros until it is the
same length as the other input.  The returned values are the same
length as the longest input.  Therefore, unlike array arithmetic,
these results may contain leading zero bytes.

@@ Byteslice_Logic.md @@


### Loading Values

Opcodes for getting data onto the stack.

Some of these have immediate data in the byte or bytes after the opcode.

@@ Loading_Values.md @@

**Transaction Fields**

@@ txn_fields.md @@

Additional details in the [opcodes document](TEAL_opcodes.md#txn) on the `txn` op.

**Global Fields**

Global fields are fields that are common to all the transactions in the group. In particular it includes consensus parameters.

@@ global_fields.md @@

**Asset Fields**

Asset fields include `AssetHolding` and `AssetParam` fields that are used in `asset_read_*` opcodes

@@ asset_holding_fields.md @@

@@ asset_params_fields.md @@

### Flow Control

@@ Flow_Control.md @@

### State Access

@@ State_Access.md @@

# Assembler Syntax

The assembler parses line by line. Ops that just use the stack appear on a line by themselves. Ops that take arguments are the op and then whitespace and then any argument or arguments.

The first line may contain a special version pragma `#pragma version X`, which directs the assembler to generate TEAL bytecode targeting a certain version. For instance, `#pragma version 2` produces bytecode targeting TEAL v2. By default, the assembler targets TEAL v1.

Subsequent lines may contain other pragma declarations (i.e., `#pragma <some-specification>`), pertaining to checks that the assembler should perform before agreeing to emit the program bytes, specific optimizations, etc. Those declarations are optional and cannot alter the semantics as described in this document.

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
byte "\x01\x02"
byte "string literal"
```

`int` constants may be `0x` prefixed for hex, `0` prefixed for octal, or decimal numbers.

`intcblock` may be explictly assembled. It will conflict with the assembler gathering `int` pseudo-ops into a `intcblock` program prefix, but may be used if code only has explicit `intc` references. `intcblock` should be followed by space separated int constants all on one line.

`bytecblock` may be explicitly assembled. It will conflict with the assembler if there are any `byte` pseudo-ops but may be used if only explicit `bytec` references are used. `bytecblock` should be followed with byte constants all on one line, either 'encoding value' pairs (`b64 AAA...`) or 0x prefix or function-style values (`base64(...)`) or string literal values.

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

It is important to prevent newly-introduced transaction fields from breaking assumptions made by older versions of TEAL. If one of the transactions in a group will execute a TEAL program whose version predates a given field, that field must not be set anywhere in the transaction group, or the group will be rejected. For example, executing a TEAL version 1 program on a transaction with RekeyTo set to a nonzero address will cause the program to fail, regardless of the other contents of the program itself.

This requirement is enforced as follows:

* For every transaction, compute the earliest TEAL version that supports all the fields and and values in this transaction. For example, a transaction with a nonzero RekeyTo field will have version (at least) 2.

* Compute the largest version number across all the transactions in a group (of size 1 or more), call it `maxVerNo`. If any transaction in this group has a TEAL program with a version smaller than `maxVerNo`, then that TEAL program will fail.

## Varuint

A '[proto-buf style variable length unsigned int](https://developers.google.com/protocol-buffers/docs/encoding#varint)' is encoded with 7 data bits per byte and the high bit is 1 if there is a following byte and 0 for the last byte. The lowest order 7 bits are in the first byte, followed by successively higher groups of 7 bits.

# What TEAL Cannot Do

Design and implementation limitations to be aware of with various versions of TEAL.

* TEAL cannot create or change a transaction, only approve or reject.
* Stateless TEAL cannot lookup balances of Algos or other assets. (Standard transaction accounting will apply after TEAL has run and authorized a transaction. A TEAL-approved transaction could still be invalid by other accounting rules just as a standard signed transaction could be invalid. e.g. I can't give away money I don't have.)
* TEAL cannot access information in previous blocks. TEAL cannot access most information in other transactions in the current block. (TEAL can access fields of the transaction it is attached to and the transactions in an atomic transaction group.)
* TEAL cannot know exactly what round the current transaction will commit in (but it is somewhere in FirstValid through LastValid).
* TEAL cannot know exactly what time its transaction is committed.
* TEAL cannot loop prior to v4. In v3 and prior, the branch instructions `bnz` "branch if not zero", `bz` "branch if zero" and `b` "branch" can only branch forward so as to skip some code.
* Until v4, TEAL had no notion of subroutines (and therefore no recursion). As of v4, use `callsub` and `retsub`.
* TEAL cannot make indirect jumps. `b`, `bz`, `bnz`, and `callsub` jump to an immediately specified address, and `retsub` jumps to the address currently on the top of the call stack, which is manipulated only by previous calls to `callsub`.
