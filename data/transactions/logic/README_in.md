# The Algorand Virtual Machine (AVM) and TEAL.

The AVM is a bytecode based stack interpreter that executes programs
associated with Algorand transactions. TEAL is an assembly language
syntax for specifying a program that is ultimately converted to AVM
bytecode. These programs can be used to check the parameters of the
transaction and approve the transaction as if by a signature. This use
is called a _Smart Signature_. Starting with v2, these programs may
also execute as _Smart Contracts_, which are often called
_Applications_. Contract executions are invoked with explicit
application call transactions.

Programs have read-only access to the transaction they are attached
to, the other transactions in their atomic transaction group, and a
few global values. In addition, _Smart Contracts_ have access to
limited state that is global to the application and per-account local
state for each account that has opted-in to the application. For both
types of program, approval is signaled by finishing with the stack
containing a single non-zero uint64 value, though `return` can be used
to signal an early approval which approves based only upon the top
stack value being a non-zero uint64 value.

## The Stack

The stack starts empty and can contain values of either uint64 or byte-arrays
(byte-arrays may not exceed
4096 bytes in length). Most operations act on the stack, popping
arguments from it and pushing results to it. Some operations have
_immediate_ arguments that are encoded directly into the instruction,
rather than coming from the stack.

The maximum stack depth is 1000. If the stack depth is
exceeded or if a byte-array element exceed 4096 bytes, the program fails.

## Scratch Space

In addition to the stack there are 256 positions of scratch
space. Like stack values, scratch locations may be uint64s or
byte-arrays. Scratch locations are initialized as uint64 zero. Scratch
space is accessed by the `load(s)` and `store(s)` opcodes which move
data from or to scratch space, respectively.

## Versions

In order to maintain existing semantics for previously written
programs, AVM code is versioned.  When new opcodes are introduced, or
behavior is changed, a new version is introduced.  Programs carrying
old versions are executed with their original semantics. In the AVM
bytecode, the version is an incrementing integer, currently 6, and
denoted vX throughout this document.

## Execution Modes

Starting from v2, the AVM can run programs in two modes:
1. LogicSig or _stateless_ mode, used to execute Smart Signatures
2. Application or _stateful_ mode, used to execute Smart Contracts

Differences between modes include:
1. Max program length (consensus parameters LogicSigMaxSize, MaxAppTotalProgramLen & MaxExtraAppProgramPages)
2. Max program cost (consensus parameters LogicSigMaxCost, MaxAppProgramCost)
3. Opcode availability. Refer to [opcodes document](TEAL_opcodes.md) for details.
4. Some global values, such as LatestTimestamp, are only available in stateful mode.
5. Only Applications can observe transaction effects, such as Logs or IDs allocated to ASAs or new Applications.

## Execution Environment for Smart Signatures

Smart Signatures execute as part of testing a proposed transaction to
see if it is valid and authorized to be committed into a block. If an
authorized program executes and finishes with a single non-zero uint64
value on the stack then that program has validated the transaction it
is attached to.

The program has access to data from the transaction it is attached to
(`txn` op), any transactions in a transaction group it is part of
(`gtxn` op), and a few global values like consensus parameters
(`global` op). Some "Args" may be attached to a transaction being
validated by a program. Args are an array of byte strings. A common
pattern would be to have the key to unlock some contract as an Arg. Be
aware that Smart Signature Args are recorded on the blockchain and
publicly visible when the transaction is submitted to the network,
even before the transaction has been included in a block. These Args
are _not_ part of the transaction ID nor of the TxGroup hash. They
also cannot be read from other programs in the group of transactions.

A program can either authorize some delegated action on a normal
signature-based or multisignature-based account or be wholly in charge
of a contract account.

* If the account has signed the program (by providing a valid ed25519
  signature or valid multisignature for the authorizer address on the
  string "Program" concatenated with the program bytecode) then: if the
  program returns true the transaction is authorized as if the account
  had signed it. This allows an account to hand out a signed program
  so that other users can carry out delegated actions which are
  approved by the program. Note that Smart Signature Args are _not_
  signed.

* If the SHA512_256 hash of the program (prefixed by "Program") is
  equal to authorizer address of the transaction sender then this is a
  contract account wholly controlled by the program. No other
  signature is necessary or possible. The only way to execute a
  transaction against the contract account is for the program to
  approve it.

The bytecode plus the length of all Args must add up to no more than
1000 bytes (consensus parameter LogicSigMaxSize). Each opcode has an
associated cost and the program cost must total no more than 20,000
(consensus parameter LogicSigMaxCost). Most opcodes have a cost of 1,
but a few slow cryptographic operations have a much higher cost. Prior
to v4, the program's cost was estimated as the static sum of all the
opcode costs in the program (whether they were actually executed or
not). Beginning with v4, the program's cost is tracked dynamically,
while being evaluated. If the program exceeds its budget, it fails.

## Execution Environment for Smart Contracts (Applications)

Smart Contracts are executed in ApplicationCall transactions. Like
Smart Signatures, contracts indicate success by leaving a single
non-zero integer on the stack.  A failed Smart Contract call is not a
valid transaction, thus not written to the blockchain. Nodes maintain
a list of transactions that would succeed, given the current state of
the blockchain, called the transaction pool. Nodes draw from the pool
if they are called upon to propose a block.

Smart Contracts have access to everything a Smart Signature may access
(see previous section), as well as the ability to examine blockchain
state such as balances and contract state (their own state and the
state of other contracts).  They also have access to some global
values that are not visible to Smart Signatures because the values
change over time.  Since smart contracts access changing state, nodes
must rerun their code to determine if the ApplicationCall transactions
in their pool would still succeed each time a block is added to the
blockchain.

Smart contracts have limits on their execution cost (700, consensus
parameter MaxAppProgramCost). Before v4, this was a static limit on
the cost of all the instructions in the program. Since then, the cost
is tracked dynamically during execution and must not exceed
MaxAppProgramCost. Beginning with v5, programs costs are pooled and
tracked dynamically across app executions in a group.  If `n`
application invocations appear in a group, then the total execution
cost of such calls must not exceed `n`*MaxAppProgramCost. In v6, inner
application calls become possible, and each such call increases the
pooled budget by MaxAppProgramCost.

Executions of the ClearStateProgram are more stringent, in order to
ensure that applications may be closed out, but that applications also
are assured a chance to clean up their internal state. At the
beginning of the execution of a ClearStateProgram, the pooled budget
available must be MaxAppProgramCost or higher. If it is not, the
containing transaction group fails without clearing the app's
state. During the execution of the ClearStateProgram, no more than
MaxAppProgramCost may be drawn. If further execution is attempted, the
ClearStateProgram fails, and the app's state _is cleared_.


### Resource availability

Smart contracts have limits on the amount of blockchain state they
may examine.  Opcodes may only access blockchain resources such as
Accounts, Assets, and contract state if the given resource is
_available_.

 * A resource in the "foreign array" fields of the ApplicationCall
   transaction (`txn.Accounts`, `txn.ForeignAssets`, and
   `txn.ForeignApplications`) is _available_.

 * The `txn.Sender`, `global CurrentApplicationID`, and `global
   CurrentApplicationAddress` are _available_.

 * Prior to v4, all assets were considered _available_ to the
   `asset_holding_get` opcode, and all applications were _available_
   to the `app_local_get_ex` opcode.

 * Since v6, any asset or contract that was created earlier in the
   same transaction group (whether by a top-level or inner
   transaction) is _available_. In addition, any account that is the
   associated account of a contract that was created earlier in the
   group is _available_.

 * Since v7, the account associated with any contract present in the
   `txn.ForeignApplications` field is _available_.

## Constants

Constants can be pushed onto the stack in two different ways:

1. Constants can be pushed directly with `pushint` or
   `pushbytes`. This method is more efficient for constants that are
   only used once.

2. Constants can be loaded into storage separate from the stack and
   scratch space, using two opcodes `intcblock` and
   `bytecblock`. Then, constants from this storage can be pushed
   pushed onto the stack by referring to the type and index using
   `intc`, `intc_[0123]`, `bytec`, and `bytec_[0123]`. This method is
   more efficient for constants that are used multiple times.

The assembler will hide most of this, allowing simple use of `int 1234`
and `byte 0xcafed00d`. Constants introduced via `int` and `byte` will
be assembled into appropriate uses of `pushint|pushbytes` and
`{int|byte}c, {int|byte}c_[0123]` to minimize program size.


The opcodes `intcblock` and `bytecblock` use [proto-buf style variable length unsigned int](https://developers.google.com/protocol-buffers/docs/encoding#varint),
reproduced [here](#varuint). The `intcblock` opcode is followed by a
varuint specifying the number of integer constants and then that
number of varuints. The `bytecblock` opcode is followed by a varuint
specifying the number of byte constants, and then that number of pairs
of (varuint, bytes) length prefixed byte strings.

### Named Integer Constants

@@ named_integer_constants.md @@

## Operations

Most operations work with only one type of argument, uint64 or bytes, and fail if the wrong type value is on the stack.

Many instructions accept values to designate Accounts, Assets, or Applications. Beginning with v4, these values may be given as an _offset_ in the corresponding Txn fields (Txn.Accounts, Txn.ForeignAssets, Txn.ForeignApps) _or_ as the value itself (a byte-array address for Accounts, or a uint64 ID). The values, however, must still be present in the Txn fields. Before v4, most opcodes required the use of an offset, except for reading account local values of assets or applications, which accepted the IDs directly and did not require the ID to be present in they corresponding _Foreign_ array. (Note that beginning with v4, those IDs _are_ required to be present in their corresponding _Foreign_ array.) See individual opcodes for details. In the case of account offsets or application offsets, 0 is specially defined to Txn.Sender or the ID of the current application, respectively.

This summary is supplemented by more detail in the [opcodes document](TEAL_opcodes.md).

Some operations immediately fail the program.
A transaction checked by a program that fails is not valid.
An account governed by a buggy program might not have a way to get assets back out of it. Code carefully.

In the documentation for each opcode, the stack arguments that are
popped are referred to alphabetically, beginning with the deepest
argument as `A`.  These arguments are shown in the opcode description,
and if the opcode must be of a specific type, it is noted there.  All
opcodes fail if a specified type is incorrect.

If an opcode pushes more than one result, the values are named for
ease of exposition and clarity concerning their stack positions.  When
an opcode manipulates the stack in such a way that a value changes
position but is otherwise unchanged, the name of the output on the
return stack matches the name of the input value.

### Arithmetic, Logic, and Cryptographic Operations

@@ Arithmetic.md @@

### Byte Array Manipulation

@@ Byte_Array_Manipulation.md @@

The following opcodes take byte-array values that are interpreted as
big-endian unsigned integers.  For mathematical operators, the
returned values are the shortest byte-array that can represent the
returned value.  For example, the zero value is the empty
byte-array. For comparison operators, the returned value is a uint64.

Input lengths are limited to a maximum length of 64 bytes,
representing a 512 bit unsigned integer. Output lengths are not
explicitly restricted, though only `b*` and `b+` can produce a larger
output than their inputs, so there is an implicit length limit of 128
bytes on outputs.

@@ Byte_Array_Arithmetic.md @@

These opcodes operate on the bits of byte-array values.  The shorter
input array is interpreted as though left padded with zeros until it is the
same length as the other input.  The returned values are the same
length as the longer input.  Therefore, unlike array arithmetic,
these results may contain leading zero bytes.

@@ Byte_Array_Logic.md @@

### Loading Values

Opcodes for getting data onto the stack.

Some of these have immediate data in the byte or bytes after the opcode.

@@ Loading_Values.md @@

#### Transaction Fields
##### Scalar Fields
@@ txn_fields.md @@
##### Array Fields
@@ txna_fields.md @@

Additional details in the [opcodes document](TEAL_opcodes.md#txn) on the `txn` op.

**Global Fields**

Global fields are fields that are common to all the transactions in the group. In particular it includes consensus parameters.

@@ global_fields.md @@

**Asset Fields**

Asset fields include `AssetHolding` and `AssetParam` fields that are used in the `asset_holding_get` and `asset_params_get` opcodes.

@@ asset_holding_fields.md @@

@@ asset_params_fields.md @@

**App Fields**

App fields used in the `app_params_get` opcode.

@@ app_params_fields.md @@

**Account Fields**

Account fields used in the `acct_params_get` opcode.

@@ acct_params_fields.md @@

### Flow Control

@@ Flow_Control.md @@

### State Access

@@ State_Access.md @@

### Inner Transactions

The following opcodes allow for "inner transactions". Inner
transactions allow stateful applications to have many of the effects
of a true top-level transaction, programatically.  However, they are
different in significant ways.  The most important differences are
that they are not signed, duplicates are not rejected, and they do not
appear in the block in the usual away. Instead, their effects are
noted in metadata associated with their top-level application
call transaction.  An inner transaction's `Sender` must be the
SHA512_256 hash of the application ID (prefixed by "appID"), or an
account that has been rekeyed to that hash.

In v5, inner transactions may perform `pay`, `axfer`, `acfg`, and
`afrz` effects.  After executing an inner transaction with
`itxn_submit`, the effects of the transaction are visible begining
with the next instruction with, for example, `balance` and
`min_balance` checks. In v6, inner transactions may also perform
`keyreg` and `appl` effects. Inner `appl` calls fail if they attempt
to invoke a program with version less than v4, or if they attempt to
opt-in to an app with a ClearState Program less than v4.

In v5, only a subset of the transaction's header fields may be set: `Type`/`TypeEnum`,
`Sender`, and `Fee`. In v6, header fields `Note` and `RekeyTo` may
also be set.  For the specific (non-header) fields of each transaction
type, any field may be set.  This allows, for example, clawback
transactions, asset opt-ins, and asset creates in addition to the more
common uses of `axfer` and `acfg`.  All fields default to the zero
value, except those described under `itxn_begin`.

Fields may be set multiple times, but may not be read. The most recent
setting is used when `itxn_submit` executes. For this purpose `Type`
and `TypeEnum` are considered to be the same field. When using
`itxn_field` to set an array field (`ApplicationArgs` `Accounts`,
`Assets`, or `Applications`) each use adds an element to the end of
the the array, rather than setting the entire array at once.

`itxn_field` fails immediately for unsupported fields, unsupported
transaction types, or improperly typed values for a particular
field. `itxn_field` makes acceptance decisions entirely from the field
and value provided, never considering previously set fields. Illegal
interactions between fields, such as setting fields that belong to two
different transaction types, are rejected by `itxn_submit`.

@@ Inner_Transactions.md @@


# Assembler Syntax

The assembler parses line by line. Ops that only take stack arguments
appear on a line by themselves. Immediate arguments follow the opcode
on the same line, separated by whitespace.

The first line may contain a special version pragma `#pragma version X`, which directs the assembler to generate AVM bytecode targeting a certain version. For instance, `#pragma version 2` produces bytecode targeting AVM v2. By default, the assembler targets AVM v1.

Subsequent lines may contain other pragma declarations (i.e., `#pragma <some-specification>`), pertaining to checks that the assembler should perform before agreeing to emit the program bytes, specific optimizations, etc. Those declarations are optional and cannot alter the semantics as described in this document.

"`//`" prefixes a line comment.

## Constants and Pseudo-Ops

A few pseudo-ops simplify writing code. `int` and `byte` and `addr` and `method` followed by a constant record the constant to a `intcblock` or `bytecblock` at the beginning of code and insert an `intc` or `bytec` reference where the instruction appears to load that value. `addr` parses an Algorand account address base32 and converts it to a regular bytes constant. `method` is passed a method signature and takes the first four bytes of the hash to convert it to the standard method selector defined in [ARC4](https://github.com/algorandfoundation/ARCs/blob/main/ARCs/arc-0004.md)

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

`int` constants may be `0x` prefixed for hex, `0o` or `0` prefixed for
octal, `0b` for binary, or decimal numbers.

`intcblock` may be explicitly assembled. It will conflict with the assembler gathering `int` pseudo-ops into a `intcblock` program prefix, but may be used if code only has explicit `intc` references. `intcblock` should be followed by space separated int constants all on one line.

`bytecblock` may be explicitly assembled. It will conflict with the assembler if there are any `byte` pseudo-ops but may be used if only explicit `bytec` references are used. `bytecblock` should be followed with byte constants all on one line, either 'encoding value' pairs (`b64 AAA...`) or 0x prefix or function-style values (`base64(...)`) or string literal values.

## Labels and Branches

A label is defined by any string not some other opcode or keyword and ending in ':'. A label can be an argument (without the trailing ':') to a branching instruction.

Example:
```
int 1
bnz safe
err
safe:
pop
```

# Encoding and Versioning

A compiled program starts with a varuint declaring the version of the compiled code. Any addition, removal, or change of opcode behavior increments the version. For the most part opcode behavior should not change, addition will be infrequent (not likely more often than every three months and less often as the language matures), and removal should be very rare.

For version 1, subsequent bytes after the varuint are program opcode bytes. Future versions could put other metadata following the version identifier.

It is important to prevent newly-introduced transaction fields from
breaking assumptions made by older versions of the AVM. If one of the
transactions in a group will execute a program whose version predates
a given field, that field must not be set anywhere in the transaction
group, or the group will be rejected. For example, executing a version
1 program on a transaction with RekeyTo set to a nonzero address will
cause the program to fail, regardless of the other contents of the
program itself.

This requirement is enforced as follows:

* For every transaction, compute the earliest version that supports
  all the fields and values in this transaction. For example, a
  transaction with a nonzero RekeyTo field will be (at least) v2.

* Compute the largest version number across all the transactions in a group (of size 1 or more), call it `maxVerNo`. If any transaction in this group has a program with a version smaller than `maxVerNo`, then that program will fail.

In addition, applications must be version 6 or greater to be eligible
for being called in an inner transaction.

## Varuint

A '[proto-buf style variable length unsigned int](https://developers.google.com/protocol-buffers/docs/encoding#varint)' is encoded with 7 data bits per byte and the high bit is 1 if there is a following byte and 0 for the last byte. The lowest order 7 bits are in the first byte, followed by successively higher groups of 7 bits.

# What AVM Programs Cannot Do

Design and implementation limitations to be aware of with various versions.

* Stateless programs cannot lookup balances of Algos or other
  assets. (Standard transaction accounting will apply after the Smart
  Signature has authorized a transaction. A transaction could still be
  invalid by other accounting rules just as a standard signed
  transaction could be invalid. e.g. I can't give away money I don't
  have.)
* Programs cannot access information in previous blocks. Programs
  cannot access information in other transactions in the current
  block, unless they are a part of the same atomic transaction group.
* Smart Signatures cannot know exactly what round the current transaction
  will commit in (but it is somewhere in FirstValid through
  LastValid).
* Programs cannot know exactly what time its transaction is committed.
* Programs cannot loop prior to v4. In v3 and prior, the branch
  instructions `bnz` "branch if not zero", `bz` "branch if zero" and
  `b` "branch" can only branch forward.
* Until v4, the AVM had no notion of subroutines (and therefore no
  recursion). As of v4, use `callsub` and `retsub`.
* Programs cannot make indirect jumps. `b`, `bz`, `bnz`, and `callsub`
  jump to an immediately specified address, and `retsub` jumps to the
  address currently on the top of the call stack, which is manipulated
  only by previous calls to `callsub` and `retsub`.
