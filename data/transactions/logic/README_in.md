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
limited state that is global to the application, per-account local
state for each account that has opted-in to the application, and
additional per-application arbitrary state in named _boxes_. For both types of
program, approval is signaled by finishing with the stack containing a
single non-zero uint64 value, though `return` can be used to signal an
early approval which approves based only upon the top stack value
being a non-zero uint64 value.

## The Stack

The stack starts empty and can contain values of either uint64 or byte-arrays
(byte-arrays may not exceed
4096 bytes in length). Most operations act on the stack, popping
arguments from it and pushing results to it. Some operations have
_immediate_ arguments that are encoded directly into the instruction,
rather than coming from the stack.

The maximum stack depth is 1000. If the stack depth is exceeded or if
a byte-array element exceeds 4096 bytes, the program fails. If an
opcode is documented to access a position in the stack that does not
exist, the operation fails. Most often, this is an attempt to access
an element below the stack -- the simplest example is an operation
like `concat` which expects two arguments on the stack. If the stack
has fewer than two elements, the operation fails. Some operations, like
`frame_dig` and `proto` could fail because of an attempt to access
above the current stack.

## Stack Types

While every element of the stack is restricted to the types `uint64` and `bytes`, 
the values of these types may be known to be bounded.  The more common bounded types are 
named to provide more semantic information in the documentation. They're also used during
assembly time to do type checking and to provide more informative error messages.


@@ named_stack_types.md @@


## Scratch Space

In addition to the stack there are 256 positions of scratch
space. Like stack values, scratch locations may be uint64s or
byte-arrays. Scratch locations are initialized as uint64 zero. Scratch
space is accessed by the `load(s)` and `store(s)` opcodes which move
data from or to scratch space, respectively. Application calls may
inspect the final scratch space of earlier application calls in the
same group using `gload(s)(s)`

## Versions

In order to maintain existing semantics for previously written
programs, AVM code is versioned.  When new opcodes are introduced, or
behavior is changed, a new version is introduced.  Programs carrying
old versions are executed with their original semantics. In the AVM
bytecode, the version is an incrementing integer, currently 12, and
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

The size of a Smart Signature is defined as the length of its bytecode
plus the length of all its Args. The sum of the sizes of all Smart
Signatures in a group must not exceed 1000 bytes times the number of
transactions in the group (1000 bytes is defined in consensus parameter
`LogicSigMaxSize`).

Each opcode has an associated cost, usually 1, but a few slow operations
have higher costs. Prior to v4, the program's cost was estimated as the
static sum of all the opcode costs in the program (whether they were
actually executed or not). Beginning with v4, the program's cost is
tracked dynamically while being evaluated. If the program exceeds its
budget, it fails.

The total program cost of all Smart Signatures in a group must not
exceed 20,000 (consensus parameter LogicSigMaxCost) times the number
of transactions in the group.


## Execution Environment for Smart Contracts (Applications)

Smart Contracts are executed in ApplicationCall transactions. Like
Smart Signatures, contracts indicate success by leaving a single
non-zero integer on the stack.  A failed Smart Contract call to an
ApprovalProgram is not a valid transaction, thus not written to the
blockchain. An ApplicationCall with OnComplete set to ClearState
invokes the ClearStateProgram, rather than the usual
ApprovalProgram. If the ClearStateProgram fails, application state
changes are rolled back, but the transaction still succeeds, and the
Sender's local state for the called application is removed.

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
the cost of all the instructions in the program. Starting in v4, the cost
is tracked dynamically during execution and must not exceed
MaxAppProgramCost. Beginning with v5, programs costs are pooled and
tracked dynamically across app executions in a group.  If `n`
application invocations appear in a group, then the total execution
cost of all such calls must not exceed `n`*MaxAppProgramCost. In v6, inner
application calls become possible, and each such call increases the
pooled budget by MaxAppProgramCost at the time the inner group is submitted
with `itxn_submit`.

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

Smart contracts have limits on the amount of blockchain state they may
examine.  These limits are enforced by failing any opcode that
attempts to access a resource unless the resource is
_available_. These resources are:

 * Accounts, which must be available to access their balance, or other
 account parameters such as voting details.
 * Assets, which must be available to access global asset parameters, such
   the as the asset's URL, Name, or privileged addresses.
 * Holdings, which must be available to access a particular address's
   balance or frozen status for a particular asset.
 * Applications, which must be available to read an application's
   programs, parameters, or global state.
 * Locals, which must be available to read a particular address's local
   state for a particular application.
 * Boxes, which must be available to read or write a box, designated
   by an application and name for the box.

Resources are _available_ based on the contents of the executing
transaction and, in later versions, the contents of other transactions
in the same group.

 * A resource in the "foreign array" fields of the ApplicationCall
   transaction (`txn.Accounts`, `txn.ForeignAssets`, and
   `txn.ForeignApplications`) is _available_.

 * The `txn.Sender`, `global CurrentApplicationID`, and `global
   CurrentApplicationAddress` are _available_.

 * In pre-v4 applications, all holdings are _available_ to the
   `asset_holding_get` opcode, and all locals are _available_ to the
   `app_local_get_ex` opcode if the *account* of the resource is
   _available_.

 * In v6 and later applications, any asset or application that was
   created earlier in the same transaction group (whether by a
   top-level or inner transaction) is _available_. In addition, any
   account that is the associated account of a contract that was
   created earlier in the group is _available_.

 * In v7 and later applications, the account associated with any
   contract present in the `txn.ForeignApplications` field is
   _available_.

 * In v4 and above applications, Holdings and Locals are _available_
   if, both components of the resource are available according to the
   above rules.

 * In v9 and later applications, there is group-level resource
   sharing. Any resource that is available in _some_ top-level
   transaction in a transaction group is available in _all_ v9 or
   later application calls in the group, whether those application
   calls are top-level or inner.

 * v9 and later applications may use the `txn.Access` list instead of
   the foreign arrays. When using `txn.Access` Holdings and Locals are
   no longer made available automatically because their components
   are. Application accounts are also not made available because of
   the availability of their corresponding app. Each resource must be
   listed explicitly. However, `txn.Access` allows for the listing of
   more resources than the foreign arrays.  Listed resources become
   available to other (post-v8) applications through group sharing.

 * When considering whether an asset holding or application local
   state is available for group-level resource sharing, the holding or
   local state must be available in a top-level transaction based on
   pre-v9 rules. For example, if account A is made available in one
   transaction, and asset X is made available in another, group
   resource sharing does _not_ make A's X holding available.

 * Top-level transactions that are not application calls also make
   resources available to group-level resource sharing. The following
   resources are made available by other transaction types.

     1. `pay` - `txn.Sender`, `txn.Receiver`, and
        `txn.CloseRemainderTo` (if set).

     1. `keyreg` - `txn.Sender`

     1. `acfg` - `txn.Sender`, `txn.ConfigAsset`, and the
        `txn.ConfigAsset` holding of `txn.Sender`.

     1. `axfer` - `txn.Sender`, `txn.AssetReceiver`, `txn.AssetSender`
        (if set), `txnAssetCloseTo` (if set), `txn.XferAsset`, and the
        `txn.XferAsset` holding of each of those accounts.

     1. `afrz` - `txn.Sender`, `txn.FreezeAccount`, `txn.FreezeAsset`,
        and the `txn.FreezeAsset` holding of `txn.FreezeAccount`. The
        `txn.FreezeAsset` holding of `txn.Sender` is _not_ made
        available.


 * A Box is _available_ to an Approval Program if _any_ transaction in
   the same group contains a box reference (in `txn.Boxes` or
   `txn.Access`) that denotes the box. A box reference contains an
   index `i`, and name `n`. The index refers to the `ith` application
   in the transaction's `ForeignApplications` or `Access` array (only
   one of which can be used), with the usual convention that 0
   indicates the application ID of the app called by that
   transaction. No box is ever _available_ to a ClearStateProgram.

Regardless of _availability_, any attempt to access an Asset or
Application with an ID less than 256 from within a Contract will fail
immediately. This avoids any ambiguity in opcodes that interpret their
integer arguments as resource IDs _or_ indexes into the
`txn.ForeignAssets` or `txn.ForeignApplications` arrays.

It is recommended that contract authors avoid supplying array indexes
to these opcodes, and always use explicit resource IDs. By using
explicit IDs, contracts will better take advantage of group resource
sharing.  The array indexing interpretation may be deprecated in a
future version.

## Constants

Constants can be pushed onto the stack in two different ways:

1. Constants can be pushed directly with `pushint` or
   `pushbytes`. This method is more efficient for constants that are
   only used once.

2. Constants can be loaded into storage separate from the stack and
   scratch space, using two opcodes `intcblock` and
   `bytecblock`. Then, constants from this storage can be
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

Many instructions accept values to designate Accounts, Assets, or Applications. Beginning with v4, these values may be given as an _offset_ in the corresponding Txn fields (Txn.Accounts, Txn.ForeignAssets, Txn.ForeignApps) _or_ as the value itself (a byte-array address for Accounts, or a uint64 ID). The values, however, must still be present in the Txn fields. Before v4, most opcodes required the use of an offset, except for reading account local values of assets or applications, which accepted the IDs directly and did not require the ID to be present in the corresponding _Foreign_ array. (Note that beginning with v4, those IDs _are_ required to be present in their corresponding _Foreign_ array.) See individual opcodes for details. In the case of account offsets or application offsets, 0 is specially defined to Txn.Sender or the ID of the current application, respectively.

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

### Arithmetic and Logic Operations

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

### Cryptographic Operations

@@ Cryptography.md @@

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

### Box Access

Box opcodes that create, delete, or resize boxes affect the minimum
balance requirement of the calling application's account.  The change
is immediate, and can be observed after exection by using
`min_balance`.  If the account does not possess the new minimum
balance, the opcode fails.

All box related opcodes fail immediately if used in a
ClearStateProgram. This behavior is meant to discourage Smart Contract
authors from depending upon the availability of boxes in a ClearState
transaction, as accounts using ClearState are under no requirement to
furnish appropriate Box References.  Authors would do well to keep the
same issue in mind with respect to the availability of Accounts,
Assets, and Apps though State Access opcodes _are_ allowed in
ClearState programs because the current application and sender account
are sure to be _available_.

@@ Box_Access.md @@

### Inner Transactions

The following opcodes allow for "inner transactions". Inner
transactions allow stateful applications to have many of the effects
of a true top-level transaction, programmatically.  However, they are
different in significant ways.  The most important differences are
that they are not signed, duplicates are not rejected, and they do not
appear in the block in the usual away. Instead, their effects are
noted in metadata associated with their top-level application
call transaction.  An inner transaction's `Sender` must be the
SHA512_256 hash of the application ID (prefixed by "appID"), or an
account that has been rekeyed to that hash.

In v5, inner transactions may perform `pay`, `axfer`, `acfg`, and
`afrz` effects.  After executing an inner transaction with
`itxn_submit`, the effects of the transaction are visible beginning
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
the array, rather than setting the entire array at once.

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

The first line may contain a special version pragma `#pragma version X`, which directs the assembler to generate bytecode targeting a certain version. For instance, `#pragma version 2` produces bytecode targeting v2. By default, the assembler targets v1.

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

It is important to prevent newly-introduced transaction types and
fields from breaking assumptions made by programs written before they
existed. If one of the transactions in a group will execute a program
whose version predates a transaction type or field that can violate
expectations, that transaction type or field must not be used anywhere
in the transaction group.

Concretely, the above requirement is translated as follows: A v1
program included in a transaction group that includes a
ApplicationCall transaction or a non-zero RekeyTo field will fail
regardless of the program itself.

This requirement is enforced as follows:

* For every transaction, compute the earliest version that supports
  all the fields and values in this transaction.
  
* Compute the largest version number across all the transactions in a group (of size 1 or more), call it `maxVerNo`. If any transaction in this group has a program with a version smaller than `maxVerNo`, then that program will fail.

In addition, applications must be v4 or greater to be called in an inner transaction.

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
