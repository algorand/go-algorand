# Transaction Execution Approval Language (TEAL)

TEAL is a bytecode based stack language that executes inside Algorand transactions to check the parameters of the transaction and approve the transaction as if by a signature.

TEAL programs should be short, at most 1000 bytes including all constants and operations, and run fast as they are run in-line along with signature checking, transaction balance rule checking, and other checks during block assembly and validation.

## The Stack

The stack starts empty and contains values of either uint64 or bytes. (`bytes` implemented in Go as a []byte slice)

The maximum stack depth is currently 1000.

## Constants

Constants are loaded into the environment into storage separate from the stack. They can then be pushed onto the stack by referring to the type and index. This makes for efficient re-use of byte constants used for account addresses, etc.

The assembler will hide most of this, allowing simple use of `int 1234` and `byte 0xcafed00d`. These constants will automatically get assembled into int and byte pages of constants, de-duplicated, and operations to load them from constant storage space inserted.

Constants are loaded into the environment by two opcodes, `intcblock` and `bytecblock`. Both of these use proto-buf style variable length unsigned int (See https://developers.google.com/protocol-buffers/docs/encoding#varint ). The `intcblock` opcode is followed by a var-uint specifying the length of the array and then than number of var-uint. The `bytecblock` opcode is followed by a var-uint array length then that number of pairs of (var-uint, bytes) length prefixed byte strings. This should efficiently load 32 and 64 byte constants which will be common as addresses, hashes, and signatures.

Constants are pushed onto the stack by `intc`, `intc_[0123]`, `bytec`, and `bytec_[0123]`. The assembler will typically handle converting `int N` or `byte N` into the appropriate constant-offset opcode or opcode followed by index byte.

## Operations


Most operation work with only one type of argument, uint64 or bytes, and panic if the wrong type value is on the stack.

### Arithmetic

For one-argument ops, `X` is the last element on the stack.

For two-argument ops, `A` is the previous element on the stack and `B` is the last element on the stack. These typically result in popping A and B from the stack and pushing the result.

| Op | Description |
| --- | --- | --- |
| err | Error. Panic immediately. This is primarily a fencepost against accidental zero bytes getting compiled into programs. |
| sha256 | Pop bytes X, push bytes sha256 hash of X |
| keccack256 | Pop bytes X, push bytes keccack256 hash of X |
| sha512_256 | Pop bytes X, push bytes sha512_256 hash of X |
| + | Add uint64 A + uint64 B. Panic on overflow |
| - | Subtract uint64 - uint64 B. Panic if result would be less than 0. |
| / | Divide uint64 A / uint64  B. Panic if B == 0. |
| * | Multiply uint64 A * uint64 B. Panic on overflow. |
| < | Compare uint64 A < uint64 B. Push 1 or 0. |
| > | Compare uint64 A > uint64 B. Push 1 or 0. |
| <= | Compare uint64 A <= uint64 B. Push 1 or 0. |
| >= | Compare uint64 A >= uint64 B. Push 1 or 0. |
| && | If uint64 A and uint64 B are both non-zero, push 1, else push 0. |
| &#124;&#124; | If uint64 A or uint64 B are either non-zero, push 1, else push 0. |
| == | Compare A equal to B (any type as long as both the same type). Push 1 or 0. |
| != | Compare A not equal to B (any type as long as both the same type). Push 1 or 0. |
| ! | Pop uint64 X. If zero push 1, else push 0. |
| len | Pop bytes X. Push uint64 length of X. |
| btoi | Pop bytes X. X may be 0 to 8 bytes. Interpret as big-endian bytes of unsigned int. Push uint64. |
| % | Modulo uint64 A % uint64 B. Panic if B == 0. |
| &#124; | Bitwise or uint64 A &#124; uint64 B. |
| & | Bitwise and uint64 A & uint64 B. |
| ^ | Bitwise XOR uint64 A ^ uint64 B. |
| ~ | Bitwise not uint64 X. |

### Loading Values

Opcodes for getting data onto the stack.

Some of these have immediate data in the byte or bytes after the opcode.

| Op | Description |
| --- | --- | --- |
| intcblock | Load next bytes into uint64 constant space. See section "Constants" above |
| intc | Next byte is index into int constant space. Push that uint64. |
| intc_0 | Push intConstant[0] |
| intc_1 | Push intConstant[1] |
| intc_2 | Push intConstant[2] |
| intc_3 | Push intConstant[3] |
| bytecblock | Load next bytes into bytes constant space. See section "Constants" above |
| bytec | Next byte is index into bytes constant space. Push that bytes value. |
| bytec_0 | Push byteConstant[0] |
| bytec_1 | Push byteConstant[1] |
| bytec_2 | Push byteConstant[2] |
| bytec_3 | Push byteConstant[3] |
| arg | Next byte is index into LogicSig.Args array. Push that bytes value. |
| arg_0 | Push LogicSig.Args[0] |
| arg_1 | Push LogicSig.Args[1] |
| arg_2 | Push LogicSig.Args[2] |
| arg_3 | Push LogicSig.Args[3] |
| txn | Next byte is index into transaction fields. Push a field from the current transaction (may be uint64 or bytes) onto the stack. See table of transaction fields below. |
| global | Next byte is index into global fields. Push a field from the global (may be uint64 or bytes) onto the stack. See table of global fields below. |

**Transaction Fields**

| Number | Name | Type |
| --- | --- | --- |
| 0 | Sender | bytes |
| 1 | Fee | uint64 |
| 2 | FirstValid | uint64 |
| 3 | LastValid | uint64 |
| 4 | Note | bytes |
| 5 | Receiver | bytes |
| 6 | Amount | uint64 |
| 7 | CloseRemainderTo | bytes |
| 8 | VotePK | bytes |
| 9 | SelectionPK | bytes |
| 10 | VoteFirst | uint64 |
| 11 | VoteLast | uint64 |
| 12 | VoteKeyDilution | uint64 |

**Global Fields**

| Number | Name | Type |
| --- | --- | --- |
| 0 | Round | uint64 |
| 1 | MinTxnFee | uint64 |
| 2 | MinBalance | uint64 |
| 3 | MaxTxnLife | uint64 |
| 4 | BlockTime | uint64 |


### Flow Control

| Op | Description |
| --- | --- |
| bnz | branch if not zero. next byte is offset if branch is taken. pop uint64 X. if X != 0, next instruction at (current pc + 2 + program[pc+1]) |
| pop | Pop anything. Discard it. |
| dup | Any last element of the stack becomes the last two elements of the stack. |


# Assembler Syntax

The assembler parses line by line. Ops that just use the stack appear on a line by themselves. Ops that take arguments are the op and then whitespace and then any argument or arguments.

"`//`" prefixes a line comment.

## Constants and Psuedo-Ops

A few psuedo-ops simplify writing code. `int` and `byte` and `addr` followed by a constant record the constant to a `intcblock` or `bytecblock` at the beginning of code and insert an `intc` or `bytec` reference where the instruction appears to load that value. `addr` parses an Algorand account address base32 and converts it to a regular bytes constant.

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

`intcblock` may be explictily assembled. It will conflict with the assembler gathering `int` psuedo-ops into a `intcblock` program prefix, but may be used in code only has explicit `intc` references. `intcblock` should be followed by space separated int contsants all on one line.

`bytecblock` may be explicitly assembled. It will conflict with the assembler if there are any `byte` psudo-ops but may be used if only explicit `bytec` references are used. `bytecblock` should be followed with byte contants all on one line, either 'encoding value' pairs (`b64 AAA...`) or 0x prefix or function-style values (`base64(...)`).

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