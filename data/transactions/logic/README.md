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


