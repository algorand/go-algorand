
## State trie

The state trie, commonly known as a prefix tree, is a tree-like data structure
used for storing an associative array where the keys are sequences of 4-bit
bytes (Nibbles) and the values are SHA-512/256 hashes of the key values.

Each node of the trie contains a cryptographic hash of itself and any children 
nodes.  This design ensures that the entire structure is tamper-evident, as a 
proof can be provided to the user to show membership (or lack of membership) of
a key value.  The proof can be verified by checking that the proof provides the 
necessary missing value to hash to the known root hash.

The root hash is only dependent on the keys and values in the trie when the hash
is calculated, and not on the order in which the keys were added, or perhaps
added, deleted and re-added, etc.

Keys are stored by traversing the root node, using an expanding prefix of the
new key to make branching decisions, until a unique spot can be found for the
key value, then adjusting the trie and marking path nodes for rehashing.  

Keys are deleted by first searching for the key, and then performing trie 
transformations until the key is removed. The rest of the trie is reconfigured
to eliminate the impact the deleted key had made on the nodes around it.

This trie has built-in support for generic backing stores, which are essential
for persistent data storage and operation on very large tries. The package
provides both an in-memory storage backstore and a pebble-based backstore 
implementation.

*Key Features:*

* Hashing: The trie provides a SHA-512/256 checksum at its root, ensuring data
integrity.

* Adding and removing key/value pairs: Through specific operations, users can
efficiently add new key-value pairs to the trie or remove existing ones. The
trie ensures consistent state transitions and optimal space usage during these
operations.

* Child and Merge Operations: The trie supports operations to manage child 
tries, enabling the creation, discard, and merge actions for subtries.

* Backstore commit: The trie supports committing changes to the trie to a
backing store that fuctions like a batched kv interface.

* Preloading: Though the trie is designed to keep only parts of it in memory for
efficiency, it offers a preloading feature to sweep all nodes with keylengths
less than a provided parameter out of the backstore and into memory.

* Nibble-sized proofs: 4-bit trie keys are represented as `Nibbles`.  Each 
branch node has one child slot for each of the 16 nibble values. Using 
nibbles over 8-bit bytes allows for smaller proofs, but creates smaller and
more frequent backstore reads and taller tries.

### Trie operation and usage

Tries are initialized against a backing store (an empty memory one will be
constructed if not provided by the user) where the full trie ultimately resides
on Commit.

```
mt := MakeTrie(nil)
key1 := MakeNibbles({0x8e, 0x28})
key2 := MakeNibbles({0x8d, 0x28})
val1 := []byte{0x13, 0x19, 0x2a, 0x3c}
val2 := []byte{0x13, 0x19, 0x2a, 0x9f}

mt.Add(key1, val1)
fmt.Println("K1:V1 Hash:", mt.Hash())

mt.Add(key2, val2)
fmt.Println("K1:V1,K2:V2 Hash:", mt.Hash())

mt.Delete(key2)
fmt.Println("K1:V1 Hash:", mt.Hash())

mt.Commit(nil)
```

The trie maintains an interface reference to the root of the trie, which is one
of five possible trie node types described below.  Trie operations Add and
Delete descend the trie from this node, loading in nodes from the backstore (as
necessary), creating new nodes (if the key added is unique or a key is found
for deletion), and keeping track of nodes that can be deleted from the
backstore on the next Commit.

New `statetrie` objects that operate on a (potentially massive) trie residing
on a backing store are created by `MakeTrie (store)` and are initialized by
loading and deserializing the root node from the store.  References pointing
down from this node are represented by shallow backing node objects.  

When Add or Delete operations want to descend through one of these backing
nodes, the bytes are obtained from the backing store and deserialized into one
of the three main trie node types (branch, extension, or leaf).

In this way, trie operations 'unroll' paths from the trie store into working
memory as necessary to complete the operation.  

```
Trie residing on backing store like Pebble with a branch node (BR1) as the root node:
                _____
               | BR1 |
           ____|_____|____
          /              \
         /                \
      __O__              __O__
     /     \            /     \
    O       O          O       O
   / \     / \        / \     / \  
  O   O   O   O      O   O   O   O
 / \ / \ / \ / \    / \ / \ / \ / \
O   O   O   O   O  O   O   O   O   O


Below is a statetrie pointed at that backing store trie, immediately after MakeTrie. 
It has a root of one branch node, with its two child nodes held as shallow 
backing nodes (labeled 'b'), with known hashes that came from the branch node
deserialization.  The root hash of this trie can be calculated immediately without 
further backstore access:

          ___
         |BR1|
         /   \
        /     \
       b       b  

Below is that same statetrie after a few update Add operations, with more paths
unrolled from the backing store:

          ___
         |BR1|
         /   \
        /     \
      __O__   __O__
     /     \       \
    O       O       O
   /       / \     / \
  O       O   b   b   O
 /       /           / \
O       O           O   O
```

Nodes that can be reached from the statetrie root node represent:

1. uncommitted new intermediary or leaf nodes created in support of the Add or
   Delete and are not yet hashed

2. altered nodes created from prior operations that were never evicted
   (replaced with backing nodes), with their hash now zeroed as they were
   modified since the last Commit,

3. unaltered nodes created from prior operations in the past that were never
   evicted (replaced with backing nodes), and still have their original, known
   hash

4. references to nodes on the backing store (with a known hash)

5. references to nodes in the parent trie, which act as lazy copies of the
   parent nodes and disappear on merge

On Commit, the first two node categories reachable from the root node
(following parent links) are hashed and committed to the backstore, and any
keys marked for deletion are removed from the store.

Unmodified unrolls or committed nodes (categories 3 and 4) can either stay in
memory or face eviction by their parent node through an eviction function
evaluated as the nodes are committed (by calling a node's evict method).

Eviction of branching and extension nodes replaces their lower subtries with
backing nodes. A nil eviction function, as above, keeps all nodes in memory.
A lambda that always returns true would collapse the trie to only the root
node, with any subtries replaced by backing nodes.

```
The statetrie above after committing with an eviction lambda returning true if 
the node key length is three.
          ___
         |BR1|
         /   \
        /     \
      __O__   __O__
     /     \       \
    O       O       O
   /       / \     / \
  b       b   b   b   b
 
```

### Trie node types

There are three main trie nodes, leaf ndoes, branch nodes, and extension nodes.
These are the nodes that are hashed to calculate the hash root, and which are
serialized to the backing store.  The statetrie object uses two other
unserialized node objects, parent nodes and backing nodes, which convert into
one of the three main trie nodes as necessary.

| Node Type      | Description                                                                                           | Value Holding | Stored in Backstore |
|----------------|-------------------------------------------------------------------------------------------------------|---------------|---------------------|
| Leaf Nodes     | Contains the remainder of the search key (`keyEnd`) and the hash of the value.                         | Yes           | Yes                 |
| Branch Nodes   | Holds references to 16 children nodes and an optional "value slot" for keys that terminate at the node. | Optional      | Yes                 |
| Extension Nodes| Contains a run of commonly shared key nibbles that lead to the next node. No value is held.            | No            | Yes                 |
| Parent Nodes   | Soft-links back to a node in a parent trie. They expand into copies if edited.                         | Varies        | No                  |
| Backing Nodes  | Soft links back to a node in the backing store. They are expanded into one of the main nodes if read.  | Varies        | No                  |


All trie nodes hold a key representing the nibble position of the node in the
trie, and a hash of the node itself.  

Any of the node types can be the root of a trie.

The node key is the key used with the backing store to insert, alter or delete
the serialized node. The key is limited to MaxKeyLength (65,536) nibbles in
size, and cannot be empty (the root node is the empty nibble).  

The node hash is set to the zero value if it is not yet known or if the
contents of the node were altered in a trie operation.  The hash is calculated
by either of the trie methods `Hash()` or `Commit()`, the later which hashes
and commits the node changes with node method `hashingCommit(store)`. In these
operations, the node hash is set to the SHA-256 hash of the serialization of
the node.  The hashing scheme requires the lower levels of the trie to be
hashed before the higher levels.

* Leaf nodes

This value-holding nodes contain the remainder of the search key (the `keyEnd`)
and the hash of the value.

* Branch nodes

Branch nodes hold references to 16 children nodes indexed by the next nibble of
the search key, plut a "value slot" to hold values for keys th at terminate at
the branch node. 

* Extension nodes

Extension nodes contain an addition run of commonly shared key nibbles that
send you along to the next node.  No value is held at an extension node. There
are no extension nodes with no next node.

* Parent nodes

These nodes are soft-links back to a node in a parent trie from a child trie.
They are expanded into copies of their nodes they link to if the node is edited
or replaced in an Add or Delete operation.  

* Backing nodes

These nodes are soft links back to a node in the backing store, containing the
key and the hash of the node.  They are expanded into one of the three main
nodes if the node is read.

When the trie is hashed, these nodes contain their own hash and thus do not
require the hash algorithm to descend that subtree from the backing store any
further.  In this way the hashing function continues to function without
loading the entire trie structure into memory.

When operated on, backing nodes deserialize themselves from the backing store
by calling `get`, which calls a node deserialization method to determine the
node type (from a prefix), and then the specific node type handles the rest of
the deserialization into a node object. This deserialization provides a hash
value to the new node object, as this value is recorded from the
deserialization of its parent node in the trie when the backing node was
constructed.  

If the deserialized branch or extension node points at another node, that
"pointed-at" node reference is stored as another backing node with its key set
to the location in the trie and with its hash set to the SHA-256 hash of the
node taken from the store bytes. If later trie operations need to descend
through these nodes, they are in turn deseralized as described.

### Trie child and merge operations

Child tries are represented as tries with unexplored node references ("parent
nodes") that point back to unmodified node objects of the parent trie. 

Obtaining a child trie from a trie allows the user to easily dispose of stacks
of changes to a child trie at an arbitrary time while retaining the parent.

Parent tries must remain read-only until after the child is disregared or until
after it is merged back into the parent.

When a child trie is initialized, it is anchored to the parent by initializing
its root node to a parent node object that points back to the parent trie root
node object. Accessing this parent node to service an Add or Delete operation
converts the parent node into a copy of the original parent node (with the
`child` node method), and from there the operations continue with the copy
holding any alterations.

When merging child tries back into their parents, the in-memory node objects in
a child trie undergoes a traversal when merging back into the parent. This
search aims to identify parent nodes, which are then replaced by their original
references, effectively stitching the child trie's modifications into the
parent trie. 

Node deletion lists are propagated into the parent in a merge to be handled by
a future parent backstore commit.

### `statetrie` cache operations
*  Eviction

Nodes can be evicted from memory during Commit and all their subtree replaced by
a single backing node according to eviction policy, which is the binary output of 
function which operates on each node.  There are three eviction strategies, EvictAll,
EvictNone, and EvictLevel(n), which evicts nodes with a key length of n. Evicted nodes 
would have to be read back in from the backing store to resume operations on them.  

Eviction of a node only affects branch and extension nodes, which replace their
children with backing nodes after they are committed.

* Preloading

Normally only part of the trie is kept in memory.  However, the trie can sweep
nodes out of the backstore and into memory by calling Preload.  

Preload loads into trie memory all backing nodes reachable from the root that
keys with length less than or equal to the one provided by obtaining them from
the store.

In a full (and therefore balanced) trie, preloading lengths has the effect of 
loading the top levels of the trie. 

### Raising nodes

Some delete operations require a trie transformation that relocates a node
"earlier" in the trie. These relocations shorten the key from the original key.
Relocating a leaf node merely reassigns the key value and adjusts the ending
key value in the node to compensate. But raising a branch node creates a new
extension node and places it just above the branch node. Raising an extension
node extends its shared key and relocates its key.  Raising a backing node gets
the node from the store and then immediately raises it.  Similarly, raising a
parent node copies the parent node by evoking `child` on it and immediately
raises it.  After a raising operation, there is guaranteed to be a node at the
new location in the trie.

### Backing stores

In large backing store tries, only a fraction of the trie nodes are represented
by in-memory trie node objects.  The rest of the nodes live in the backing
store.

Backing stores are kv stores which maintain all the mapping between committed
trie keys and node serialization data (which includes the hash of the key
value).

Backing stores must "set" byte data containing serialized nodes, and "get"
nodes back from the store by deserializing them into trie nodes that (may)
contain deferred references to further backing store nodes.  A simple backing
store is a golang map from strings to nodes which uses the provided node
serialization / deserialization utilites.  This is implemented as
`memoryBackstore`.

`BatchStart()` methods on backing stores called before any store set operations
are begun, and `BatchEnd()` is called after there are no more, to allow for
preparations around batch commits. 

Committing the trie to the backing store will trigger hashing of the trie, as
committing requires node serialization and node serialization requires the hash
of subtree elements in branch and extension nodes.

