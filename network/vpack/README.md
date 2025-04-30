# Stateless *vpack* wire format

This document specifies the byte‑level (on‑wire) layout produced by `StatelessEncoder.CompressVote` and accepted by `StatelessDecoder.DecompressVote`.
The goal is to minimize vote size while retaining a 1‑to‑1, loss‑free mapping to the canonical msgpack representation of `agreement.UnauthenticatedVote`.

---

## 1. High‑level structure

```
+---------+-----------------+---------------------+--------------------------+
| Header  | VrfProof ("pf") | rawVote ("r")       | OneTimeSignature ("sig") |
| 2 bytes | 80 bytes        | variable length     | 256 bytes                |
+---------+-----------------+------------------------------------------------+
```

All fields appear exactly once, and in the fixed order above. The presence of optional sub‑fields inside `rawVote` are indicated by a 1‑byte bitmask in the header.

---

## 2. Header (2 bytes)

| Offset | Description                                                    |
| ------ | -------------------------------------------------------------- |
| `0`    | Presence flags for optional values (LSB first, see table).     |
| `1`    | Reserved, currently zero.                                      |

### 2.1 Bit‑mask layout (byte 0)

| Bit | Flag        | Field enabled                    | Size needed |
| --- | ----------- | -------------------------------- | ----------- |
| 0   | `bitPer`    | `r.per` (varuint)                | 1 – 9       |
| 1   | `bitDig`    | `r.prop.dig` (32-byte digest)    | 32          |
| 2   | `bitEncDig` | `r.prop.encdig` (32-byte digest) | 32          |
| 3   | `bitOper`   | `r.prop.oper` (varuint)          | 1 – 9       |
| 4   | `bitOprop`  | `r.prop.oprop` (32-byte address) | 32          |
| 5   | `bitStep`   | `r.step` (varuint)               | 1 - 9       |

*Variable‑length integers* use msgpack varuint encoding:
- `fixint` (≤ 127), 1 byte in length
- `uint8` 2 bytes in length (1 for marker, 1 for value)
- `uint16` 3 bytes in length (1 for marker, 2 for value)
- `uint32` 5 bytes in length (1 for marker, 4 for value)
- `uint64` 9 bytes in length (1 for marker, 8 for value)

---

## 3. Field serialization order

After the 2-byte header, the encoder emits values in the following order:

1. `pf` VRF credential (80 bytes), always present.
1. `r.per` period (varuint), if `bitPer` is set.
1. `r.prop.dig` proposal's digest (32 bytes), if `bitDig` is set.
1. `r.prop.encdig` encoded proposal's digest (32 bytes), if `bitEncDig` is set.
1. `r.prop.oper` proposal's original period (32 bytes), if `bitOper` is set.
1. `r.prop.oprop` proposal's original proposer (32 bytes), if `bitOprop` is set.
1. `r.rnd` round number (varuint), always present.
1. `r.snd` sender address (32 bytes) always present.
1. `r.step` step (varuint), if `bitStep` is set.
1. `sig.p` public key (32 bytes), always present.
1. `sig.p1s` signature of offset ID (64 bytes), always present.
1. `sig.p2` second-tier public key (32 bytes), always present.
1. `sig.p2s` signature of batch ID (64 bytes), always present.
1. `sig.s` signature of message under key p (64 bytes), always present.
