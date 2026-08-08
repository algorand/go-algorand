<!-- markdownlint-disable MD024 -->

# JSON Spec

A valid JSON text must follow the grammar defined in [RFC7159](https://www.rfc-editor.org/rfc/rfc7159.html)

Additional specifications used by **json_ref** that are extensions to the RFC7159 grammar are listed below.

Two kinds of rules follow. **Whole-text** rules are enforced when `json_ref`
parses the JSON text, so violating one anywhere in the object causes an error.
**Extraction** rules are enforced only on the value that the requested key refers
to; values elsewhere in the object are checked against the grammar but are never
interpreted, so an extraction rule they violate goes unnoticed. Each section
below says which kind it is.

## File Encoding

Whole-text, except as noted.

- The text is expected to be utf-8 encoded; utf-16 and utf-32 texts are rejected
- The byte order mark (BOM), "\uFEFF", is not allowed at the beginning of a JSON text
- utf-8 validity is not otherwise enforced: raw bytes that are not valid utf-8
  parse without error, and on extraction of a string value each such byte is
  replaced by the replacement character (U+FFFD)

### Invalid JSON text

```json
\uFEFF{"key0": 1}
```

```json
{"key0": "\uFF"}
```

### Object

#### duplicate key

Whole-text. Duplicate keys at the top level result in an error. Duplicate keys
nested at a lower level are accepted; extracting such an object returns its raw
bytes, duplicate keys included.

#### Invalid JSON text

```json
{"key0": 1,"key0": 2}
```

#### Acceptable JSON text

```json
{"key0": 1,"key1": {"key2":2,"key2":"10"}}
```

### Numbers

#### Range

Extraction.

- Only integers between 0 and 2^64-1 are accepted
- All other values result in an error

#### Special Values

- `true` and `false` are accepted (whole-text)
- `null` parses, but extracting a key whose value is `null` always results in an
  error, whatever type is requested (extraction)
- other special values such as `NaN`,`+Inf`,`-Inf` are not accepted (whole-text)

#### Exponential Notation

Extraction. Exponential notation is not accepted

#### Invalid JSON text

```json
{"key": 1.2E-6}
```

```json
{"key": 0.2E+8}
```

##### Hex values

Whole-text. Hex values are not accepted

#### Invalid JSON text

```json
{"key0": 0x1}
```

```json
{"key0": 0xFF}
```

### Trailing Commas

Whole-text. Trailing commas are not accepted.

#### Invalid JSON text

```json
{"key": 4160,,,}
```

```json
{"key": "algo",,,}
```

### Comment

Whole-text. Comment blocks are not accepted.

#### Invalid JSON text

```json
{"key0": /*comment*/"algo"}
```

```json
{"key0": [1,/*comment*/,3]}
```

### White Spaces

Whole-text.

- space, tab(`\t`), new line(`\n`) and carriage return(`\r`) are allowed
- form feed(`\f`) is not allowed

### Escaped Characters

These rules concern `\` escape sequences inside strings. Escape sequences are
plain ASCII in the raw text, so they never affect its utf-8 validity; the rules
below are about what the sequences decode to.

- a truncated escape sequence, or one that uses an unknown escape letter, is
  rejected (whole-text). `\u` followed by four characters that are not all hex
  digits is not rejected at parse, but extracting a string value that contains
  one is an error. In a key, it becomes the replacement character (U+FFFD)
- control chars (U+0000 - U+001F) must be escaped (extraction)
- an escaped surrogate pair (`\uD800`-`\uDBFF` followed by `\uDC00`-`\uDFFF`) is
  accepted, and decodes to the single codepoint it represents (whole-text)
- an escaped surrogate that is not part of such a pair is accepted at parse, but
  is replaced by the replacement character (U+FFFD) on extraction, since a lone
  surrogate is not a valid codepoint

#### Example

a valid escaped surrogate pair, decoding to U+10437

```json
{"key0": "\uD801\udc37"}
```

lone surrogates, each replaced by U+FFFD on extraction

```json
{"key0": "\uD800\uD800n"}
```
