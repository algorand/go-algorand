<!-- markdownlint-disable MD024 -->

# JSON Spec

A valid JSON text must follow the grammar defined in [RFC7159](https://www.rfc-editor.org/rfc/rfc7159.html)

Additional specifications used by **json_ref** that are extensions to the RFC7159 grammar are listed below.

## File Encoding

- Only utf-8 encoded are accepted
- The byte order mark (BOM), "\uFEFF", is not allowed at the beginning of a JSON text
- Raw non-unicode characters not accepted

### Invalid JSON text

```json
\uFEFF{"key0": 1}
```

```json
{"key0": "\uFF"}
```

### Object

#### duplicate key

Duplicate keys at the top level result in an error; however, duplicate keys nested at a lower level are ignored.

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

- Only integers between 0 and 2^64-1 are accepted
- All other values result in an error

#### Special Values

- `null`, `true`, `false` are the only accepted special values.
- other special values such as `NaN`,`+Inf`,`-Inf` are not accepted

#### Exponential Notation

Exponential notation is not accepted

#### Invalid JSON text

```json
{"key": 1.2E-6}
```

```json
{"key": 0.2E+8}
```

##### Hex values

Hex values are not accepted

#### Invalid JSON text

```json
{"key0": 0x1}
```

```json
{"key0": 0xFF}
```

### Trailing Commas

Trailing commas are not accepted.

#### Invalid JSON text

```json
{"key": 4160,,,}
```

```json
{"key": "algo",,,}
```

### Comment

Comment blocks are not accepted.

#### Invalid JSON text

```json
{"key0": /*comment*/"algo"}
```

```json
{"key0": [1,/*comment*/,3]}
```

### White Spaces

- space, tab(`\t`), new line(`\n`) and carriage return(`\r`) are allowed
- form feed(`\f`) is not allowed

### Escaped Characters

- control chars (U+0000 - U+001F) must be escaped
- surrogate pairs are accepted
- escaped invalid characters are replaced by replacement character (U+FFFD)

#### Example

a valid surrogate pair

```json
{"key0": "\uD801\udc37"}
```

replaced by U+FFFD

```json
{"key0": "\uD800\uD800n"}
```
