package gen

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

type Topics struct {
	structs map[string][]string
}

func (t *Topics) Bytes() []byte {
	outbuf := bytes.NewBuffer(make([]byte, 0, 4096))
	outbuf.WriteString("// The following msgp objects are implemented in this file:\n")

	keys := []string{}
	for key := range t.structs {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		values := t.structs[key]
		outbuf.WriteString(fmt.Sprintf("// %s\n", key))
		spaces := len(key) / 2
		for _, value := range values {
			outbuf.WriteString("// ")
			outbuf.WriteString(strings.Repeat(" ", spaces))
			outbuf.WriteString(fmt.Sprintf("|-----> %s\n", value))
		}
		outbuf.WriteString("//\n")
	}
	outbuf.WriteString("\n")
	return outbuf.Bytes()
}

func (t *Topics) Add(key, value string) {
	if t.structs == nil {
		t.structs = make(map[string][]string)
	}
	if key[0] == '*' {
		key = key[1:]
		value = "(*) " + value
	}
	t.structs[key] = append(t.structs[key], value)
}
