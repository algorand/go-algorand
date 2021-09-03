// +build compare_purego_implementation

package crypto

import "fmt"

func init() {
	fmt.Println("purego: Compiled with comparison enabled for Verify() implementation.")
	validateGoVerify = func(pk VrfPubkey, p VrfProof, message Hashable, ok bool, out VrfOutput) {
		goOk, goOut := pk.verifyBytesGo(p, hashRep(message))
		if out != goOut {
			panic(fmt.Sprintf("Go and C implementations differ: %x %x %x %x %x\n", pk, p, message, out, goOut))
		}
		if ok != goOk {
			panic(fmt.Sprintf("Go and C implementations differ: %x %x %x\n", pk, p, message))
		}
	}
}
