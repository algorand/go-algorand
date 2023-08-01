// Copyright (C) 2019-2023 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package logic

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/algorand/go-algorand/test/partitiontest"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const pairingNonsense = `
 pushbytes 0x012345
 dup
 ec_add BN254g1
 dup
 ec_scalar_mul BLS12_381g2
 dup
 ec_pairing_check BN254g1
 ec_multi_exp BLS12_381g2
 ec_subgroup_check BLS12_381g1
 ec_map_to BN254g2
`

const pairingCompiled = "800301234549e00049e10349e200e303e402e501"

func bn254G1sToBytes(g1s []bn254.G1Affine) []byte {
	var out []byte
	for i := range g1s {
		out = append(out, bn254G1ToBytes(&g1s[i])...)
	}
	return out
}

func bn254G2sToBytes(g2s []bn254.G2Affine) []byte {
	var out []byte
	for i := range g2s {
		out = append(out, bn254G2ToBytes(&g2s[i])...)
	}
	return out
}

func bls12381G1sToBytes(g1s []bls12381.G1Affine) []byte {
	var out []byte
	for i := range g1s {
		out = append(out, bls12381G1ToBytes(&g1s[i])...)
	}
	return out
}

func bls12381G2sToBytes(g2s []bls12381.G2Affine) []byte {
	var out []byte
	for i := range g2s {
		out = append(out, bls12381G2ToBytes(&g2s[i])...)
	}
	return out
}

type pairConstants [2]curveConstants

type curveConstants struct {
	name string
	size uint64
	q    *big.Int // the size of the entire curve
	r    *big.Int // size of the main prime order group
	rand func() []byte
}

var bnCurves = pairConstants{
	{"BN254g1", 64, bn254fp.Modulus(), bn254fr.Modulus(),
		func() []byte { p := bn254RandomG1(); return bn254G1ToBytes(&p) }},
	{"BN254g2", 128, bn254fp.Modulus(), bn254fr.Modulus(),
		func() []byte { p := bn254RandomG2(); return bn254G2ToBytes(&p) }},
}
var blsCurves = pairConstants{
	{"BLS12_381g1", 96, bls12381fp.Modulus(), bls12381fr.Modulus(),
		func() []byte { p := bls12381RandomG1(); return bls12381G1ToBytes(&p) }},
	{"BLS12_381g2", 192, bls12381fp.Modulus(), bls12381fr.Modulus(),
		func() []byte { p := bls12381RandomG2(); return bls12381G2ToBytes(&p) }},
}

func tealBytes(b []byte) string {
	return fmt.Sprintf("byte 0x%s;", hex.EncodeToString(b))
}

func tealInt(i uint64) string {
	return fmt.Sprintf("int %d;", i)
}

func TestEcAdd(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	curves := []curveConstants{bnCurves[0], bnCurves[1], blsCurves[0], blsCurves[1]}
	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			pt1 := tealBytes(c.rand())
			pt2 := tealBytes(c.rand())
			add := "ec_add " + c.name + ";"
			testAccepts(t, pt1+pt2+add+"len", pairingVersion)
			// rando + 0 = rando
			testAccepts(t, pt1+tealInt(c.size)+"bzero;"+add+pt1+"==", pairingVersion)
			// bad lengths, arg 2
			testPanics(t, pt1+tealInt(c.size+1)+"bzero;"+add+pt1+"==", pairingVersion, "bad length")
			testPanics(t, pt1+tealInt(c.size-1)+"bzero;"+add+pt1+"==", pairingVersion, "bad length")
			// 0 + rando = rando
			testAccepts(t, tealInt(c.size)+"bzero;"+pt1+add+pt1+"==", pairingVersion)
			// bad lengths, arg 1
			testPanics(t, tealInt(c.size+1)+"bzero;"+pt1+add+pt1+"==", pairingVersion, "bad length")
			testPanics(t, tealInt(c.size-1)+"bzero;"+pt1+add+pt1+"==", pairingVersion, "bad length")

			// 0 + 0 = 0
			testAccepts(t, tealInt(c.size)+"bzero; dupn 2;"+add+"==", pairingVersion)

			// ought to test "on curve, but not in subgroup" but bn254g1 has no such points
		})
	}

}

func TestEcScalarMul(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	curves := []curveConstants{bnCurves[0], bnCurves[1], blsCurves[0], blsCurves[1]}
	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			pt := tealBytes(c.rand())
			mul := "ec_scalar_mul " + c.name + ";"

			testAccepts(t, pt+"int 0; itob;"+mul+tealInt(c.size)+"bzero; ==", pairingVersion)
			testPanics(t, "int 63; bzero; int 1; itob;"+mul+"len", pairingVersion, "bad length")
			testPanics(t, "int 65; bzero; int 1; itob;"+mul+"len", pairingVersion, "bad length")
			//testPanics(t, pt+"int 33; bzero;"+mul+tealInt(c.size)+"bzero; ==", pairingVersion, "ec_scalar_mul scalar len 33")
			// multiply by prime order gives 0,0 (the "point at infinity")
			r := tealBytes(c.r.Bytes())
			testAccepts(t, pt+r+mul+tealInt(c.size)+"bzero; ==", pairingVersion)

			// multiplying by 1 does nothing
			testAccepts(t, pt+"int 1; itob;"+mul+pt+"==", pairingVersion)

			// multiplying by r+1 does nothing
			rp1 := big.NewInt(1)
			rp1.Add(rp1, c.r)
			testAccepts(t, pt+tealBytes(rp1.Bytes())+mul+pt+"==", pairingVersion)

			// shows that "short" big-endian scalars are ok
			testAccepts(t, pt+`
dup
int 32; bzero; int 7; itob; b|;`+mul+`
swap
int 7; itob;`+mul+`
==
`, pairingVersion)
		})
	}
}

func TestPairCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	t.Run("bn254", func(t *testing.T) {
		t.Parallel()
		var g1GenNeg bn254.G1Affine
		g1GenNeg.Neg(&bnG1Gen)
		g1points := []bn254.G1Affine{g1GenNeg, bnG1Gen}
		g2points := []bn254.G2Affine{bnG2Gen, bnG2Gen}
		// -1 g1 g2 + g1 g2 = 0
		g1bytes := tealBytes(bn254G1sToBytes(g1points))
		g2bytes := tealBytes(bn254G2sToBytes(g2points))

		testAccepts(t, g1bytes+g2bytes+`ec_pairing_check BN254g1`, pairingVersion)
		testAccepts(t, g2bytes+g1bytes+`ec_pairing_check BN254g2`, pairingVersion)
	})

	t.Run("bls12-381", func(t *testing.T) {
		t.Parallel()
		var g1GenNeg bls12381.G1Affine
		g1GenNeg.Neg(&blsG1Gen)
		g1points := []bls12381.G1Affine{g1GenNeg, blsG1Gen}
		g2points := []bls12381.G2Affine{blsG2Gen, blsG2Gen}
		// -1 g1 g2 + g1 g2 = 0
		g1bytes := tealBytes(bls12381G1sToBytes(g1points))
		g2bytes := tealBytes(bls12381G2sToBytes(g2points))

		testAccepts(t, g1bytes+g2bytes+`ec_pairing_check BLS12_381g1`, pairingVersion)
		testAccepts(t, g2bytes+g1bytes+`ec_pairing_check BLS12_381g2`, pairingVersion)
	})
}

func TestEcMultiExp(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	curves := []curveConstants{bnCurves[0], bnCurves[1], blsCurves[0], blsCurves[1]}
	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			pt := tealBytes(c.rand())
			multiexp := "ec_multi_exp " + c.name + ";"
			mul := "ec_scalar_mul " + c.name + ";"

			// multiply by 0 gives 0
			testAccepts(t, pt+"int 32; bzero;"+multiexp+tealInt(c.size)+"bzero; ==", pairingVersion)
			// multiply by 1 gives 1
			testAccepts(t, pt+"int 32; bzero; int 1; itob; b|;"+multiexp+pt+"==", pairingVersion)
			// two multiplies by 1 gives same as multiply 2
			testAccepts(t, pt+"dup; concat;  int 32; bzero; int 1; itob; b|; dup; concat;"+multiexp+
				pt+"byte 0x02;"+mul+"==", pairingVersion)
		})
	}
}

// TestAgreement ensures that scalar muls and adds is the same as multi_exp
func TestAgreement(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	k1 := "2F53" // any old int

	curves := []curveConstants{bnCurves[0], bnCurves[1], blsCurves[0], blsCurves[1]}
	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			pt1 := tealBytes(c.rand())
			pt2 := tealBytes(c.rand())

			multiexp := "ec_multi_exp " + c.name + ";"
			mul := "ec_scalar_mul " + c.name + ";"
			add := "ec_add " + c.name + ";"

			// Try a normal k2 and one very big one
			for _, k2 := range []string{"372D82", strings.Repeat("FE", 32)} {
				testAccepts(t, fmt.Sprintf(`
      %s
      byte 0x%s;`+mul+`
      %s
      byte 0x%s;`+mul+add+`
      %s; %s; concat
      int 32; bzero; byte 0x%s; b|;
      int 32; bzero; byte 0x%s; b|;
      concat;`+multiexp+`==`,
					pt1, k1, pt2, k2,
					pt1, pt2, k1, k2), pairingVersion)
			}
		})
	}
}

func TestSubgroupCheckInfinity(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	curves := []curveConstants{bnCurves[0], bnCurves[1], blsCurves[0], blsCurves[1]}
	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			testAccepts(t, tealInt(c.size)+"bzero; ec_subgroup_check "+c.name, pairingVersion)
			testPanics(t, tealInt(c.size+1)+"bzero; ec_subgroup_check "+c.name, pairingVersion, "bad length")
			testPanics(t, tealInt(c.size-1)+"bzero; ec_subgroup_check "+c.name, pairingVersion, "bad length")
		})
	}
}

func TestSubgroupCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	curves := []curveConstants{bnCurves[0], bnCurves[1], blsCurves[0], blsCurves[1]}
	for _, c := range curves {
		pt := tealBytes(c.rand())
		testAccepts(t, pt+"ec_subgroup_check "+c.name, pairingVersion)

		/* On BN curve, subgroup == on curve, we can't create a g1bytes that makes this Accept
		pt = ???
		testAccepts(t, g1bytes1+"ec_subgroup_check BN254g1; !", pairingVersion)
		*/

		// surely no longer in subgroup, but also not likely on curve, so we get a panic
		changed := strings.Replace(pt, "a", "f", 1)
		changed = strings.Replace(changed, "c", "a", 1)
		testPanics(t, changed+"ec_subgroup_check "+c.name+"; !", pairingVersion, "point not on curve")
	}
}

func TestMapTo(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, curve := range []string{"BN254g1", "BLS12_381g1"} {
		testAccepts(t, fmt.Sprintf("int 27; itob; ec_map_to %s; ec_subgroup_check %s",
			curve, curve), pairingVersion)
	}

}

// TestSlowMapTo tests the G2 MapTo functions, which require more budget, and
// therefore mess with a global and prevent t.Parallel.
func TestSlowMapTo(t *testing.T) {
	partitiontest.PartitionTest(t)
	//nolint:paralleltest // Not parallel because it modifies testLogicBudget

	was := testLogicBudget
	testLogicBudget = 1_000_000
	defer func() { testLogicBudget = was }()
	for _, curve := range []string{"BN254g2", "BLS12_381g2"} {
		testPanics(t, fmt.Sprintf("int 27; itob; ec_map_to %s; ec_subgroup_check %s",
			curve, curve), pairingVersion, "bad encoded element length")
	}

	testAccepts(t, `
int 32; bzero
int 67; itob; b|
int 32; bzero
int 2783; itob; b|
concat
ec_map_to BN254g2
ec_subgroup_check BN254g2`, pairingVersion)

	testAccepts(t, `
int 48; bzero
int 67; itob; b|
int 48; bzero
int 2783; itob; b|
concat
ec_map_to BLS12_381g2
ec_subgroup_check BLS12_381g2`, pairingVersion)

}

func BenchmarkBn254(b *testing.B) {
	if pairingVersion > LogicVersion {
		b.Skip()
	}

	was := eccMontgomery.NbTasks
	eccMontgomery.NbTasks = 1
	defer func() { eccMontgomery.NbTasks = was }()

	fpbytes := fmt.Sprintf("byte 0x%s\n",
		strings.Repeat("00", 1)+strings.Repeat("22", bn254fpSize-1))
	fp2bytes := fpbytes + fpbytes + "concat\n"

	kbytes := make([]byte, scalarSize)
	rand.Read(kbytes)
	byteK := tealBytes(kbytes)

	g1point := bn254RandomG1()
	g1bytes := bn254G1ToBytes(&g1point)
	byteG1 := tealBytes(g1bytes)

	g2point := bn254RandomG2()
	g2bytes := bn254G2ToBytes(&g2point)
	byteG2 := tealBytes(g2bytes)

	b.Run("g1 add", func(b *testing.B) {
		benchmarkOperation(b, byteG1, "dup; ec_add BN254g1", "pop; int 1")
	})
	b.Run("g2 add", func(b *testing.B) {
		benchmarkOperation(b, byteG2, "dup; ec_add BN254g2", "pop; int 1")
	})

	b.Run("g1 scalar_mul", func(b *testing.B) {
		benchmarkOperation(b, byteG1, byteK+"ec_scalar_mul BN254g1", "pop; int 1")
	})

	b.Run("g2 scalar_mul", func(b *testing.B) {
		benchmarkOperation(b, byteG2, byteK+"ec_scalar_mul BN254g2", "pop; int 1")
	})

	b.Run("g1 pairing f", func(b *testing.B) {
		benchmarkOperation(b, "", byteG1+byteG2+"ec_pairing_check BN254g1; !; assert", "int 1")
	})
	b.Run("g2 pairing f", func(b *testing.B) {
		benchmarkOperation(b, "", byteG2+byteG1+"ec_pairing_check BN254g2; !; assert", "int 1")
	})

	var g1GenNeg bn254.G1Affine
	g1GenNeg.Neg(&bnG1Gen)
	g1points := []bn254.G1Affine{g1GenNeg, bnG1Gen}
	g2points := []bn254.G2Affine{bnG2Gen, bnG2Gen}
	// -1 g1 g2 + g1 g2 = 0
	g1pbytes := tealBytes(bn254G1sToBytes(g1points))
	g2pbytes := tealBytes(bn254G2sToBytes(g2points))

	b.Run("g1 pairing t2", func(b *testing.B) {
		benchmarkOperation(b, "", g1pbytes+g2pbytes+"ec_pairing_check BN254g1; assert", "int 1")
	})
	b.Run("g2 pairing t2", func(b *testing.B) {
		benchmarkOperation(b, "", g2pbytes+g1pbytes+"ec_pairing_check BN254g2; assert", "int 1")
	})
	b.Run("g1 pairing t4", func(b *testing.B) {
		benchmarkOperation(b, "",
			g1pbytes+g1pbytes+"concat;"+g2pbytes+g2pbytes+"concat; ec_pairing_check BN254g1; assert", "int 1")
	})
	b.Run("g2 pairing t4", func(b *testing.B) {
		benchmarkOperation(b, "",
			g2pbytes+g2pbytes+"concat;"+g1pbytes+g1pbytes+"concat; ec_pairing_check BN254g2; assert", "int 1")
	})

	for _, size := range []int{1, 10, 20, 30, 40, 50} {
		g1s := byteRepeat(g1bytes, size)
		ks := byteRepeat(kbytes, size)
		b.Run(fmt.Sprintf("g1 multi_exp %d", size), func(b *testing.B) {
			benchmarkOperation(b, "", g1s+ks+"ec_multi_exp BN254g1; pop", "int 1")
		})
	}
	for _, size := range []int{1, 5, 10, 15, 20, 25} {
		g2s := byteRepeat(g2bytes, size)
		ks := byteRepeat(kbytes, size)
		b.Run(fmt.Sprintf("g2 multi_exp %d", size), func(b *testing.B) {
			benchmarkOperation(b, "", g2s+ks+"ec_multi_exp BN254g2; pop", "int 1")
		})
	}

	b.Run("g1 subgroup", func(b *testing.B) {
		benchmarkOperation(b, "", byteG1+"ec_subgroup_check BN254g1; pop", "int 1")
	})
	b.Run("g2 subgroup", func(b *testing.B) {
		benchmarkOperation(b, "", byteG2+"ec_subgroup_check BN254g2; pop", "int 1")
	})

	b.Run("g1 map to", func(b *testing.B) {
		benchmarkOperation(b, "", fpbytes+"ec_map_to BN254g1; pop", "int 1")
	})
	b.Run("g2 map to", func(b *testing.B) {
		benchmarkOperation(b, "", fp2bytes+"ec_map_to BN254g2; pop", "int 1")
	})

}

func bn254RandomG1() bn254.G1Affine {
	var fp bn254fp.Element
	fp.SetRandom()
	return bn254.MapToG1(fp)
}

func bn254RandomG2() bn254.G2Affine {
	fp2 := bn254.G2Affine{}.X // no way to declare an fptower.E2
	fp2.SetRandom()
	return bn254.MapToG2(fp2)
}

func byteRepeat(bytes []byte, count int) string {
	return "byte 0x" + strings.Repeat(hex.EncodeToString(bytes), count) + "\n"
}

func BenchmarkBls12381(b *testing.B) {
	was := eccMontgomery.NbTasks
	eccMontgomery.NbTasks = 0
	defer func() { eccMontgomery.NbTasks = was }()

	fpbytes := fmt.Sprintf("byte 0x%s\n",
		strings.Repeat("00", 1)+strings.Repeat("22", bls12381fpSize-1))
	fp2bytes := fpbytes + fpbytes + "concat\n"

	kbytes := make([]byte, scalarSize)
	rand.Read(kbytes)
	byteK := tealBytes(kbytes)

	g1point := bls12381RandomG1()
	g1bytes := bls12381G1ToBytes(&g1point)
	byteG1 := tealBytes(g1bytes)

	g2point := bls12381RandomG2()
	g2bytes := bls12381G2ToBytes(&g2point)
	byteG2 := byteRepeat(g2bytes, 1)

	b.Run("g1 add", func(b *testing.B) {
		benchmarkOperation(b, byteG1, "dup; ec_add BLS12_381g1", "pop; int 1")
	})
	b.Run("g2 add", func(b *testing.B) {
		benchmarkOperation(b, byteG2, "dup; ec_add BLS12_381g2", "pop; int 1")
	})

	b.Run("g1 scalar_mul", func(b *testing.B) {
		benchmarkOperation(b, byteG1, byteK+"ec_scalar_mul BLS12_381g1", "pop; int 1")
	})
	b.Run("g2 scalar_mul", func(b *testing.B) {
		benchmarkOperation(b, byteG2, byteK+"ec_scalar_mul BLS12_381g2", "pop; int 1")
	})

	b.Run("g1 pairing f", func(b *testing.B) {
		benchmarkOperation(b, "", byteG1+byteG2+"ec_pairing_check BLS12_381g1; pop", "int 1")
	})
	b.Run("g2 pairing f", func(b *testing.B) {
		benchmarkOperation(b, "", byteG2+byteG1+"ec_pairing_check BLS12_381g2; pop", "int 1")
	})

	var g1GenNeg bls12381.G1Affine
	g1GenNeg.Neg(&blsG1Gen)
	g1points := []bls12381.G1Affine{g1GenNeg, blsG1Gen}
	g2points := []bls12381.G2Affine{blsG2Gen, blsG2Gen}
	// -1 g1 g2 + g1 g2 = 0
	g1pbytes := tealBytes(bls12381G1sToBytes(g1points))
	g2pbytes := tealBytes(bls12381G2sToBytes(g2points))

	b.Run("g1 pairing t2", func(b *testing.B) {
		benchmarkOperation(b, "", g1pbytes+g2pbytes+"ec_pairing_check BLS12_381g1; assert", "int 1")
	})
	b.Run("g2 pairing t2", func(b *testing.B) {
		benchmarkOperation(b, "", g2pbytes+g1pbytes+"ec_pairing_check BLS12_381g2; assert", "int 1")
	})
	b.Run("g1 pairing t4", func(b *testing.B) {
		benchmarkOperation(b, "",
			g1pbytes+g1pbytes+"concat;"+g2pbytes+g2pbytes+"concat; ec_pairing_check BLS12_381g1; assert", "int 1")
	})
	b.Run("g2 pairing t4", func(b *testing.B) {
		benchmarkOperation(b, "",
			g2pbytes+g2pbytes+"concat;"+g1pbytes+g1pbytes+"concat; ec_pairing_check BLS12_381g2; assert", "int 1")
	})

	for _, size := range []int{1, 5, 10, 15, 20, 25} {
		g1s := byteRepeat(g1bytes, size)
		ks := byteRepeat(kbytes, size)
		b.Run(fmt.Sprintf("g1 multi_exp %d", size), func(b *testing.B) {
			benchmarkOperation(b, "", g1s+ks+"ec_multi_exp BLS12_381g1; pop", "int 1")
		})
	}
	for _, size := range []int{1, 3, 5, 7, 9, 11} {
		g2s := byteRepeat(g2bytes, size)
		ks := byteRepeat(kbytes, size)
		b.Run(fmt.Sprintf("g2 multi_exp %d", size), func(b *testing.B) {
			benchmarkOperation(b, "", g2s+ks+"ec_multi_exp BLS12_381g2; pop", "int 1")
		})
	}

	b.Run("g1 subgroup", func(b *testing.B) {
		benchmarkOperation(b, "", byteG1+"ec_subgroup_check BLS12_381g1; pop", "int 1")
	})
	b.Run("g2 subgroup", func(b *testing.B) {
		benchmarkOperation(b, "", byteG2+"ec_subgroup_check BLS12_381g2; pop", "int 1")
	})

	b.Run("g1 map to", func(b *testing.B) {
		benchmarkOperation(b, "", fpbytes+"ec_map_to BLS12_381g1; pop", "int 1")
	})
	b.Run("g2 map to", func(b *testing.B) {
		benchmarkOperation(b, "", fp2bytes+"ec_map_to BLS12_381g2; pop", "int 1")
	})
}

func bls12381RandomG1() bls12381.G1Affine {
	var fp bls12381fp.Element
	fp.SetRandom()
	return bls12381.MapToG1(fp)
}

func bls12381RandomG2() bls12381.G2Affine {
	fp2 := bls12381.G2Affine{}.X // no way to declare an fptower.E2
	fp2.SetRandom()
	return bls12381.MapToG2(fp2)
}

var bnG1Gen bn254.G1Affine
var bnG2Gen bn254.G2Affine

func init() {
	var g1GenJac bn254.G1Jac
	var g2GenJac bn254.G2Jac

	g1GenJac.X.SetOne()
	g1GenJac.Y.SetUint64(2)
	g1GenJac.Z.SetOne()

	g2GenJac.X.SetString(
		"10857046999023057135944570762232829481370756359578518086990519993285655852781",
		"11559732032986387107991004021392285783925812861821192530917403151452391805634")
	g2GenJac.Y.SetString(
		"8495653923123431417604973247489272438418190587263600148770280649306958101930",
		"4082367875863433681332203403145435568316851327593401208105741076214120093531")
	g2GenJac.Z.SetString("1", "0")

	bnG1Gen.FromJacobian(&g1GenJac)
	bnG2Gen.FromJacobian(&g2GenJac)
}

var blsG1Gen bls12381.G1Affine
var blsG2Gen bls12381.G2Affine

func init() {
	var g1GenJac bls12381.G1Jac
	var g2GenJac bls12381.G2Jac

	g1GenJac.X.SetOne()
	g1GenJac.Y.SetUint64(2)
	g1GenJac.Z.SetOne()

	g1GenJac.X.SetString("3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507")
	g1GenJac.Y.SetString("1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569")
	g1GenJac.Z.SetOne()

	g2GenJac.X.SetString(
		"352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160",
		"3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758")
	g2GenJac.Y.SetString(
		"1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905",
		"927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582")
	g2GenJac.Z.SetString("1", "0")

	blsG1Gen.FromJacobian(&g1GenJac)
	blsG2Gen.FromJacobian(&g2GenJac)
}
