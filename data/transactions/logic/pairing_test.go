// Copyright (C) 2019-2026 Algorand Foundation Ltd.
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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"

	"filippo.io/edwards25519"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"

	"github.com/algorand/go-algorand/data/transactions"
	"github.com/algorand/go-algorand/test/partitiontest"
)

const pairingNonsense = `
 pushbytes 0x012345
 dup
 ec_add BN254g1
 dup
 ec_scalar_mul BLS12_381g2
 dup
 ec_pairing_check BN254g1
 ec_multi_scalar_mul BLS12_381g2
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
			testPanics(t, pt+"int 33; bzero;"+mul+tealInt(c.size)+"bzero; ==", pairingVersion, "ec_scalar_mul scalar len is 33")
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
	//nolint:paralleltest // Not parallel because it modifies testLogicBudget

	was := testLogicBudget
	testLogicBudget = 16 * 20_000
	defer func() { testLogicBudget = was }()

	t.Run("bn254", func(t *testing.T) {
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
	//nolint:paralleltest // Not parallel because it modifies testLogicBudget

	was := testLogicBudget
	testLogicBudget = 16 * 20_000
	defer func() { testLogicBudget = was }()

	curves := []curveConstants{bnCurves[0], bnCurves[1], blsCurves[0], blsCurves[1]}
	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			pt := tealBytes(c.rand())
			multiexp := "ec_multi_scalar_mul " + c.name + ";"
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

func requireBlsG1Eq(t *testing.T, g1points []bls12381.G1Affine, kbytes []byte) {
	b1, err := bls12381G1MultiMulSmall(g1points, kbytes)
	require.NoError(t, err)
	b2, err := bls12381G1MultiMulLarge(g1points, kbytes)
	require.NoError(t, err)
	require.Equal(t, b1, b2)
}

func TestBlsG1LargeSmallEquivalent(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	zero := [32]byte{}
	for i := 1; i < 10; i++ {
		g1points := make([]bls12381.G1Affine, i)
		for j := 0; j < i; j++ {
			g1points[j] = bls12381RandomG1()
		}
		kbytes := make([]byte, i*scalarSize)
		rand.Read(kbytes)
		requireBlsG1Eq(t, g1points, kbytes)
		g1points[0] = bls12381.G1Affine{} // Infinity at 0
		requireBlsG1Eq(t, g1points, kbytes)
		g1points[0] = bls12381RandomG1()    // change back to random
		g1points[i-1] = bls12381.G1Affine{} // Infinity at end
		requireBlsG1Eq(t, g1points, kbytes)
		copy(kbytes, zero[:]) // zero scalar
		requireBlsG1Eq(t, g1points, kbytes)
	}
}

func requireBlsG2Eq(t *testing.T, g2points []bls12381.G2Affine, kbytes []byte) {
	b1, err := bls12381G2MultiMulSmall(g2points, kbytes)
	require.NoError(t, err)
	b2, err := bls12381G2MultiMulLarge(g2points, kbytes)
	require.NoError(t, err)
	require.Equal(t, b1, b2)
}

func TestBlsG2LargeSmallEquivalent(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	zero := [32]byte{}
	for i := 1; i < 10; i++ {
		g2points := make([]bls12381.G2Affine, i)
		for j := 0; j < i; j++ {
			g2points[j] = bls12381RandomG2()
		}
		kbytes := make([]byte, i*scalarSize)
		rand.Read(kbytes)
		requireBlsG2Eq(t, g2points, kbytes)
		g2points[0] = bls12381.G2Affine{} // Infinity at 0
		requireBlsG2Eq(t, g2points, kbytes)
		g2points[0] = bls12381RandomG2()    // change back to random
		g2points[i-1] = bls12381.G2Affine{} // Infinity at end
		requireBlsG2Eq(t, g2points, kbytes)
		copy(kbytes, zero[:]) // zero scalar
		requireBlsG2Eq(t, g2points, kbytes)
	}
}

func requireBnG1Eq(t *testing.T, g1points []bn254.G1Affine, kbytes []byte) {
	b1, err := bn254G1MultiMulSmall(g1points, kbytes)
	require.NoError(t, err)
	b2, err := bn254G1MultiMulLarge(g1points, kbytes)
	require.NoError(t, err)
	require.Equal(t, b1, b2)
}

func TestBnG1LargeSmallEquivalent(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	zero := [32]byte{}
	for i := 1; i < 10; i++ {
		g1points := make([]bn254.G1Affine, i)
		for j := 0; j < i; j++ {
			g1points[j] = bn254RandomG1()
		}
		kbytes := make([]byte, i*scalarSize)
		rand.Read(kbytes)
		requireBnG1Eq(t, g1points, kbytes)
		g1points[0] = bn254.G1Affine{} // Infinity at 0
		requireBnG1Eq(t, g1points, kbytes)
		g1points[0] = bn254RandomG1()    // change back to random
		g1points[i-1] = bn254.G1Affine{} // Infinity at end
		requireBnG1Eq(t, g1points, kbytes)
		copy(kbytes, zero[:]) // zero scalar
		requireBnG1Eq(t, g1points, kbytes)
	}
}

func requireBnG2Eq(t *testing.T, g2points []bn254.G2Affine, kbytes []byte) {
	b1, err := bn254G2MultiMulSmall(g2points, kbytes)
	require.NoError(t, err)
	b2, err := bn254G2MultiMulLarge(g2points, kbytes)
	require.NoError(t, err)
	require.Equal(t, b1, b2)
}

func TestBnG2LargeSmallEquivalent(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	zero := [32]byte{}
	for i := 1; i < 10; i++ {
		g2points := make([]bn254.G2Affine, i)
		for j := 0; j < i; j++ {
			g2points[j] = bn254RandomG2()
		}
		kbytes := make([]byte, i*scalarSize)
		rand.Read(kbytes)
		requireBnG2Eq(t, g2points, kbytes)
		g2points[0] = bn254.G2Affine{} // Infinity at 0
		requireBnG2Eq(t, g2points, kbytes)
		g2points[0] = bn254RandomG2()    // change back to random
		g2points[i-1] = bn254.G2Affine{} // Infinity at end
		requireBnG2Eq(t, g2points, kbytes)
		copy(kbytes, zero[:]) // zero scalar
		requireBnG2Eq(t, g2points, kbytes)
	}
}

// TestAgreement ensures that scalar muls and adds is the same as multi_exp
func TestAgreement(t *testing.T) {
	partitiontest.PartitionTest(t)
	//nolint:paralleltest // Not parallel because it modifies testLogicBudget

	was := testLogicBudget
	testLogicBudget = 16 * 20_000
	defer func() { testLogicBudget = was }()

	k1 := "2F53" // any old int

	curves := []curveConstants{bnCurves[0], bnCurves[1], blsCurves[0], blsCurves[1]}
	for _, c := range curves {
		t.Run(c.name, func(t *testing.T) {
			pt1 := tealBytes(c.rand())
			pt2 := tealBytes(c.rand())

			multiexp := "ec_multi_scalar_mul " + c.name + ";"
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
	testLogicBudget = 16 * 20_000
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
	was := mecLimit.NbTasks
	mecLimit.NbTasks = 1
	defer func() { mecLimit.NbTasks = was }()

	g1point := bn254RandomG1()
	g1teal := tealBytes(bn254G1ToBytes(&g1point))

	g2point := bn254RandomG2()
	g2teal := tealBytes(bn254G2ToBytes(&g2point))

	b.Run("g1 add", func(b *testing.B) {
		benchmarkOperation(b, g1teal, "dup; ec_add BN254g1", "len")
	})
	b.Run("g2 add", func(b *testing.B) {
		benchmarkOperation(b, g2teal, "dup; ec_add BN254g2", "len")
	})

	b.Run("g1 scalar_mul", func(b *testing.B) {
		benchmarkOperation(b, g1teal, "dup; extract 0 32; ec_scalar_mul BN254g1", "len")
	})

	for i := 0; i < 7; i++ {
		size := 1 << uint(i)
		dups := strings.Repeat("dup; concat;", i)
		b.Run(fmt.Sprintf("g1 multi_exp %d", size), func(b *testing.B) {
			benchmarkOperation(b, g1teal, dups+"dup; extract 0 32;"+dups+"ec_multi_scalar_mul BN254g1", "len")
		})
	}

	b.Run("g2 scalar_mul", func(b *testing.B) {
		benchmarkOperation(b, g2teal, "dup; extract 0 32; ec_scalar_mul BN254g2", "len")
	})

	for i := 0; i < 6; i++ {
		size := 1 << uint(i)
		dups := strings.Repeat("dup; concat;", i)
		b.Run(fmt.Sprintf("g2 multi_exp %d", size), func(b *testing.B) {
			benchmarkOperation(b, g2teal, dups+"dup; extract 0 32;"+dups+"ec_multi_scalar_mul BN254g2", "len")
		})
	}

	var g1GenNeg bn254.G1Affine
	g1GenNeg.Neg(&bnG1Gen)
	g1points := []bn254.G1Affine{g1GenNeg, bnG1Gen}
	g2points := []bn254.G2Affine{bnG2Gen, bnG2Gen}
	// -1 g1 g2 + g1 g2 = 0
	g1pbytes := tealBytes(bn254G1sToBytes(g1points))
	g2pbytes := tealBytes(bn254G2sToBytes(g2points))

	b.Run("pairing 1", func(b *testing.B) {
		benchmarkOperation(b, "", g1teal+g2teal+"ec_pairing_check BN254g1; !; assert", "int 1")
	})
	for i := 0; i < 4; i++ {
		size := 1 << uint(i)
		dups := strings.Repeat("dup; concat;", i)

		// size * 2 in name because we start with two points
		b.Run(fmt.Sprintf("pairing %d", size*2), func(b *testing.B) {
			benchmarkOperation(b, "", g1pbytes+dups+g2pbytes+dups+"ec_pairing_check BN254g1; assert", "int 1")
		})
	}

	b.Run("g1 subgroup", func(b *testing.B) {
		benchmarkOperation(b, "", g1teal+"ec_subgroup_check BN254g1; assert", "int 1")
	})
	b.Run("g2 subgroup", func(b *testing.B) {
		benchmarkOperation(b, "", g2teal+"ec_subgroup_check BN254g2; assert", "int 1")
	})

	fpbytes := fmt.Sprintf("byte 0x%s\n",
		strings.Repeat("00", 1)+strings.Repeat("22", bn254fpSize-1))
	fp2bytes := fpbytes + fpbytes + "concat\n"

	b.Run("g1 map to", func(b *testing.B) {
		benchmarkOperation(b, "", fpbytes+"ec_map_to BN254g1; pop", "int 1")
	})
	b.Run("g2 map to", func(b *testing.B) {
		benchmarkOperation(b, "", fp2bytes+"ec_map_to BN254g2; pop", "int 1")
	})

}

func BenchmarkFindMultiMulCutoff(b *testing.B) {
	for i := 1; i < 5; i++ {
		kbytes := make([]byte, i*scalarSize)
		{
			g1points := make([]bls12381.G1Affine, i)
			b.Run(fmt.Sprintf("bls g1 small %02d", i), func(b *testing.B) {
				for r := 0; r < b.N; r++ {
					for j := 0; j < i; j++ {
						g1points[j] = bls12381RandomG1()
					}
					rand.Read(kbytes)
					bls12381G1MultiMulSmall(g1points, kbytes)
				}
			})
			b.Run(fmt.Sprintf("bls g1 large %02d", i), func(b *testing.B) {
				for r := 0; r < b.N; r++ {
					for j := 0; j < i; j++ {
						g1points[j] = bls12381RandomG1()
					}
					rand.Read(kbytes)
					bls12381G1MultiMulLarge(g1points, kbytes)
				}
			})

			g2points := make([]bls12381.G2Affine, i)
			b.Run(fmt.Sprintf("bls g2 small %02d", i), func(b *testing.B) {
				for r := 0; r < b.N; r++ {
					for j := 0; j < i; j++ {
						g2points[j] = bls12381RandomG2()
					}
					rand.Read(kbytes)
					bls12381G2MultiMulSmall(g2points, kbytes)
				}
			})
			b.Run(fmt.Sprintf("bls g2 large %02d", i), func(b *testing.B) {
				for r := 0; r < b.N; r++ {
					for j := 0; j < i; j++ {
						g2points[j] = bls12381RandomG2()
					}
					rand.Read(kbytes)
					bls12381G2MultiMulLarge(g2points, kbytes)
				}
			})
		}

		{
			g1points := make([]bn254.G1Affine, i)
			b.Run(fmt.Sprintf("bn g1 small %02d", i), func(b *testing.B) {
				for r := 0; r < b.N; r++ {
					for j := 0; j < i; j++ {
						g1points[j] = bn254RandomG1()
					}
					rand.Read(kbytes)
					bn254G1MultiMulSmall(g1points, kbytes)
				}
			})
			b.Run(fmt.Sprintf("bn g1 large %02d", i), func(b *testing.B) {
				for r := 0; r < b.N; r++ {
					for j := 0; j < i; j++ {
						g1points[j] = bn254RandomG1()
					}
					rand.Read(kbytes)
					bn254G1MultiMulLarge(g1points, kbytes)
				}
			})

			g2points := make([]bn254.G2Affine, i)
			b.Run(fmt.Sprintf("bn g2 small %02d", i), func(b *testing.B) {
				for r := 0; r < b.N; r++ {
					for j := 0; j < i; j++ {
						g2points[j] = bn254RandomG2()
					}
					rand.Read(kbytes)
					bn254G2MultiMulSmall(g2points, kbytes)
				}
			})
			b.Run(fmt.Sprintf("bn g2 large %02d", i), func(b *testing.B) {
				for r := 0; r < b.N; r++ {
					for j := 0; j < i; j++ {
						g2points[j] = bn254RandomG2()
					}
					rand.Read(kbytes)
					bn254G2MultiMulLarge(g2points, kbytes)
				}
			})
		}

	}
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
	was := mecLimit.NbTasks
	mecLimit.NbTasks = 1
	defer func() { mecLimit.NbTasks = was }()

	g1point := bls12381RandomG1()
	g1teal := tealBytes(bls12381G1ToBytes(&g1point))

	g2point := bls12381RandomG2()
	g2teal := tealBytes(bls12381G2ToBytes(&g2point))

	b.Run("g1 add", func(b *testing.B) {
		benchmarkOperation(b, g1teal, "dup; ec_add BLS12_381g1", "len")
	})
	b.Run("g2 add", func(b *testing.B) {
		benchmarkOperation(b, g2teal, "dup; ec_add BLS12_381g2", "len")
	})

	b.Run("g1 scalar_mul", func(b *testing.B) {
		benchmarkOperation(b, g1teal, "dup; extract 0 32; ec_scalar_mul BLS12_381g1", "len")
	})
	for i := 0; i < 6; i++ {
		size := 1 << uint(i)
		dups := strings.Repeat("dup; concat;", i)
		b.Run(fmt.Sprintf("g1 multi_exp %d", size), func(b *testing.B) {
			benchmarkOperation(b, g1teal, dups+"dup; extract 0 32;"+dups+"ec_multi_scalar_mul BLS12_381g1", "len")
		})
	}

	b.Run("g2 scalar_mul", func(b *testing.B) {
		benchmarkOperation(b, g2teal, "dup; extract 0 32; ec_scalar_mul BLS12_381g2", "len")
	})
	for i := 0; i < 5; i++ {
		size := 1 << uint(i)
		dups := strings.Repeat("dup; concat;", i)
		b.Run(fmt.Sprintf("g2 multi_exp %d", size), func(b *testing.B) {
			benchmarkOperation(b, g2teal, dups+"dup; extract 0 32;"+dups+"ec_multi_scalar_mul BLS12_381g2", "len")
		})
	}

	var g1GenNeg bls12381.G1Affine
	g1GenNeg.Neg(&blsG1Gen)
	g1points := []bls12381.G1Affine{g1GenNeg, blsG1Gen}
	g2points := []bls12381.G2Affine{blsG2Gen, blsG2Gen}
	// -1 g1 g2 + g1 g2 = 0
	g1pbytes := tealBytes(bls12381G1sToBytes(g1points))
	g2pbytes := tealBytes(bls12381G2sToBytes(g2points))

	b.Run("g1 pairing f", func(b *testing.B) {
		benchmarkOperation(b, "", g1teal+g2teal+"ec_pairing_check BLS12_381g1; !; assert", "int 1")
	})
	for i := 0; i < 4; i++ {
		size := 1 << uint(i)
		dups := strings.Repeat("dup; concat;", i)

		// size * 2 in name because we start with two points
		b.Run(fmt.Sprintf("pairing %d", size*2), func(b *testing.B) {
			benchmarkOperation(b, "", g1pbytes+dups+g2pbytes+dups+"ec_pairing_check BLS12_381g1; assert", "int 1")
		})
	}

	b.Run("g1 subgroup", func(b *testing.B) {
		benchmarkOperation(b, "", g1teal+"ec_subgroup_check BLS12_381g1; pop", "int 1")
	})
	b.Run("g2 subgroup", func(b *testing.B) {
		benchmarkOperation(b, "", g2teal+"ec_subgroup_check BLS12_381g2; pop", "int 1")
	})

	fpbytes := fmt.Sprintf("byte 0x%s\n",
		strings.Repeat("00", 1)+strings.Repeat("22", bls12381fpSize-1))
	fp2bytes := fpbytes + fpbytes + "concat\n"

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

// TestFieldCosts ensures that costs are calculated right for an opcodes
// whose costs depends on the immediate
func TestFieldCosts(t *testing.T) { //nolint:paralleltest // manipulates opcode table
	partitiontest.PartitionTest(t)

	// make an opcode "xxx" that just performs a pop. But it takes an immediate
	// - any of the "EC" constants. The first three fields have different
	// costs.

	xxx := OpSpec{
		Opcode:    106,
		Name:      "xxx",
		op:        opPop,
		Proto:     proto("a:"),
		OpDetails: costByField("f", &EcGroups, []int{10, 20, 30, 33, 40}),
	}

	withOpcode(t, LogicVersion, xxx, func(opcode byte) {
		testApp(t, "int 32; bzero; xxx BN254g1; global OpcodeBudget; int 687; ==", nil)
		testApp(t, "int 32; bzero; xxx BN254g2; global OpcodeBudget; int 677; ==", nil)
		testApp(t, "int 32; bzero; xxx BLS12_381g1; global OpcodeBudget; int 667; ==", nil)
		testApp(t, "int 32; bzero; xxx BLS12_381g2; global OpcodeBudget; int 664; ==", nil)
	})
}

// TestLinearFieldCost ensures that costs are calculated right for an opcodes
// that have field AND arg length costs
func TestLinearFieldCost(t *testing.T) { //nolint:paralleltest // manipulates opcode table
	partitiontest.PartitionTest(t)

	// make an opcode "xxx" that just performs a pop. But it takes an immediate
	// - any of the "EC" constants. The first three fields have different
	// costs, that depend on the length of the input

	xxx := OpSpec{
		Opcode: 106,
		Name:   "xxx",
		op:     opPop,
		Proto:  proto("a:"),
		OpDetails: costByFieldAndLength("f", &EcGroups, []linearCost{{
			baseCost:  1,
			chunkCost: 2,
			chunkSize: 2,
		}, {
			baseCost:  5,
			chunkCost: 2,
			chunkSize: 10,
		}, {
			baseCost:  1,
			chunkCost: 1,
			chunkSize: 1,
		}, {
			baseCost:  1,
			chunkCost: 1,
			chunkSize: 1,
		}, {
			baseCost:  1,
			chunkCost: 1,
			chunkSize: 1,
		}}),
	}

	withOpcode(t, LogicVersion, xxx, func(opcode byte) {
		// starts at 1, goes up by two for each PAIR of bytes
		testApp(t, "int 0; bzero; xxx BN254g1; global OpcodeBudget; int 696; ==", nil)
		testApp(t, "int 1; bzero; xxx BN254g1; global OpcodeBudget; int 694; ==", nil)
		testApp(t, "int 2; bzero; xxx BN254g1; global OpcodeBudget; int 694; ==", nil)
		testApp(t, "int 3; bzero; xxx BN254g1; global OpcodeBudget; int 692; ==", nil)
		testApp(t, "int 4; bzero; xxx BN254g1; global OpcodeBudget; int 692; ==", nil)

		// starts at 5, goes up by two for each 10 bytes
		testApp(t, "int 0; bzero; xxx BN254g2; global OpcodeBudget; int 692; ==", nil)
		testApp(t, "int 1; bzero; xxx BN254g2; global OpcodeBudget; int 690; ==", nil)
		testApp(t, "int 2; bzero; xxx BN254g2; global OpcodeBudget; int 690; ==", nil)
		testApp(t, "int 9; bzero; xxx BN254g2; global OpcodeBudget; int 690; ==", nil)
		testApp(t, "int 10; bzero; xxx BN254g2; global OpcodeBudget; int 690; ==", nil)
		testApp(t, "int 11; bzero; xxx BN254g2; global OpcodeBudget; int 688; ==", nil)
	})
}

// ed25519 test helpers. Points use the uncompressed 64-byte encoding (32 byte
// big-endian X then Y), matching the on-stack form consumed by the opcodes.

func ed25519Identity() []byte { return ed25519PointToBytes(edwards25519.NewIdentityPoint()) }

func ed25519RandomScalar() *edwards25519.Scalar {
	var b [64]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	s, err := new(edwards25519.Scalar).SetUniformBytes(b[:])
	if err != nil {
		panic(err)
	}
	return s
}

// ed25519RandomPoint returns a random prime-order (torsion-free) point, since
// it is a multiple of the base point.
func ed25519RandomPoint() []byte {
	return ed25519PointToBytes(new(edwards25519.Point).ScalarBaseMult(ed25519RandomScalar()))
}

// ed25519Torsion is a canonical point of order 8 (a generator of the small
// subgroup), uncompressed. It is on the curve but not in the prime-order
// subgroup. The literal is the well-known compressed encoding, decompressed
// here once into the uncompressed on-stack form.
var ed25519Torsion = func() []byte {
	compressed, _ := hex.DecodeString("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
	p, err := new(edwards25519.Point).SetBytes(compressed)
	if err != nil {
		panic(err)
	}
	return ed25519PointToBytes(p)
}()

func TestEd25519Add(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	p := ed25519RandomPoint()
	q := ed25519RandomPoint()
	id := ed25519Identity()
	add := "ec_add ED25519;"

	pt := tealBytes(p)
	qt := tealBytes(q)
	idt := tealBytes(id)

	// P + identity == P, and identity + P == P
	testAccepts(t, pt+idt+add+pt+"==", edwardsVersion)
	testAccepts(t, idt+pt+add+pt+"==", edwardsVersion)

	// P + (-P) == identity
	var negP edwards25519.Point
	pp, err := bytesToEd25519Point(p)
	require.NoError(t, err)
	negP.Negate(pp)
	testAccepts(t, pt+tealBytes(ed25519PointToBytes(&negP))+add+idt+"==", edwardsVersion)

	// commutative: P + Q == Q + P
	testAccepts(t, pt+qt+add+qt+pt+add+"==", edwardsVersion)

	// matches a direct filippo computation
	qq, err := bytesToEd25519Point(q)
	require.NoError(t, err)
	sum := new(edwards25519.Point).Add(pp, qq)
	testAccepts(t, pt+qt+add+tealBytes(ed25519PointToBytes(sum))+"==", edwardsVersion)

	// bad lengths
	testPanics(t, pt+"int 63; bzero;"+add+"len", edwardsVersion, "bad ed25519 point length")
	testPanics(t, "int 65; bzero;"+pt+add+"len", edwardsVersion, "bad ed25519 point length")
}

func TestEd25519ScalarMul(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	p := ed25519RandomPoint()
	pt := tealBytes(p)
	idt := tealBytes(ed25519Identity())
	mul := "ec_scalar_mul ED25519;"

	// 0 * P == identity
	testAccepts(t, pt+"int 0; itob;"+mul+idt+"==", edwardsVersion)
	// 1 * P == P
	testAccepts(t, pt+"int 1; itob;"+mul+pt+"==", edwardsVersion)
	// L * P == identity (scalar reduces to 0 mod the group order)
	testAccepts(t, pt+tealBytes(ed25519Order.Bytes())+mul+idt+"==", edwardsVersion)
	// (L+1) * P == P
	lp1 := new(big.Int).Add(ed25519Order, big.NewInt(1))
	testAccepts(t, pt+tealBytes(lp1.Bytes())+mul+pt+"==", edwardsVersion)

	// matches a direct filippo computation for a random scalar
	k := ed25519RandomScalar()
	pp, err := bytesToEd25519Point(p)
	require.NoError(t, err)
	prod := new(edwards25519.Point).ScalarMult(k, pp)
	// k.Bytes() is little-endian; the opcode wants big-endian, so reverse.
	kbe := reversed(k.Bytes())
	testAccepts(t, pt+tealBytes(kbe)+mul+tealBytes(ed25519PointToBytes(prod))+"==", edwardsVersion)

	// scalar too long
	testPanics(t, pt+"int 33; bzero;"+mul+"len", edwardsVersion, "scalar len is 33")
}

func reversed(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

func TestEd25519MultiScalarMul(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	p := ed25519RandomPoint()
	q := ed25519RandomPoint()
	pt := tealBytes(p)
	multiexp := "ec_multi_scalar_mul ED25519;"
	mul := "ec_scalar_mul ED25519;"
	add := "ec_add ED25519;"

	// single point, scalar 0 -> identity
	testAccepts(t, pt+"int 32; bzero;"+multiexp+tealBytes(ed25519Identity())+"==", edwardsVersion)
	// single point, scalar 1 -> P
	testAccepts(t, pt+"int 32; bzero; int 1; itob; b|;"+multiexp+pt+"==", edwardsVersion)

	// [P, Q] . [1, 1] == P + Q
	one := "int 32; bzero; int 1; itob; b|;"
	points := tealBytes(append(append([]byte{}, p...), q...))
	scalars := one + one + "concat;"
	testAccepts(t, points+scalars+multiexp+pt+tealBytes(q)+add+"==", edwardsVersion)

	// [P, Q] . [2, 3] == 2P + 3Q
	twoThree := "byte 0x" + hex.EncodeToString(leftPad(big.NewInt(2).Bytes(), 32)) +
		"; byte 0x" + hex.EncodeToString(leftPad(big.NewInt(3).Bytes(), 32)) + "; concat;"
	expected := pt + "byte 0x02;" + mul + tealBytes(q) + "byte 0x03;" + mul + add
	testAccepts(t, points+twoThree+multiexp+expected+"==", edwardsVersion)
}

func leftPad(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

func TestEd25519SubgroupCheck(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	check := "ec_subgroup_check ED25519"

	// a random prime-order point is torsion-free
	testAccepts(t, tealBytes(ed25519RandomPoint())+check, edwardsVersion)
	// the identity is in the prime-order subgroup
	testAccepts(t, tealBytes(ed25519Identity())+check, edwardsVersion)

	// a pure torsion point (order 8) is not
	require.NotEmpty(t, ed25519Torsion)
	tp, err := bytesToEd25519Point(ed25519Torsion) // sanity: decodes as uncompressed
	require.NoError(t, err)
	testRejects(t, tealBytes(ed25519Torsion)+check, edwardsVersion)

	// prime-order point plus torsion is not torsion-free
	rp, err := bytesToEd25519Point(ed25519RandomPoint())
	require.NoError(t, err)
	mixed := new(edwards25519.Point).Add(rp, tp)
	testRejects(t, tealBytes(ed25519PointToBytes(mixed))+check, edwardsVersion)
}

// BenchmarkEd25519VerifyInTeal times the hand-written verifier against the
// opcode it reimplements, which is the price of doing this in TEAL rather than
// in Go.
func BenchmarkEd25519VerifyInTeal(b *testing.B) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(b, err)
	msg := []byte("attack at dawn")
	sig := ed25519.Sign(priv, msg)

	run := func(b *testing.B, program []byte, args [][]byte) {
		b.Helper()
		var txn transactions.SignedTxn
		txn.Lsig.Logic = program
		txn.Lsig.Args = args
		ep := benchmarkSigParams(txn)
		for range b.N {
			pass, err := EvalSignature(0, ep)
			if err != nil || !pass {
				b.Fatalf("%v %v", pass, err)
			}
			ep.reset()
		}
	}

	b.Run("teal", func(b *testing.B) {
		run(b, testProg(b, ed25519VerifySource, edwardsVersion).Program,
			[][]byte{msg, sig, pub, ed25519Hint(pub), ed25519Hint(sig[:32])})
	})
	b.Run("opcode", func(b *testing.B) {
		run(b, testProg(b, "arg 0; arg 1; arg 2; ed25519verify_bare", edwardsVersion).Program,
			[][]byte{msg, sig, pub})
	})
}

// ed25519NafWeight returns the number of nonzero digits in the width-w
// non-adjacent form of k. That count is exactly the number of point additions
// edwards25519's variable-time routines perform for k: the 256 doublings are
// fixed and shared between points, so the NAF weight is the only part of the
// work a caller controls. It reimplements the (unexported) algorithm in
// edwards25519's Scalar.nonAdjacentForm, bottom up rather than by 64-bit
// windows.
func ed25519NafWeight(k *big.Int, w uint) int {
	x := new(big.Int).Set(k)
	width := new(big.Int).Lsh(big.NewInt(1), w)
	mask := new(big.Int).Sub(width, big.NewInt(1))
	half := new(big.Int).Rsh(width, 1)
	digit := new(big.Int)
	weight := 0
	for x.Sign() > 0 {
		if x.Bit(0) == 1 {
			digit.And(x, mask)
			if digit.Cmp(half) >= 0 {
				digit.Sub(digit, width) // the "negative" of the pair, as NAF prefers
			}
			x.Sub(x, digit)
			weight++
		}
		x.Rsh(x, 1)
	}
	return weight
}

// ed25519WorstScalar is the scalar that makes the variable-time routines do the
// most work. A width-5 NAF keeps at least four zeros between nonzero digits, so
// weight is maximized by a nonzero digit every fifth position, which is what a
// bit set every fifth position produces. Below L, so reduction leaves it alone.
var ed25519WorstScalar = func() []byte {
	k := new(big.Int)
	for i := 0; i <= 250; i += 5 {
		k.SetBit(k, i, 1)
	}
	return leftPad(k.Bytes(), scalarSize)
}()

func TestEd25519WorstScalar(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	worst := new(big.Int).SetBytes(ed25519WorstScalar)
	require.Negative(t, worst.Cmp(ed25519Order)) // survives reduction unchanged

	// 253 bits, nonzero digits five apart, is 51 of them.
	require.Equal(t, 51, ed25519NafWeight(worst, 5))

	// Random scalars come in well under that, averaging about 256/(w+1).
	total, high := 0, 0
	const trials = 200
	for range trials {
		k := new(big.Int).SetBytes(reversed(ed25519RandomScalar().Bytes()))
		weight := ed25519NafWeight(k, 5)
		require.LessOrEqual(t, weight, 51)
		total += weight
		high = max(high, weight)
	}
	require.Less(t, total/trials, 46, "random scalars should not average near the worst case")
	t.Logf("width-5 NAF weight over %d random scalars: mean %d, max %d (worst possible 51)",
		trials, total/trials, high)
}

// BenchmarkEd25519 is how the ED25519 costs were set. To read it, divide ns/op
// by the cost the op is charged, and compare against the same ratio for the
// signature opcodes in BenchmarkVerify, which are the calibration anchors
// (ed25519verify_bare, ecdsa_verify, and vrf_verify all land near 25 ns per
// unit of cost).
//
// The scalar multiplications are variable time, so the "worst" cases here feed
// them ed25519WorstScalar, which maximizes the work. Costs are set from those,
// not from the random-scalar cases.
func BenchmarkEd25519(b *testing.B) {
	pt := tealBytes(ed25519RandomPoint())
	worst := tealBytes(ed25519WorstScalar)

	b.Run("add", func(b *testing.B) {
		benchmarkOperation(b, pt, "dup; ec_add ED25519", "len")
	})

	b.Run("scalar_mul", func(b *testing.B) {
		benchmarkOperation(b, pt, "dup; extract 0 32; ec_scalar_mul ED25519", "len")
	})
	b.Run("scalar_mul worst", func(b *testing.B) {
		benchmarkOperation(b, pt, worst+"ec_scalar_mul ED25519", "len")
	})

	for i := 0; i < 7; i++ {
		size := 1 << uint(i)
		dups := strings.Repeat("dup; concat;", i)
		b.Run(fmt.Sprintf("multi_exp %d", size), func(b *testing.B) {
			benchmarkOperation(b, pt, dups+"dup; extract 0 32;"+dups+"ec_multi_scalar_mul ED25519", "len")
		})
		b.Run(fmt.Sprintf("multi_exp %d worst", size), func(b *testing.B) {
			benchmarkOperation(b, pt, dups+byteRepeat(ed25519WorstScalar, size)+"ec_multi_scalar_mul ED25519", "len")
		})
	}

	b.Run("subgroup", func(b *testing.B) {
		benchmarkOperation(b, "", pt+"ec_subgroup_check ED25519; assert", "int 1")
	})
}

func TestEd25519Versioning(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// ED25519 was introduced in v14; earlier versions reject it at assembly.
	testProg(t, "byte 0x00; byte 0x00; ec_add ED25519", edwardsVersion-1,
		exp(1, "ec_add ED25519 field was introduced in v14. Missed #pragma version?"))
	testProg(t, "byte 0x00; byte 0x00; ec_add ED25519", edwardsVersion) // ok at v13

	// ED25519 is not valid for the pairing-only opcodes, at any version.
	testProg(t, "byte 0x00; byte 0x00; ec_pairing_check ED25519", edwardsVersion,
		exp(1, "ec_pairing_check unknown field: \"ED25519\""))
	testProg(t, "byte 0x00; ec_map_to ED25519", edwardsVersion,
		exp(1, "ec_map_to unknown field: \"ED25519\""))

	// but it is valid for ec_subgroup_check
	testProg(t, "byte 0x00; ec_subgroup_check ED25519", edwardsVersion)
}

// ed25519VerifySource is ed25519verify_bare written out in TEAL, using nothing
// but sha512 and the ED25519 ec_ opcodes. RFC 8032 verification is
// k = SHA512(R || A || M) and then [S]B == R + [k]A, the "cofactorless"
// equation that crypto/ed25519 uses.
//
//	arg 0  message
//	arg 1  signature: 32 byte compressed R, then 32 byte little-endian S
//	arg 2  public key: 32 byte compressed A
//	arg 3  hint: A uncompressed (32 byte big-endian X, then 32 byte big-endian Y)
//	arg 4  hint: R uncompressed
//
// The ec_ opcodes work on uncompressed points, and decompressing takes a
// modular square root, which the AVM has no cheap way to compute. So the caller
// supplies the uncompressed points, and the program checks them by compressing
// them back down - a byte reversal and one sign bit - and comparing against the
// 32 bytes that were actually signed over. Compression is injective on curve
// points, so a hint that survives the check is the point its compressed
// encoding denotes, and a caller gains nothing by lying about it.
//
// This is stricter than crypto/ed25519 in one respect: non-canonical encodings
// of A or R (a y coordinate that is not reduced mod p, or x == 0 with the sign
// bit set) have no uncompressed preimage here, so they cannot be verified.
//
// It costs about 4,200, so it fits in a logic sig. The multi-exp is 1,970 of
// that, and the four byte reversals another 1,900 or so, which makes shuffling
// bytes between big and little endian nearly as expensive as the curve
// arithmetic.
//
// Only the final group equation rejects. Everything else - a wrong length, a
// non-canonical S, a hint that is not the point it claims to be - fails the
// program outright, which for a logic sig amounts to the same thing.
const ed25519VerifySource = `
arg 1; len; int 64; ==; assert	// signature is R || S
arg 2; len; int 32; ==; assert	// compressed public key

// k = SHA512(R || A || M) mod L, big-endian for ec_scalar_mul
arg 1; extract 0 32; arg 2; concat; arg 0; concat
sha512
callsub reverse			// the digest is read as a little-endian scalar
byte 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed // L
b%
int 32; bzero; b|		// b% trims leading zeros, and scalars are fixed width
store 0				// k

// S must be canonical. Reducing it instead of rejecting it is what makes
// naive verifiers accept malleated signatures.
arg 1; extract 32 32; callsub reverse
dup
byte 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed // L
b<
assert
store 1				// S

// the hints must be the points that the signed-over encodings denote
arg 3; callsub compress; arg 2; ==; assert
arg 4; callsub compress; arg 1; extract 0 32; ==; assert

// [S]B - [k]A == R, as a single multi-exp. The 256 point doublings dominate a
// scalar multiplication and one multi-exp shares them across both terms, so
// this is far cheaper than multiplying twice and adding.
byte 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a6666666666666666666666666666666666666666666666666666666666666658 // B

// -A is (p-X, Y). A hint with X of 0 (only the identity and the point of order
// two) or X above p has no negation here, and fails the program.
byte 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed // p
arg 3; extract 0 32
b-
int 32; bzero; b|		// b- trims leading zeros, and coordinates are fixed width
arg 3; extract 32 32
concat
concat				// B then -A

load 1				// S
load 0				// k
concat
ec_multi_scalar_mul ED25519
arg 4				// R
==
return

// reverse converts between the big-endian byte order the ec_ opcodes use for
// scalars and coordinates, and the little-endian order ed25519 encodes in.
reverse:
proto 1 1
byte ""
frame_dig -1; len		// index of the byte after the one to append next
reverse_loop:
int 1; -
dup
frame_dig -1; swap; int 1; extract3
swap; cover 2			// accumulator and byte on top, index below
concat
swap
dup; bnz reverse_loop
pop
retsub

// compress turns an uncompressed point into its 32 byte RFC 8032 encoding:
// little-endian Y, with the low bit of X as the high bit.
compress:
proto 1 1
frame_dig -1; extract 32 32; callsub reverse
int 248				// high bit of the last byte, in setbit's ordering
frame_dig -1; int 255; getbit	// low bit of X
setbit
retsub
`

// ed25519Hint decompresses a 32 byte RFC 8032 point encoding into the
// uncompressed form the ec_ opcodes consume. Tampered encodings often do not
// decompress at all; the identity stands in for those, so that the program
// under test rejects on the compression check rather than erring on an
// undecodable point.
func ed25519Hint(compressed []byte) []byte {
	p, err := new(edwards25519.Point).SetBytes(compressed)
	if err != nil {
		return ed25519Identity()
	}
	return ed25519PointToBytes(p)
}

func TestEd25519VerifyInTeal(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// the two constants the program embeds, in the encoding it expects
	require.Contains(t, ed25519VerifySource,
		hex.EncodeToString(ed25519PointToBytes(edwards25519.NewGeneratorPoint())))
	require.Contains(t, ed25519VerifySource,
		hex.EncodeToString(leftPad(ed25519Order.Bytes(), 32)))

	teal := testProg(t, ed25519VerifySource, edwardsVersion).Program
	// the opcode this program reimplements, for comparison
	bare := testProg(t, "arg 0; arg 1; arg 2; ed25519verify_bare", edwardsVersion).Program

	accepts := func(program []byte, args [][]byte) bool {
		var txn transactions.SignedTxn
		txn.Lsig.Logic = program
		txn.Lsig.Args = args
		pass, err := EvalSignature(0, defaultSigParams(txn))
		return pass && err == nil
	}
	// hinted builds the five arguments the TEAL verifier takes from the three
	// the opcode takes.
	hinted := func(msg, sig, pk []byte) [][]byte {
		return [][]byte{msg, sig, pk, ed25519Hint(pk), ed25519Hint(sig[:32])}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	other, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	msg := []byte("attack at dawn")
	sig := ed25519.Sign(priv, msg)

	flip := func(b []byte, i int) []byte {
		c := slices.Clone(b)
		c[i] ^= 1
		return c
	}
	// S + L is a second encoding of the same scalar. Conforming verifiers
	// reject it, so the signature cannot be mauled into a distinct-looking one.
	malleated := slices.Clone(sig)
	s := new(big.Int).SetBytes(reversed(sig[32:]))
	copy(malleated[32:], reversed(leftPad(s.Add(s, ed25519Order).Bytes(), 32)))

	var verifyTests = []struct {
		name string
		msg  []byte
		sig  []byte
		pk   []byte
		pass bool
	}{
		{"valid", msg, sig, pub, true},
		{"wrong message", []byte("attack at dusk"), sig, pub, false},
		{"tampered R", msg, flip(sig, 0), pub, false},
		{"tampered S", msg, flip(sig, 63), pub, false},
		{"wrong key", msg, sig, other, false},
		{"malleated S", msg, malleated, pub, false},
	}
	for _, test := range verifyTests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, test.pass, accepts(teal, hinted(test.msg, test.sig, test.pk)))
			// the TEAL agrees with the opcode, and both agree with the
			// reference implementation
			require.Equal(t, test.pass, accepts(bare, [][]byte{test.msg, test.sig, test.pk}))
			require.Equal(t, test.pass, ed25519.Verify(test.pk, test.msg, test.sig))
		})
	}

	// A hint that is a perfectly good point, but not the one the signature or
	// public key names, is caught by the compression check.
	for _, arg := range []int{3, 4} {
		lying := hinted(msg, sig, pub)
		lying[arg] = ed25519RandomPoint()
		require.False(t, accepts(teal, lying))
	}

	// Compressing only looks at Y and the low bit of X, so a hint can compress
	// correctly and still not be on the curve. Nothing in the program checks
	// the curve equation; the opcodes do it, when they decode the point.
	offCurve := hinted(msg, sig, pub)
	offCurve[3] = slices.Clone(offCurve[3])
	offCurve[3][31] ^= 2 // changes X, but not its low bit
	var txn transactions.SignedTxn
	txn.Lsig.Args = offCurve
	testLogicBytes(t, teal, defaultSigParams(txn), "invalid ed25519 point")

	// The identity as a public key compresses correctly, but negating it needs
	// p-0, which is not a canonical coordinate, so the program fails rather
	// than verifying anything. libsodium rejects such a key too, by an
	// explicit small-order check.
	identity := hinted(msg, sig, pub)
	identity[2] = make([]byte, ed25519fpSize)
	identity[2][0] = 1 // little-endian y of 1, x sign clear
	identity[3] = ed25519Identity()
	txn.Lsig.Args = identity
	testLogicBytes(t, teal, defaultSigParams(txn), "larger than modulus")

	// short signature and short public key fail the length assertions
	txn.Lsig.Args = hinted(msg, sig, pub)
	txn.Lsig.Args[1] = sig[1:]
	testLogicBytes(t, teal, defaultSigParams(txn), "assert failed")
	txn.Lsig.Args = hinted(msg, sig, pub)
	txn.Lsig.Args[2] = pub[1:]
	testLogicBytes(t, teal, defaultSigParams(txn), "assert failed")
}
