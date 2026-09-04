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
	edfield "filippo.io/edwards25519/field"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

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
		OpDetails: costByField("f", &EcGroups, []int{10, 20, 30, 33, 40, 50}),
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

// A multi-exp over no points at all is rejected by every group. The empty sum
// is arguably the identity, but the opcode should not answer differently
// depending on which group its immediate names.
func TestEcMultiScalarMulEmpty(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	for _, group := range ecArithGroups.Names {
		if group == "" { // a group this opcode does not accept, ED25519_Monero
			continue
		}
		spec, ok := ecArithGroups.SpecByName(group)
		require.True(t, ok)
		testPanics(t, "byte 0x; byte 0x; ec_multi_scalar_mul "+group+"; len", spec.Version(), "empty input")
	}
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

	// Elligator 2 branches on whether g(x1) is square, and the branch that is
	// not takes a second square root, so both are timed and the cost comes from
	// the slower.
	square, notSquare := ed25519MapInputs()
	b.Run("map_to square", func(b *testing.B) {
		benchmarkOperation(b, "", tealBytes(square)+"ec_map_to ED25519; pop", "int 1")
	})
	b.Run("map_to nonsquare", func(b *testing.B) {
		benchmarkOperation(b, "", tealBytes(notSquare)+"ec_map_to ED25519; pop", "int 1")
	})

	// The Monero map takes one exponentiation whichever of its four branches it
	// takes, so all four are timed to show that the cost really does not depend
	// on the branch, and the worst sets the cost.
	for _, v := range moneroMapVectors {
		b.Run("monero map_to "+v.branch, func(b *testing.B) {
			benchmarkOperation(b, "", tealBytes(moneroMapArg(b, v.hash))+"ec_map_to ED25519_Monero; pop", "int 1")
		})
	}
}

// ed25519MapInputs returns two field elements that drive ec_map_to down its two
// paths: one whose g(x1) is a square, so the map takes a single square root,
// and one whose is not, so it takes a second for the other candidate x. It
// recomputes the branch condition rather than observing it, since the map does
// not report which way it went.
func ed25519MapInputs() (square, notSquare []byte) {
	one := new(edfield.Element).One()
	for i := 1; square == nil || notSquare == nil; i++ {
		u := new(edfield.Element).Mult32(one, uint32(i))
		var zuu, xMd, x1n, xMd2, gxd, gx1n edfield.Element
		zuu.Square(u)
		zuu.Add(&zuu, &zuu)
		xMd.Add(&zuu, one)
		x1n.Negate(ed25519MontJ)
		xMd2.Square(&xMd)
		gxd.Multiply(&xMd2, &xMd)
		gx1n.Multiply(ed25519MontJ, &zuu)
		gx1n.Multiply(&gx1n, &x1n)
		gx1n.Add(&gx1n, &xMd2)
		gx1n.Multiply(&gx1n, &x1n)
		if _, wasSquare := new(edfield.Element).SqrtRatio(&gx1n, &gxd); wasSquare == 1 {
			square = reversed(u.Bytes()) // the opcode reads big-endian
		} else {
			notSquare = reversed(u.Bytes())
		}
	}
	return
}

// TestEd25519MapTo checks ec_map_to ED25519 against RFC 9380's own test
// vectors, from Appendix J.5.2, edwards25519_XMD:SHA-512_ELL2_NU_. The RFC
// prints, for each message, the field element u it hashed to, the point Q that
// map_to_curve produced from u, and the point P after clearing the cofactor.
// The opcode does both steps, so it must produce P, and Q must be P once
// multiplied by the cofactor of 8.
func TestEd25519MapTo(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	var vectors = []struct{ u, qx, qy, px, py string }{
		{
			"7f3e7fb9428103ad7f52db32f9df32505d7b427d894c5093f7a0f0374a30641d",
			"42836f691d05211ebc65ef8fcf01e0fb6328ec9c4737c26050471e50803022eb",
			"22cb4aaa555e23bd460262d2130d6a3c9207aa8bbb85060928beb263d6d42a95",
			"1ff2b70ecf862799e11b7ae744e3489aa058ce805dd323a936375a84695e76da",
			"222e314d04a4d5725e9f2aff9fb2a6b69ef375a1214eb19021ceab2d687f0f9b",
		}, {
			"09cfa30ad79bd59456594a0f5d3a76f6b71c6787b04de98be5cd201a556e253b",
			"333e41b61c6dd43af220c1ac34a3663e1cf537f996bab50ab66e33c4bd8e4e19",
			"51b6f178eb08c4a782c820e306b82c6e273ab22e258d972cd0c511787b2a3443",
			"5f13cc69c891d86927eb37bd4afc6672360007c63f68a33ab423a3aa040fd2a8",
			"67732d50f9a26f73111dd1ed5dba225614e538599db58ba30aaea1f5c827fa42",
		}, {
			"475ccff99225ef90d78cc9338e9f6a6bb7b17607c0c4428937de75d33edba941",
			"55186c242c78e7d0ec5b6c9553f04c6aeef64e69ec2e824472394da32647cfc6",
			"5b9ea3c265ee42256a8f724f616307ef38496ef7eba391c08f99f3bea6fa88f0",
			"1dd2fefce934ecfd7aae6ec998de088d7dd03316aa1847198aecf699ba6613f1",
			"2f8a6c24dd1adde73909cada6a4a137577b0f179d336685c4a955a0a8e1a86fb",
		}, {
			"049a1c8bd51bcb2aec339f387d1ff51428b88d0763a91bcdf6929814ac95d03d",
			"024b6e1621606dca8071aa97b43dce4040ca78284f2a527dcf5d0fbfac2b07e7",
			"5102353883d739bdc9f8a3af650342b171217167dcce34f8db57208ec1dfdbf2",
			"35fbdc5143e8a97afd3096f2b843e07df72e15bfca2eaf6879bf97c5d3362f73",
			"2af6ff6ef5ebba128b0774f4296cb4c2279a074658b083b8dcca91f57a603450",
		}, {
			"3cb0178a8137cefa5b79a3a57c858d7eeeaa787b2781be4a362a2f0750d24fa0",
			"3e6368cff6e88a58e250c54bd27d2c989ae9b3acb6067f2651ad282ab8c21cd9",
			"38fb39f1566ca118ae6c7af42810c0bb9767ae5960abb5a8ca792530bfb9447d",
			"6e5e1f37e99345887fc12111575fc1c3e36df4b289b8759d23af14d774b66bff",
			"2c90c3d39eb18ff291d33441b35f3262cdd307162cc97c31bfcc7a4245891a37",
		},
	}

	mapTo := "ec_map_to ED25519;"
	for i, v := range vectors {
		t.Run(fmt.Sprintf("rfc9380/%d", i), func(t *testing.T) {
			t.Parallel()
			u := "byte 0x" + v.u + ";"
			p := "byte 0x" + v.px + v.py + ";"
			q := "byte 0x" + v.qx + v.qy + ";"
			// the opcode maps and clears the cofactor, landing on P
			testAccepts(t, u+mapTo+p+"==", edwardsVersion)
			// and P is the RFC's Q with the cofactor cleared
			testAccepts(t, q+"byte 0x08; ec_scalar_mul ED25519;"+p+"==", edwardsVersion)
			// which means the result is torsion free, as every group's map promises
			testAccepts(t, u+mapTo+"ec_subgroup_check ED25519", edwardsVersion)
		})
	}

	// zero is the input that drives the map into its degenerate case, where the
	// Montgomery y is 0 and the birational map has no image but the identity
	testAccepts(t, "byte 0x00;"+mapTo+tealBytes(ed25519Identity())+"==", edwardsVersion)
	testAccepts(t, "byte 0x;"+mapTo+tealBytes(ed25519Identity())+"==", edwardsVersion)

	// short inputs are accepted without 0-padding, as for the other curves
	testAccepts(t, "byte 0x07;"+mapTo+"byte 0x0000000000000000000000000000000000000000000000000000000000000007;"+mapTo+"==", edwardsVersion)

	// but not over-long ones, nor field elements at or above the modulus
	testPanics(t, "int 33; bzero;"+mapTo+"len", edwardsVersion, "Expected at most 32")
	testPanics(t, "byte 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;"+mapTo+"len",
		edwardsVersion, "larger than modulus")
}

// moneroMapVectors come from Monero's tests/crypto/tests.txt, whose
// "hash_to_point" lines exercise ge_fromfe_frombytes_vartime alone, without the
// ge_mul8 that Monero's hash_to_ec (and this opcode) finish with. So the point
// here is the map's own output, and the opcode should land on eight times it.
//
// The four are one apiece for the four square roots the map chooses between,
// which is every branch it has. Nothing about a vector says which branch it
// takes, so branch here is a claim, and TestEd25519MoneroBranches checks it.
//
// hash is the 32 byte little-endian string Monero maps. The opcode takes a
// big-endian field element instead, like every other ec_ immediate, so a caller
// reverses and reduces first - which is what moneroMapArg does here and what
// the TEAL below does with reverse and b%.
var moneroMapVectors = []struct{ branch, hash, point string }{
	{"fffb1", // x == -w
		"d7a3cb05a3846008cda1755b6d2f0d3b4ba3e2d1fddd098670d86ac58b4a6da4",
		"bdfdf6e21eaaa082618d408e8c2da5485e5de7568dfb7908ff8399b056a8f709",
	}, {"fffb2", // x == w
		"3f287e7e6cf6ef2ed9a8c7361e4ec96535f0df208ddee9a57ffb94d4afb94a93",
		"e462eea6e7d404b0f1219076e3433c742a1641dbcc9146362c27d152c6175410",
	}, {"fffb3", // the negative branch
		"5c380f98794ab7a9be7c2d3259b92772125ce93527be6a76210631fdd8001498",
		"31a1feb4986d42e2137ae061ea031838d24fa523234954cf8860bcd42421ae94",
	}, {"fffb4", // the negative branch
		"83efb774657700e37291f4b8dd10c839d1c739fd135c07a2fd7382334dafdd6a",
		"2789ecbaf36e4fcb41c6157228001538b40ca379464b718d830c58caae7ea4ca",
	},
}

// moneroMapArg is the transformation a contract performs before ec_map_to
// ED25519_Monero: read Monero's 32 byte hash as the little-endian integer it is,
// and reduce it modulo p. The reduction is not optional. Monero's map drops the
// mask that fe_frombytes applies to the top bit, so it consumes all 256 bits,
// and half of all 32 byte strings are at or above the modulus.
func moneroMapArg(tb testing.TB, hash string) []byte {
	tb.Helper()
	le, err := hex.DecodeString(hash)
	require.NoError(tb, err)
	require.Len(tb, le, 32)
	return new(big.Int).Mod(new(big.Int).SetBytes(reversed(le)), ed25519FieldModulus).Bytes()
}

// moneroMapPoint decompresses a vector's point and clears its cofactor, which
// is what ge_mul8 does and therefore what the opcode returns.
func moneroMapPoint(tb testing.TB, compressed string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(compressed)
	require.NoError(tb, err)
	p, err := new(edwards25519.Point).SetBytes(b)
	require.NoError(tb, err)
	return ed25519PointToBytes(new(edwards25519.Point).MultByCofactor(p))
}

func TestEd25519MoneroMapTo(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	mapTo := "ec_map_to ED25519_Monero;"
	for i, v := range moneroMapVectors {
		t.Run(fmt.Sprintf("monero/%d", i), func(t *testing.T) {
			t.Parallel()
			u := tealBytes(moneroMapArg(t, v.hash))
			// the opcode maps and clears the cofactor, landing on 8 times the
			// point Monero's own hash_to_point reports
			testAccepts(t, u+mapTo+tealBytes(moneroMapPoint(t, v.point))+"==", edwardsVersion)
			// so the result is torsion free, as every group's map promises
			testAccepts(t, u+mapTo+"ec_subgroup_check ED25519", edwardsVersion)

			// Both maps are Elligator 2 with the same Z, so they agree on the
			// Montgomery x and can only disagree on the sign of the root. They
			// do, on exactly the inputs Monero's negative branch claims: there
			// the two results sum to the identity, and elsewhere they are equal.
			// Half of all inputs land on each, so a program that reached for
			// ED25519 instead would be right half the time - which for a key
			// image is no better than never.
			standard := u + "ec_map_to ED25519;"
			if v.branch == "fffb3" || v.branch == "fffb4" {
				testAccepts(t, u+mapTo+standard+"ec_add ED25519;"+tealBytes(ed25519Identity())+"==",
					edwardsVersion)
			} else {
				testAccepts(t, u+mapTo+standard+"==", edwardsVersion)
			}
		})
	}

	// The top bit of Monero's hash is data, not padding: ge_fromfe_frombytes_vartime
	// leaves out the mask that fe_frombytes applies, so a caller that masks
	// instead of reducing maps a value 19 away from the right one, and lands
	// somewhere else entirely. The first vector's hash has that bit set.
	masked := func(hash string) []byte {
		le, err := hex.DecodeString(hash)
		require.NoError(t, err)
		require.NotZero(t, le[31]&0x80, "vector does not exercise the top bit")
		le[31] &= 0x7f
		return reversed(le)
	}
	v := moneroMapVectors[0]
	testAccepts(t, tealBytes(masked(v.hash))+mapTo+tealBytes(moneroMapPoint(t, v.point))+"!=",
		edwardsVersion)

	// zero maps to the order-2 point, which the cofactor clearing takes to the
	// identity - the same answer the standard map gives 0, by a different route
	testAccepts(t, "byte 0x00;"+mapTo+tealBytes(ed25519Identity())+"==", edwardsVersion)
	testAccepts(t, "byte 0x;"+mapTo+tealBytes(ed25519Identity())+"==", edwardsVersion)

	// short inputs are accepted without 0-padding, as for the other curves
	testAccepts(t, "byte 0x07;"+mapTo+"byte 0x0000000000000000000000000000000000000000000000000000000000000007;"+mapTo+"==", edwardsVersion)

	// but not over-long ones, nor field elements at or above the modulus. This
	// map is defined on a 32 byte string, but the opcode's argument is a field
	// element for every group, so a caller reduces rather than relying on it.
	testPanics(t, "int 33; bzero;"+mapTo+"len", edwardsVersion, "Expected at most 32")
	testPanics(t, "byte 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;"+mapTo+"len",
		edwardsVersion, "larger than modulus")
}

// TestEd25519MoneroBranches checks the branch each vector above claims, by
// recomputing it from scratch. The implementation cannot report which branch it
// took, and a vector set that missed one would leave a quarter of the map
// untested while looking thorough. The claims also decide what
// TestEd25519MoneroMapTo expects of the standard map, so a wrong label there
// would be a test that passes for the wrong reason.
func TestEd25519MoneroBranches(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	p := ed25519FieldModulus
	mod := func(x *big.Int) *big.Int { return new(big.Int).Mod(x, p) }
	j := big.NewInt(486662)
	// i is a square root of -1, and (p+3)/4 the exponent that squares the
	// map's candidate root
	i := new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 2), p)
	quarter := new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(3)), 2)

	branch := func(u *big.Int) string {
		v := mod(new(big.Int).Lsh(new(big.Int).Mul(u, u), 1))
		w := mod(new(big.Int).Add(v, big.NewInt(1)))
		x := mod(new(big.Int).Sub(mod(new(big.Int).Mul(w, w)), mod(new(big.Int).Mul(mod(new(big.Int).Mul(j, j)), v))))
		require.NotZero(t, x.Sign(), "x is 0, which the map cannot divide by")
		s := mod(new(big.Int).Mul(w, new(big.Int).ModInverse(x, p)))
		xx := mod(new(big.Int).Mul(new(big.Int).Exp(s, quarter, p), x))
		switch {
		case xx.Cmp(w) == 0:
			return "fffb2"
		case xx.Cmp(mod(new(big.Int).Neg(w))) == 0:
			return "fffb1"
		}
		xi := mod(new(big.Int).Mul(xx, i))
		switch {
		case mod(new(big.Int).Sub(w, xi)).Sign() == 0:
			return "fffb4"
		case mod(new(big.Int).Add(w, xi)).Sign() == 0:
			return "fffb3"
		}
		return "none" // the case ed25519MoneroMapTo returns an error for
	}

	seen := map[string]bool{}
	for _, v := range moneroMapVectors {
		require.Equal(t, v.branch, branch(new(big.Int).SetBytes(moneroMapArg(t, v.hash))), v.hash)
		seen[v.branch] = true
	}
	require.Equal(t, map[string]bool{"fffb1": true, "fffb2": true, "fffb3": true, "fffb4": true}, seen)
}

// TestEd25519MoneroConstants checks the six constants the map multiplies by,
// which are derived here rather than copied out of Monero's limb arrays. It also
// settles two claims the implementation depends on: that all four roots exist,
// and that no input can drive the map's Z to zero.
func TestEd25519MoneroConstants(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	p := ed25519FieldModulus
	legendre := func(x *big.Int) int {
		switch s := new(big.Int).Exp(new(big.Int).Mod(x, p), new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1), p); {
		case s.Sign() == 0:
			return 0
		case s.Cmp(big.NewInt(1)) == 0:
			return 1
		default:
			return -1
		}
	}
	// p is 5 mod 8, which is what makes 2 and sqrt(-1) non-squares
	require.EqualValues(t, 5, new(big.Int).Mod(p, big.NewInt(8)).Int64())
	require.Equal(t, -1, legendre(big.NewInt(2)))

	j := big.NewInt(486662)
	jj2 := new(big.Int).Mul(j, new(big.Int).Add(j, big.NewInt(2))) // A*(A+2)
	i := new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 2), p)
	require.Equal(t, -1, legendre(i))

	// A*(A+2) is a non-square, and that is exactly what leaves the four roots
	// the map needs all existing: 2*A*(A+2) because 2 is a non-square too, and
	// both of +/-i*A*(A+2) because i is.
	require.Equal(t, -1, legendre(jj2))
	require.Equal(t, 1, legendre(new(big.Int).Lsh(jj2, 1)))
	require.Equal(t, 1, legendre(new(big.Int).Mul(i, jj2)))
	require.Equal(t, 1, legendre(new(big.Int).Mul(new(big.Int).Neg(i), jj2)))

	// and the derived constants really are roots of those values
	toBig := func(e *edfield.Element) *big.Int { return new(big.Int).SetBytes(reversed(e.Bytes())) }
	square := func(x *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(x, x), p) }
	norm := func(x *big.Int) *big.Int { return new(big.Int).Mod(x, p) }
	require.Equal(t, norm(new(big.Int).Neg(j)), toBig(ed25519MontNegJ))
	require.Equal(t, norm(new(big.Int).Neg(new(big.Int).Mul(j, j))), toBig(ed25519MontNegJSq))
	require.Equal(t, norm(big.NewInt(-1)), square(toBig(ed25519SqrtM1)))
	require.Equal(t, norm(new(big.Int).Neg(new(big.Int).Lsh(jj2, 1))), square(toBig(ed25519MoneroFFFB1)))
	require.Equal(t, norm(new(big.Int).Lsh(jj2, 1)), square(toBig(ed25519MoneroFFFB2)))
	require.Equal(t, norm(new(big.Int).Mul(new(big.Int).Neg(toBig(ed25519SqrtM1)), jj2)), square(toBig(ed25519MoneroFFFB3)))
	require.Equal(t, norm(new(big.Int).Mul(toBig(ed25519SqrtM1), jj2)), square(toBig(ed25519MoneroFFFB4)))

	// The map's Z is z+w, and z is either -A*v (with v = w-1) or -A. So Z is 0
	// only for u^2 == 1/(2*(A-1)) or u^2 == (A-1)/2, and neither is a square, so
	// no u reaches the degenerate case at all. The implementation still returns
	// an error there rather than a point that is not on the curve.
	half := new(big.Int).ModInverse(big.NewInt(2), p)
	require.Equal(t, -1, legendre(new(big.Int).ModInverse(new(big.Int).Lsh(new(big.Int).Sub(j, big.NewInt(1)), 1), p)))
	require.Equal(t, -1, legendre(new(big.Int).Mul(new(big.Int).Sub(j, big.NewInt(1)), half)))
}

func TestEd25519Versioning(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	// ED25519 was introduced in v14; earlier versions reject it at assembly.
	testProg(t, "byte 0x00; byte 0x00; ec_add ED25519", edwardsVersion-1,
		exp(1, "ec_add ED25519 field was introduced in v14. Missed #pragma version?"))
	testProg(t, "byte 0x00; byte 0x00; ec_add ED25519", edwardsVersion) // ok at v14

	// ED25519 is not valid for ec_pairing_check, at any version, there being no
	// pairing on it to check.
	testProg(t, "byte 0x00; byte 0x00; ec_pairing_check ED25519", edwardsVersion,
		exp(1, "ec_pairing_check unknown field: \"ED25519\""))

	// Need to confirm it also fails at evaluation time, patch in the ED field
	// code. The complaint names the field byte rather than the group, because
	// ec_pairing_check's cost depends on the field, so eval checks that the
	// field is one it accepts before it charges anything for it.
	ep := defaultSigParams()
	ops := testProg(t, "#pragma autosalt false\n byte 0x00; byte 0x00; ec_pairing_check BLS12_381g2", edwardsVersion)
	ops.Program[len(ops.Program)-1] = byte(ED25519)
	testLogicBytes(t, ops.Program, ep, fmt.Sprintf("ec_pairing_check unknown field: %d", ED25519))

	// but it is valid for every other ec_ opcode, subject to the same version gate
	testProg(t, "byte 0x00; ec_subgroup_check ED25519", edwardsVersion)
	testProg(t, "byte 0x00; ec_map_to ED25519", edwardsVersion)
	testProg(t, "byte 0x00; ec_map_to ED25519", edwardsVersion-1,
		exp(1, "ec_map_to ED25519 field was introduced in v14. Missed #pragma version?"))

	// The version gate has to hold at evaluation as well, since assembly is not
	// in the loop for hand-written bytecode. Without it, a v10 program could
	// name a group that did not exist when it was written, and would be
	// accepted by nodes that have this code and rejected by nodes that do not.
	for _, test := range []struct{ op, args string }{
		{"ec_add", "byte 0x00; byte 0x00;"},
		{"ec_scalar_mul", "byte 0x00; byte 0x00;"},
		{"ec_multi_scalar_mul", "byte 0x00; byte 0x00;"},
		{"ec_subgroup_check", "byte 0x00;"},
		{"ec_map_to", "byte 0x00;"},
	} {
		// autosalt off, and the group immediate last, so patching the final
		// byte swaps the group without disturbing anything else
		ops = testProg(t, "#pragma autosalt false\n"+test.args+test.op+" BLS12_381g1", pairingVersion)
		ops.Program[len(ops.Program)-1] = byte(ED25519)
		testLogicBytes(t, ops.Program, ep, "invalid "+test.op+" group ED25519")
	}
}

// TestEd25519MoneroVersioning is TestEd25519Versioning for the second
// edwards25519 map, which is more tightly held: ec_map_to is the only opcode
// that takes it, because it names a map rather than a group. Nothing else has a
// use for it, and letting it through would leave two spellings of one group.
func TestEd25519MoneroVersioning(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	testProg(t, "byte 0x00; ec_map_to ED25519_Monero", edwardsVersion) // ok at v14
	testProg(t, "byte 0x00; ec_map_to ED25519_Monero", edwardsVersion-1,
		exp(1, "ec_map_to ED25519_Monero field was introduced in v14. Missed #pragma version?"))

	for _, test := range []struct{ op, args string }{
		{"ec_add", "byte 0x00; byte 0x00;"},
		{"ec_scalar_mul", "byte 0x00; byte 0x00;"},
		{"ec_pairing_check", "byte 0x00; byte 0x00;"},
		{"ec_multi_scalar_mul", "byte 0x00; byte 0x00;"},
		{"ec_subgroup_check", "byte 0x00;"},
	} {
		// every other ec_ opcode rejects the name at assembly, at any version
		testProg(t, test.args+test.op+" ED25519_Monero", edwardsVersion,
			exp(1, test.op+" unknown field: \"ED25519_Monero\""))

		// and at evaluation, which is what actually holds the line, since
		// hand-written bytecode never passes through the assembler
		ops := testProg(t, "#pragma autosalt false\n"+test.args+test.op+" BLS12_381g1", pairingVersion)
		ops.Program[len(ops.Program)-1] = byte(ED25519_Monero)
		testLogicBytes(t, ops.Program, defaultSigParams(),
			fmt.Sprintf("%s unknown field: %d", test.op, ED25519_Monero))
	}
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
` + ed25519TealHelpers

// ed25519TealHelpers are the subroutines any ed25519 program needs, because the
// ec_ opcodes take big-endian coordinates and uncompressed points, while
// ed25519 itself encodes little-endian and compressed. Appended to the programs
// below, which jump into them.
const ed25519TealHelpers = `
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

// ringVerifySource verifies a ring signature: n public keys, one of whose owners
// signed, and no way to tell which. Signing produces a chain of challenges that
// closes on itself, and verifying walks the chain and checks that it does:
//
//	for i in 0..n-1:   c[i+1] = H(m || compress([s_i]B + [c_i]P_i))
//	accept if c[n] == c[0]
//
// where H is keccak-256 read as a little-endian scalar and reduced, which is
// Monero's hash_to_scalar. Only the signer's own step is computed forwards
// (from a random nonce); every other s_i is chosen at random and the challenge
// it produces is whatever it is. The verifier cannot tell the two apart.
//
// The chain is the shape RingCT's MLSAG takes. Monero's own pre-RingCT
// signature sums its challenges instead, and linkableRingVerifySource below
// verifies that one exactly, against Monero's test vectors.
//
//	arg 0  message
//	arg 1  c[0], the challenge the ring must close on (32 byte little-endian)
//	arg 2  s_0..s_n-1, concatenated 32 byte little-endian scalars
//	arg 3  the ring: P_0..P_n-1, concatenated 32 byte compressed points
//	arg 4  hint: the same points uncompressed, 64 bytes each
//
// The hints are untrusted and checked by compressing them, exactly as in
// ed25519VerifySource. Nothing else needs to bind the ring, since substituting
// a key changes every later challenge and the chain stops closing.
//
// It costs 466 plus about 3,880 per ring member, so a ring of five fits in one
// logic sig and Monero's current ring size of sixteen (62,595) needs four
// pooled. Half of the per-member cost is the multi-exp; most of the rest is
// byte reversal, since Monero is little-endian throughout and the ec_ opcodes
// are big-endian.
//
// WHAT THIS LEAVES OUT. Monero's ring signatures are *linkable*, and that is
// the part that stops double spends: alongside each L_i the signer publishes a
// key image I and the verifier also computes
//
//	R_i = [s_i]H_p(P_i) + [c_i]I
//
// where H_p hashes a public key to a curve point. Because I = [x]H_p(P) for the
// signer's own secret x, one key always yields one image, so a second spend is
// spotted without learning which ring member spent.
//
// H_p is keccak-256 followed by ge_fromfe_frombytes_vartime, a map CryptoNote
// wrote years before RFC 9380, and then the cofactor. ec_map_to ED25519 is not
// it: that is Elligator 2 as the RFC specifies, which agrees with Monero's map
// on half of its inputs and returns the negation on the other half, so it would
// compute the right key image half the time. Elligator 2 is nonetheless the
// right meaning for the plain name - see the reasoning where ed25519MapTo is
// defined - so Monero's map has its own immediate, ED25519_Monero, and
// linkableRingVerifySource below verifies the linkable signature in full.
//
// Hinting H_p would not have done instead. Hints work for decompression because
// compressing is the cheap direction, so a claimed point can be checked.
// Hash-to-point has no cheap inverse, and a hinted H_p(P_i) that nobody
// verifies is a forgery, since choosing it freely lets one key produce any
// number of images.
//
// This is also the pre-RingCT signature. Current Monero uses CLSAG, which adds
// commitment layers and aggregation coefficients on top of the above, and
// Bulletproofs range proofs, which are far out of reach.
const ringVerifySource = `
// the ring's length sets n, and the other two arrays must agree with it
arg 3; len; int 32; %; !; assert	// whole keys only
arg 3; len; int 32; /
dup; assert				// a ring of nobody signs nothing
store 0					// n
arg 2; len; load 0; int 32; *; ==; assert
arg 4; len; load 0; int 64; *; ==; assert

// c[0], which is both where the walk starts and what it must come back to
arg 1; callsub reverse
dup
byte 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed // L
b<; assert				// canonical, as Monero's sc_check demands
dup; store 1				// running challenge
store 3					// and the value to close against

int 0; store 2				// i

ring_loop:
// P_i, from the hint, and it must be the key the ring names
arg 4; load 2; int 64; *; int 64; extract3
dup; callsub compress
arg 3; load 2; int 32; *; int 32; extract3
==; assert				// leaves the uncompressed P_i

// L_i = [s_i]B + [c]P_i, one multi-exp rather than two multiplies and an add
byte 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a6666666666666666666666666666666666666666666666666666666666666658 // B
swap; concat				// B then P_i
arg 2; load 2; int 32; *; int 32; extract3; callsub reverse
dup
byte 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed // L
b<; assert				// s_i canonical too
load 1; concat				// s_i then c, matching the points
ec_multi_scalar_mul ED25519
callsub compress			// Monero hashes points compressed

// c = H(m || L_i)
arg 0; swap; concat
keccak256
callsub reverse				// the digest is read as a little-endian scalar
byte 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed // L
b%
int 32; bzero; b|			// b% trims leading zeros, and scalars are fixed width
store 1

load 2; int 1; +; dup; store 2
load 0; <
bnz ring_loop

// the ring closes
load 1; load 3; ==
return
` + ed25519TealHelpers

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

// ringChallenge is Monero's hash_to_scalar over a message and a point: keccak,
// read little-endian, reduced.
func ringChallenge(msg []byte, l *edwards25519.Point) *edwards25519.Scalar {
	h := sha3.NewLegacyKeccak256()
	h.Write(msg)
	h.Write(l.Bytes()) // compressed, as Monero hashes points
	k := new(big.Int).SetBytes(reversed(h.Sum(nil)))
	s, err := bigIntToEd25519Scalar(k)
	if err != nil {
		panic(err)
	}
	return s
}

// ringSign signs msg on behalf of ring[signer], whose secret it is given. It is
// the construction the verifier inverts: run one step forwards from a random
// nonce, pick every other scalar at random and accept whatever challenges they
// produce, then solve for the signer's own scalar so that the chain closes.
// Which index did the solving is not recoverable from the result.
func ringSign(ring []*edwards25519.Point, secret *edwards25519.Scalar, signer int, msg []byte) (c0 []byte, scalars []byte) {
	n := len(ring)
	s := make([]*edwards25519.Scalar, n)
	c := make([]*edwards25519.Scalar, n) // c[i] is the challenge entering step i

	// the signer's step, forwards from the nonce: L = [alpha]B
	alpha := ed25519RandomScalar()
	c[(signer+1)%n] = ringChallenge(msg, new(edwards25519.Point).ScalarBaseMult(alpha))

	// every other step, with a scalar picked before the challenge it produces
	for k := 1; k < n; k++ {
		i := (signer + k) % n
		s[i] = ed25519RandomScalar()
		l := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(c[i], ring[i], s[i])
		c[(i+1)%n] = ringChallenge(msg, l)
	}

	// solve: [s]B + [c]P == [alpha]B when s == alpha - c*x
	s[signer] = new(edwards25519.Scalar).Subtract(alpha,
		new(edwards25519.Scalar).Multiply(c[signer], secret))

	for _, si := range s {
		scalars = append(scalars, si.Bytes()...)
	}
	return c[0].Bytes(), scalars
}

func TestRingVerifyInTeal(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	teal := testProg(t, ringVerifySource, edwardsVersion).Program
	msg := []byte("spend it once")

	// a ring, and the secrets that would let each member sign
	const n = 5
	secrets := make([]*edwards25519.Scalar, n)
	ring := make([]*edwards25519.Point, n)
	for i := range ring {
		secrets[i] = ed25519RandomScalar()
		ring[i] = new(edwards25519.Point).ScalarBaseMult(secrets[i])
	}
	// the two encodings of the ring: compressed as the signature names it,
	// uncompressed as the opcodes consume it
	packed := func(ring []*edwards25519.Point) (compressed, uncompressed []byte) {
		for _, p := range ring {
			compressed = append(compressed, p.Bytes()...)
			uncompressed = append(uncompressed, ed25519PointToBytes(p)...)
		}
		return
	}
	compressed, uncompressed := packed(ring)

	accepts := func(args [][]byte) bool {
		var txn transactions.SignedTxn
		txn.Lsig.Logic = teal
		txn.Lsig.Args = args
		pass, err := EvalSignature(0, defaultSigParams(txn))
		return pass && err == nil
	}

	// any member can sign, and the signature does not say which did
	for signer := range ring {
		c0, scalars := ringSign(ring, secrets[signer], signer, msg)
		require.True(t, accepts([][]byte{msg, c0, scalars, compressed, uncompressed}),
			"signer %d", signer)
	}

	c0, scalars := ringSign(ring, secrets[2], 2, msg)
	good := [][]byte{msg, c0, scalars, compressed, uncompressed}
	require.True(t, accepts(good))

	// break each part in turn, and the chain stops closing
	var breakTests = []struct {
		name string
		arg  int
		mung func([]byte) []byte
	}{
		{"message", 0, func(b []byte) []byte { return append(slices.Clone(b), '!') }},
		{"starting challenge", 1, func(b []byte) []byte { return flipScalar(b) }},
		{"a scalar", 2, func(b []byte) []byte { return flipScalar(b) }},
		{"another scalar", 2, func(b []byte) []byte {
			c := slices.Clone(b)
			copy(c[3*32:4*32], flipScalar(c[3*32:4*32]))
			return c
		}},
	}
	for _, test := range breakTests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			broken := slices.Clone(good)
			broken[test.arg] = test.mung(broken[test.arg])
			require.False(t, accepts(broken))
		})
	}

	// a different ring does not verify, even one that differs by a single key
	other := slices.Clone(ring)
	other[4] = new(edwards25519.Point).ScalarBaseMult(ed25519RandomScalar())
	otherCompressed, otherUncompressed := packed(other)
	require.False(t, accepts([][]byte{msg, c0, scalars, otherCompressed, otherUncompressed}))

	// a hint that is a real point, but not the key the ring names, is caught
	lying := slices.Clone(good)
	lying[4] = slices.Clone(uncompressed)
	copy(lying[4][64:128], ed25519RandomPoint())
	require.False(t, accepts(lying))

	// a ring of one is just a Schnorr signature, and still works
	single := []*edwards25519.Point{ring[0]}
	singleCompressed, singleUncompressed := packed(single)
	c0, scalars = ringSign(single, secrets[0], 0, msg)
	require.True(t, accepts([][]byte{msg, c0, scalars, singleCompressed, singleUncompressed}))

	// lengths that do not agree, and a ring of nobody, are program failures
	var txn transactions.SignedTxn
	txn.Lsig.Args = [][]byte{msg, good[1], good[2], compressed[:32*4], uncompressed}
	testLogicBytes(t, teal, defaultSigParams(txn), "assert failed")
	txn.Lsig.Args = [][]byte{msg, good[1], good[2], compressed[:31], uncompressed}
	testLogicBytes(t, teal, defaultSigParams(txn), "assert failed")
	txn.Lsig.Args = [][]byte{msg, good[1], nil, nil, nil}
	testLogicBytes(t, teal, defaultSigParams(txn), "assert failed")
}

// flipScalar changes a 32 byte little-endian scalar, keeping it canonical by
// touching a low byte rather than the top one.
func flipScalar(b []byte) []byte {
	c := slices.Clone(b)
	c[0] ^= 1
	return c
}

// linkableRingVerifySource verifies Monero's pre-RingCT ring signature in full,
// which is to say the linkable one, key image and all. It is crypto::check_ring_signature
// from src/crypto/crypto.cpp, and the shape is not the chain that
// ringVerifySource walks. Every step is computed forwards, and the challenges
// are checked by summing them:
//
//	for i in 0..n-1:
//	    L_i = [r_i]B        + [c_i]P_i
//	    R_i = [r_i]H_p(P_i) + [c_i]I
//	accept if sum(c_i) == H(prefix || L_0 || R_0 || ... || L_n-1 || R_n-1)
//
// where H is Monero's hash_to_scalar (keccak-256 read little-endian, reduced)
// and H_p its hash to point: keccak-256 of the compressed key, then
// ec_map_to ED25519_Monero, which is where the whole of this program's reason
// for existing sits. The signer knows one x with P = [x]B, publishes
// I = [x]H_p(P), and can answer the challenge at that one index; the ring hides
// which index that was. Because I is a function of the key alone, a second
// signature by the same key repeats it, and that is what stops a double spend.
//
// Nothing here needs to bind the ring beyond the hash: substituting a key
// changes L_i and R_i, and the sum stops matching.
//
//	arg 0  prefix hash, the message the signature commits to
//	arg 1  the key image I, 32 byte compressed
//	arg 2  the ring: P_0..P_n-1, concatenated 32 byte compressed points
//	arg 3  the signature: n pairs of 32 byte little-endian scalars, c_i then r_i
//	arg 4  hint: I uncompressed, then the ring uncompressed, 64 bytes each
//
// The hints are untrusted and checked by compressing them, as in
// ringVerifySource. H_p(P_i) is not hinted and could not be: compressing is the
// cheap direction, so a claimed decompression can be checked, but a claimed
// hash to point cannot, and a program that took one on trust would let a single
// key produce as many images as it liked.
//
// It costs 1,069 plus 7,125 per ring member, so three members exhaust one logic
// sig and Monero's current ring size of sixteen (115,069) needs six pooled. The
// two multi-exponentiations are over half of the per-member cost and the byte
// reversals are most of the rest; the map this is all for is 350 of it.
//
// WHAT THIS LEAVES OUT. check_ring_signature is the whole of the pre-RingCT
// signature, but not the whole of what a Monero node checks. The key image is
// tested for the main subgroup elsewhere in Monero, and a verifier that wanted
// that here would add ec_subgroup_check ED25519 on the hinted I. Current Monero
// uses CLSAG rather than this, which adds commitment layers and aggregation
// coefficients, and Bulletproofs range proofs, which are far out of reach.
const linkableRingVerifySource = `
arg 0; len; int 32; ==; assert		// a hash, not a message of any length

// the ring's length sets n, and the other arrays must agree with it
arg 2; len; int 32; %; !; assert	// whole keys only
arg 2; len; int 32; /
dup; assert				// a ring of nobody signs nothing
store 0					// n
arg 3; len; load 0; int 64; *; ==; assert
arg 4; len; load 0; int 1; +; int 64; *; ==; assert

// I, from the first hint, and it must be the image the signature names
arg 4; extract 0 64
dup; callsub compress
arg 1; ==; assert
store 4					// uncompressed I

arg 0; store 5				// what gets hashed: prefix, then every L and R
int 32; bzero; store 6			// the running sum of challenges
int 0; store 2				// i

ring_loop:
// c_i and r_i, both canonical, as Monero's sc_check demands
arg 3; load 2; int 64; *; int 32; extract3; callsub reverse
dup
byte 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed // L
b<; assert
store 1					// c_i
arg 3; load 2; int 64; *; int 32; +; int 32; extract3; callsub reverse
dup
byte 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed // L
b<; assert
store 3					// r_i

// P_i, from its hint, and it must be the key the ring names
arg 4; load 2; int 1; +; int 64; *; int 64; extract3
dup; callsub compress
arg 2; load 2; int 32; *; int 32; extract3
==; assert				// leaves the uncompressed P_i

// L_i = [r_i]B + [c_i]P_i, one multi-exp rather than two multiplies and an add
byte 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a6666666666666666666666666666666666666666666666666666666666666658 // B
swap; concat				// B then P_i
load 3; load 1; concat			// r_i then c_i, matching the points
ec_multi_scalar_mul ED25519
callsub compress			// Monero hashes points compressed
load 5; swap; concat; store 5

// H_p(P_i). The digest is a 32 byte string to Monero and a field element to
// ec_map_to, so it is reversed and reduced on the way in.
arg 2; load 2; int 32; *; int 32; extract3
keccak256
callsub reverse
byte 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed // p
b%
ec_map_to ED25519_Monero

// R_i = [r_i]H_p(P_i) + [c_i]I
load 4; concat				// H_p(P_i) then I
load 3; load 1; concat
ec_multi_scalar_mul ED25519
callsub compress
load 5; swap; concat; store 5

// the challenges are summed here, not chained as in ringVerifySource
load 6; load 1; b+
byte 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed // L
b%
int 32; bzero; b|			// b% trims leading zeros, and scalars are fixed width
store 6

load 2; int 1; +; dup; store 2
load 0; <
bnz ring_loop

// the signature stands if the challenges sum to the hash of the whole walk
load 5; keccak256; callsub reverse
byte 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed // L
b%
int 32; bzero; b|
load 6; ==
return
` + ed25519TealHelpers

// linkableRingVectors come from the check_ring_signature lines of Monero's
// tests/crypto/tests.txt, which carry both signatures that verify and
// signatures that do not. They are real Monero ring signatures, so a program
// that accepts exactly these is one Monero would agree with.
var linkableRingVectors = []struct {
	valid         bool
	prefix, image string
	ring          []string
	sig           string
}{
	{valid: false,
		prefix: "d26f225fcb6ca8e13089a96e17d1844cc0264af9f7149048b96ad0de6f16567c",
		image:  "e3eff7c3e814a43140a264bd49704171f93baa8806c561b7448a0441ad1a32cf",
		ring: []string{
			"9e5ba7c35a5a809999bc39e543adf5a1bf007c7236498c3a772f4daeeeea30e0",
		},
		sig: "cf80ccacc126c14015e06d5c631484d659f75bb87a596e9e4a988957533e5307" +
			"f8cd8bae2044231358b1d495814fab2710fd47e7529625a1f0fa2f2093e8a40e",
	},
	{valid: true,
		prefix: "c70652ca5f06255dc529bc0924491754f5fad28552f4c9cd7e396f1582cecdca",
		image:  "89d2e649616ccdf1680e0a3f316dcbd59f0c7f20eba96e86500aa68f123f9ecd",
		ring: []string{
			"9cc7f48f7a41d634397102d46b71dd46e6accd6465b903cb83e1c2cd0c41744e",
		},
		sig: "3e292a748b8814564f4f393b6c4bd2eaaface741b37fd7ac39c06ab41f1b700d" +
			"b548462601351a1226e8247fea67df6f49ea8f7d952a66b9ec9456a99ce7b90b",
	},
	{valid: false,
		prefix: "01504ac79366978307ff9ddf25e051817a2a94f1f71e5e03b6fa0353ed25e6a3",
		image:  "c26444038d90ac980e62ae2b51e8bf08eaea3d9e42ebb9a024bc19ac641e4826",
		ring: []string{
			"f7f38889ea8803c737651de3a1be85e5403f4d742a9165e6d36d760e1b1b9342",
			"b193744ea1cb8c2a6e780fda538e776343cd0d6c469c16e60a62793e1fe62bc9",
		},
		sig: "77ab659d67aed19f3a98b3a79d2a11fa1dff903ff3588c343ac6f43139e43104" +
			"e2861a14a787aabd4f9739e954a07276722d8dd9b567b8b7bdff3ff97dc5b30e" +
			"fca0e003a4017c33d224bf4f2ae768ec6ee51284a06b855faa9a50d643754908" +
			"f6875872fb236c17354024708e507275e061096d7c19610754161ee45c8aa40f",
	},
	{valid: true,
		prefix: "90660b84dd3be5705c7766695fec404348af6df58f8c5d58213f3b70b8b67a23",
		image:  "6289b9b151eeb263fc29e4b5e90978db7670f06f408403c8973bbfff2a884dd9",
		ring: []string{
			"4af96f2c3a70ac1860d48132136989c1d38551367025d43f36aec0ffa8e7f28a",
			"376cc178d8ae3a68ce467bfbe719e88b22514617dbd1e764e0b94b4f6bc961af",
		},
		sig: "4ccadd504d1d03e385ebd25dc51b98c6f3a0e1c1be7e5694e44dc2377898510c" +
			"a3202d7872294cc04b65d8c109e3a6e843c327b3416ca3a2b1c585fe41522605" +
			"55441dd7b1543549f749acf5fc9a93a3f3c240425c5f7cadccdef4f06cef0702" +
			"ae4ad477d0cb60a1a48c1da22f5a8b20c7c5672833c7ae13f78edeb3db1a7b01",
	},
	{valid: true,
		prefix: "f6d2c5db9f57fca3c124032a588abaa623e16373c859cecce4cbd95f175edde5",
		image:  "be3aaaae636683d032cea44982b860687072eb87bd5d8419e76c19075f8b3238",
		ring: []string{
			"0f73c60791e9d89110da4e459a9c8a08df9bd87f95ebe1553c9605214e87862a",
			"57dec9cd6476939b62c0d1743d3f2da84551486525917abd866415d8bc42cb50",
			"627a0c2a9a5e279f17b1b949364cb62706bb6c56f01eafe7a6b21dee06858218",
			"82e0318d21793d7a50de4cd3210681fee3a94db40d756de03bc8e73ebdfc3946",
		},
		sig: "062f6896ea42d4a27eb2a760b1b3941ba7c36e655bc3e58499cc83cdddea1e00" +
			"e07d7c00f7ed3accc20830485a5c561dd809e7fea35553cb7e5cdbdd939b5c0e" +
			"a60030190addb34d76155254f5f290370e3ea93aaeadaab8be2401b1204a920d" +
			"16e4e63c8d763bfd379b49ee4489de92b2b2eee1acc704570fe594d22052ce06" +
			"70925c65613ffbc6d34c4202ccab7862d5d89bc567f8f22e748ff0227d2dd208" +
			"f4fc34f51e511a28921abb92e7abd56e7e2e51996a30d7c5cef55665e5346c03" +
			"5b7b533dc0bdc490f347be660a8d95f1a897cb2c68fbd88927a3a969ef9a610e" +
			"63594aa6d83863c9c689b8a51bb59fbc6076e3718a76dafe715865de4f62f104",
	},
}

func TestLinkableRingVerifyInTeal(t *testing.T) {
	partitiontest.PartitionTest(t)
	t.Parallel()

	teal := testProg(t, linkableRingVerifySource, edwardsVersion).Program

	// hints for the image and every ring member, in the order the program reads
	// them. They are untrusted, and the program checks them by compressing.
	hints := func(image string, ring []string) []byte {
		out := ed25519Hint(unhex(t, image))
		for _, p := range ring {
			out = append(out, ed25519Hint(unhex(t, p))...)
		}
		return out
	}

	args := func(v struct {
		valid         bool
		prefix, image string
		ring          []string
		sig           string
	}) [][]byte {
		var ring []byte
		for _, p := range v.ring {
			ring = append(ring, unhex(t, p)...)
		}
		return [][]byte{unhex(t, v.prefix), unhex(t, v.image), ring,
			unhex(t, v.sig), hints(v.image, v.ring)}
	}

	for i, v := range linkableRingVectors {
		t.Run(fmt.Sprintf("monero/%d/n=%d", i, len(v.ring)), func(t *testing.T) {
			t.Parallel()
			require.Equal(t, v.valid, ringAccepts(t, teal, args(v), len(v.ring)))
		})
	}

	// The cost quoted on linkableRingVerifySource, measured rather than
	// asserted, so that the note cannot quietly rot and neither can the pooling
	// ringAccepts does from the same two numbers.
	for _, v := range linkableRingVectors {
		if !v.valid {
			continue // a rejected signature stops early and costs less
		}
		var txn transactions.SignedTxn
		txn.Lsig.Logic = teal
		txn.Lsig.Args = args(v)
		ep := defaultSigParams(txn)
		const plenty = 10_000_000
		remaining := plenty // eval spends this in place, so keep the start separately
		ep.PooledLogicSigBudget = &remaining
		pass, err := EvalSignature(0, ep)
		require.NoError(t, err)
		require.True(t, pass)
		require.Equal(t, linkableRingBase+linkableRingPer*len(v.ring), plenty-remaining)
	}

	// The rest works from one good signature, and breaks it in a different way
	// each time. A key image is only worth anything if it cannot be moved.
	good := linkableRingVectors[len(linkableRingVectors)-1]
	require.True(t, good.valid)
	n := len(good.ring)
	require.Greater(t, n, 1)

	var breakTests = []struct {
		name string
		arg  int
		mung func([]byte) []byte
	}{
		{"prefix", 0, func(b []byte) []byte { return flipScalar(b) }},
		{"key image", 1, func(b []byte) []byte { return ed25519RandomCompressed() }},
		{"a ring member", 2, func(b []byte) []byte {
			c := slices.Clone(b)
			copy(c[32:64], ed25519RandomCompressed())
			return c
		}},
		{"a challenge", 3, func(b []byte) []byte { return flipScalar(b) }},
		{"a response", 3, func(b []byte) []byte {
			c := slices.Clone(b)
			copy(c[32:64], flipScalar(c[32:64]))
			return c
		}},
		{"the ring's order", 2, func(b []byte) []byte {
			c := slices.Clone(b)
			copy(c[:32], b[32:64])
			copy(c[32:64], b[:32])
			return c
		}},
	}
	for _, test := range breakTests {
		t.Run("broken "+test.name, func(t *testing.T) {
			t.Parallel()
			a := args(good)
			a[test.arg] = test.mung(a[test.arg])
			if test.arg == 1 || test.arg == 2 { // the hints must still match
				a[4] = hints(hex.EncodeToString(a[1]), splitPoints(a[2]))
			}
			require.False(t, ringAccepts(t, teal, a, n))
		})
	}

	// A hint that is a real point, but not the one it stands in for, is caught
	// by the compression check rather than trusted.
	a := args(good)
	copy(a[4][64:128], ed25519RandomPoint())
	require.False(t, ringAccepts(t, teal, a, n))

	// A scalar at or above the group order is where the program stops rather
	// than rejecting, which is Monero's sc_check drawn as an assert. The
	// vectors above all fail the ring equation itself instead, so this is the
	// only thing that covers that check.
	var txn transactions.SignedTxn
	txn.Lsig.Logic = teal
	pooled := make([]transactions.SignedTxn, 1+(linkableRingBase+linkableRingPer*n)/20_000)
	failsWith := func(args [][]byte, msg string) {
		txn.Lsig.Args = args
		pooled[0] = txn
		testLogicBytes(t, teal, defaultSigParams(pooled...), msg)
	}
	order := unhex(t, "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010") // L, little-endian
	noncanonical := args(good)
	copy(noncanonical[3], order)
	failsWith(noncanonical, "assert failed")

	// and arrays that do not agree on n are program failures too, not rejections
	short := args(good)
	short[2] = short[2][:32*(n-1)]
	failsWith(short, "assert failed")
	partial := args(good)
	partial[2] = partial[2][:31]
	failsWith(partial, "assert failed")
	failsWith([][]byte{args(good)[0], nil, nil, nil, nil}, "assert failed")
}

// linkableRingBase and linkableRingPer are what the linkable verifier costs,
// measured in TestLinkableRingVerifyInTeal rather than estimated here.
const (
	linkableRingBase = 1_069
	linkableRingPer  = 7_125
)

// ringAccepts runs the verifier over a ring of n, pooling as many logic sigs as
// the ring needs. One logic sig is 20,000, which runs out at three members, so
// spreading the cost over a group is the normal case rather than the exception.
func ringAccepts(t *testing.T, teal []byte, args [][]byte, n int) bool {
	t.Helper()
	txns := make([]transactions.SignedTxn, 1+(linkableRingBase+linkableRingPer*n)/20_000)
	txns[0].Lsig.Logic = teal
	txns[0].Lsig.Args = args
	pass, err := EvalSignature(0, defaultSigParams(txns...))
	return pass && err == nil
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func splitPoints(b []byte) []string {
	var out []string
	for i := 0; i < len(b); i += 32 {
		out = append(out, hex.EncodeToString(b[i:i+32]))
	}
	return out
}

// ed25519RandomCompressed is a random point in the compressed encoding Monero
// uses, for tests that need a well formed key that is the wrong key.
func ed25519RandomCompressed() []byte {
	p, err := bytesToEd25519Point(ed25519RandomPoint())
	if err != nil {
		panic(err)
	}
	return p.Bytes()
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
