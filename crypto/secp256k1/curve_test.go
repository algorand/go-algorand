package secp256k1_test

import (
	"math/big"
	"testing"

	"github.com/algorand/go-algorand/crypto/secp256k1"
)

// Helper function to create a new big.Int from a hex string
func newBigInt(hex string) *big.Int {
	i, success := new(big.Int).SetString(hex, 0)
	if !success {
		panic("invalid hex string")
	}
	return i
}

func TestIsOnCurve(t *testing.T) {
	curve := secp256k1.S256()

	tests := []struct {
		x, y   *big.Int
		result bool
	}{
		// Base point should be on the curve
		{x: curve.Gx, y: curve.Gy, result: true},
		// Random point not on the curve
		{x: newBigInt("0x123456789abcdef"), y: newBigInt("0xabcdef123456789"), result: false},
	}

	for _, test := range tests {
		onCurve := curve.IsOnCurve(test.x, test.y)
		if onCurve != test.result {
			t.Errorf("IsOnCurve failed for x=%s, y=%s. Expected %v, got %v", test.x, test.y, test.result, onCurve)
		}
	}
}

func TestAdd(t *testing.T) {
	curve := secp256k1.S256()

	// Adding G to G should result in 2G
	x1, y1 := curve.Gx, curve.Gy
	x2, y2 := curve.Gx, curve.Gy
	x3, y3 := curve.Add(x1, y1, x2, y2)

	// Check if the result is on the curve
	if !curve.IsOnCurve(x3, y3) {
		t.Errorf("Add failed: point (x=%s, y=%s) is not on the curve", x3, y3)
	}
}

func TestDouble(t *testing.T) {
	curve := secp256k1.S256()

	// Doubling G should result in 2G
	x1, y1 := curve.Gx, curve.Gy
	x2, y2 := curve.Double(x1, y1)

	// Check if the result is on the curve
	if !curve.IsOnCurve(x2, y2) {
		t.Errorf("Double failed: point (x=%s, y=%s) is not on the curve", x2, y2)
	}
}

func TestScalarBaseMult(t *testing.T) {
	curve := secp256k1.S256()

	// Ensure curve is initialized
	if curve == nil {
		t.Fatal("curve initialization failed: secp256k1.S256() returned nil")
	}

	// Multiply the base point by 1, should return the base point itself
	x, y := curve.ScalarBaseMult([]byte{1})
	if x == nil || y == nil || x.Cmp(curve.Gx) != 0 || y.Cmp(curve.Gy) != 0 {
		t.Errorf("ScalarBaseMult failed for k=1: got (x=%v, y=%v), expected (x=%v, y=%v)", x, y, curve.Gx, curve.Gy)
	}

	// Multiply the base point by 0
	k := []byte{0}
	x, y = curve.ScalarBaseMult(k)
	if x == nil && y == nil {
		t.Logf("ScalarBaseMult for k=0 correctly returned point at infinity as (nil, nil)")
	} else if x.Sign() != 0 || y.Sign() != 0 {
		t.Errorf("ScalarBaseMult failed for k=0: got (x=%v, y=%v), expected infinity (0, 0)", x, y)
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	curve := secp256k1.S256()

	// Marshal and unmarshal the base point
	x, y := curve.Gx, curve.Gy
	data := curve.Marshal(x, y)
	x2, y2 := curve.Unmarshal(data)

	if x.Cmp(x2) != 0 || y.Cmp(y2) != 0 {
		t.Errorf("Marshal/Unmarshal failed: got (x=%s, y=%s), expected (x=%s, y=%s)", x2, y2, x, y)
	}
}

func TestAddInfinity(t *testing.T) {
	curve := secp256k1.S256()

	// Adding a point to the point at infinity should return the original point
	x, y := curve.Gx, curve.Gy
	xInf := new(big.Int).SetInt64(0)
	yInf := new(big.Int).SetInt64(0)

	x2, y2 := curve.Add(x, y, xInf, yInf)
	if x2.Cmp(x) != 0 || y2.Cmp(y) != 0 {
		t.Errorf("Add with infinity failed: got (x=%s, y=%s), expected (x=%s, y=%s)", x2, y2, x, y)
	}
}

func TestDoubleInfinity(t *testing.T) {
	curve := secp256k1.S256()

	// Doubling the point at infinity should return the point at infinity
	xInf := new(big.Int).SetInt64(0)
	yInf := new(big.Int).SetInt64(0)

	x2, y2 := curve.Double(xInf, yInf)
	if x2.Sign() != 0 || y2.Sign() != 0 {
		t.Errorf("Double infinity failed: got (x=%s, y=%s), expected infinity", x2, y2)
	}
}

func TestInvalidInputs(t *testing.T) {
	curve := secp256k1.S256()

	// Test with negative inputs
	negX := new(big.Int).Neg(curve.Gx)
	negY := new(big.Int).Neg(curve.Gy)
	if curve.IsOnCurve(negX, negY) {
		t.Errorf("Negative inputs should not be on the curve: x=%s, y=%s", negX, negY)
	}
}
