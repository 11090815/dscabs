package bigint

import "testing"

func TestBigIntBasic(t *testing.T) {
	x := new(BigInt).SetInt64(72)
	y := new(BigInt).SetInt64(8)

	x.Exp(x, y, new(BigInt).SetInt64(123))
	t.Log(x)
}
