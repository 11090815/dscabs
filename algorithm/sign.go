package algorithm

import (
	"crypto/sha256"

	"github.com/11090815/dscabs/ecdsa"
	"github.com/11090815/dscabs/ecdsa/bigint"
)

func Sign(params *SystemParams, m []byte, sk *bigint.BigInt) *ecdsa.EllipticCurveSignature {
	var r = ecdsa.RandNumOnCurve(params.Curve)
	var R = &ecdsa.EllipticCurvePoint{}
	var zero = new(bigint.BigInt).SetInt64(0)
	for {
		rx, ry := params.Curve.ScalarBaseMult(r.Bytes())
		R.X, R.Y = bigint.GoToBigInt(rx), bigint.GoToBigInt(ry)
		if R.X.Cmp(zero) != 0 && R.Y.Cmp(zero) != 0 {
			break
		}
	}

	var e = new(bigint.BigInt).SetBytes(sha256.New().Sum(m))
	var inverseK, _ = ecdsa.CalcInverseElem(r.GetGoBigInt(), params.Curve.Params().N)
	var s = new(bigint.BigInt).Set(sk)
	s.Mul(s, R.X)
	s.Add(s, e)
	s.Mul(s, inverseK)
	s.Mod(s, bigint.GoToBigInt(params.Curve.Params().N))
	return &ecdsa.EllipticCurveSignature{S: s, R: R.X}
}
