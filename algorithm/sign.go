package algorithm

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/11090815/dscabs/sm2"
)

// func Sign(params *SystemParams, m []byte, sk *bigint.BigInt) *ecdsa.EllipticCurveSignature {
// 	var r = ecdsa.RandNumOnCurve(params.Curve)
// 	var R = &ecdsa.EllipticCurvePoint{}
// 	var zero = new(bigint.BigInt).SetInt64(0)
// 	for {
// 		rx, ry := params.Curve.ScalarBaseMult(r.Bytes())
// 		R.X, R.Y = bigint.GoToBigInt(rx), bigint.GoToBigInt(ry)
// 		if R.X.Cmp(zero) != 0 && R.Y.Cmp(zero) != 0 {
// 			break
// 		}
// 	}

// 	var e = new(bigint.BigInt).SetBytes(sha256.New().Sum(m))
// 	var inverseK, _ = ecdsa.CalcInverseElem(r.GetGoBigInt(), params.Curve.Params().N)
// 	var s = new(bigint.BigInt).Set(sk)
// 	s.Mul(s, R.X)
// 	s.Add(s, e)
// 	s.Mul(s, inverseK)
// 	s.Mod(s, bigint.GoToBigInt(params.Curve.Params().N))
// 	return &ecdsa.EllipticCurveSignature{S: s, R: R.X}
// }

func Sign(privkey *sm2.PrivateKey, m []byte) (string, error) {
	sig, err := privkey.Sign(rand.Reader, m, nil)
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %v", err)
	}

	return hex.EncodeToString(sig), nil
}
