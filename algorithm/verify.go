package algorithm

import (
	"math/big"

	"github.com/11090815/dscabs/ecdsa"
	"github.com/11090815/dscabs/ecdsa/bigint"
	"github.com/11090815/dscabs/sm2"
)

func Verify(params *SystemParams, userAPK map[string]*ecdsa.EllipticCurvePoint, userPK *sm2.PublicKey, key *Key, m []byte, sig *ecdsa.EllipticCurveSignature) bool {
	if key == nil {
		return false
	}
	t := &track{m: make(map[*Key][]struct {
		key   *Key
		point *ecdsa.EllipticCurvePoint
	})}
	return verify(params, userAPK, userPK, key, m, sig, t, 1)
}

func VerifyNode(params *SystemParams, key *Key, userPK map[string]*ecdsa.EllipticCurvePoint) *ecdsa.EllipticCurvePoint {
	var res = &ecdsa.EllipticCurvePoint{
		X: new(bigint.BigInt).Set(ecdsa.Bottom.X),
		Y: new(bigint.BigInt).Set(ecdsa.Bottom.Y),
	}
	if key.Children == nil {
		// leaf node.
		if pki, ok := userPK[key.HashVal]; ok {
			resX, resY := params.Curve.ScalarMult(pki.X.GetGoBigInt(), pki.Y.GetGoBigInt(), key.Du.Bytes())
			res.X, res.Y = bigint.GoToBigInt(resX), bigint.GoToBigInt(resY)
		}
	}
	return res
}

func verify(params *SystemParams, userAPK map[string]*ecdsa.EllipticCurvePoint, userPK *sm2.PublicKey, key *Key, m []byte, sig *ecdsa.EllipticCurveSignature, t *track, stack int) bool {
	if key.Children == nil || len(key.Children) == 0 {
		point := VerifyNode(params, key, userAPK)
		if !point.EqualBottom() {
			// this attribute is belong to user.
			if t.m[key.Parent] == nil {
				t.m[key.Parent] = make([]struct {
					key   *Key
					point *ecdsa.EllipticCurvePoint
				}, 0)
			}
			t.m[key.Parent] = append(t.m[key.Parent], struct {
				key   *Key
				point *ecdsa.EllipticCurvePoint
			}{key: key, point: point})
		}
		key.UseToVerify = point
	}

	for _, child := range key.Children {
		_stack := stack + 1
		verify(params, userAPK, userPK, child, m, sig, t, _stack)
	}

	if key.T <= len(t.m[key]) { // if the number of children exceeds threshold.
		var x, y *bigint.BigInt = new(bigint.BigInt).SetInt64(0), new(bigint.BigInt).SetInt64(0)
		for _, childA := range t.m[key] {
			rA := new(bigint.BigInt).SetInt64(1)
			for _, childB := range t.m[key] {
				if childA.key != childB.key {
					b := new(bigint.BigInt).Neg(new(bigint.BigInt).SetInt64(int64(childB.key.Index)))
					a_b := new(bigint.BigInt).Sub(new(bigint.BigInt).SetInt64(int64(childA.key.Index)), new(bigint.BigInt).SetInt64(int64(childB.key.Index)))
					inverse_a_b, _ := ecdsa.CalcInverseElem(a_b.GetGoBigInt(), params.Curve.Params().N)
					rA.Mul(rA, new(bigint.BigInt).Mul(b, inverse_a_b))
					rA.Mod(rA, bigint.GoToBigInt(params.Curve.Params().N))
				}
			}
			xA, yA := params.Curve.ScalarMult(childA.point.X.GetGoBigInt(), childA.point.Y.GetGoBigInt(), rA.Bytes())
			_x, _y := params.Curve.Add(x.GetGoBigInt(), y.GetGoBigInt(), xA, yA)
			x, y = bigint.GoToBigInt(_x), bigint.GoToBigInt(_y)
		}
		key.UseToVerify = &ecdsa.EllipticCurvePoint{X: x, Y: y}

		if key.Parent != nil {
			if t.m[key.Parent] == nil {
				t.m[key.Parent] = make([]struct {
					key   *Key
					point *ecdsa.EllipticCurvePoint
				}, 0)
			}
			t.m[key.Parent] = append(t.m[key.Parent], struct {
				key   *Key
				point *ecdsa.EllipticCurvePoint
			}{key: key, point: &ecdsa.EllipticCurvePoint{X: x, Y: y}})
		}
	}

	if stack == 1 {
		if key.UseToVerify == nil {
			return false
		}

		var X = new(bigint.BigInt).SetInt64(0)

		for key := range userAPK {
			X.Add(X, universe[key].x)
		}
		X.Mod(X, bigint.GoToBigInt(params.Curve.Params().N))

		ux, uy := params.Curve.ScalarMult(key.UseToVerify.X.GetGoBigInt(), key.UseToVerify.Y.GetGoBigInt(), X.Bytes())
		// key.UseToVerify.X, key.UseToVerify.Y = bigint.GoToBigInt(ux), bigint.GoToBigInt(uy)

		e, err := sm2.Sm2Hash(m, userPK)
		if err != nil {
			return false
		}

		sx, sy := params.Curve.ScalarBaseMult(sig.S.Bytes())
		t := new(big.Int).Add(sig.R.GetGoBigInt(), sig.S.GetGoBigInt())
		t.Mod(t, params.Curve.Params().N)
		tx, ty := params.Curve.ScalarMult(ux, uy, t.Bytes())
		x, _ := params.Curve.Add(sx, sy, tx, ty)
		x.Add(x, e)
		x.Mod(x, params.Curve.Params().N)
		if x.Cmp(sig.R.GetGoBigInt()) == 0 {
			return true
		} else {
			return false
		}
	}
	return false
}
