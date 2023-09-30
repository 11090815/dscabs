package algorithm

import (
	"crypto/sha256"

	"github.com/11090815/dscabs/ecdsa"
	"github.com/11090815/dscabs/ecdsa/bigint"
)

func Verify(params *SystemParams, userPK map[string]*ecdsa.EllipticCurvePoint, key *Key, m []byte, sig *ecdsa.EllipticCurveSignature) bool {
	if key == nil {
		return false
	}
	t := &track{m: make(map[*Key][]struct {
		key   *Key
		point *ecdsa.EllipticCurvePoint
	})}
	return verify(params, userPK, key, m, sig, t, 1)
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

func verify(params *SystemParams, userPK map[string]*ecdsa.EllipticCurvePoint, key *Key, m []byte, sig *ecdsa.EllipticCurveSignature, t *track, stack int) bool {
	if key.Children == nil || len(key.Children) == 0 {
		point := VerifyNode(params, key, userPK)
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
		verify(params, userPK, child, m, sig, t, _stack)
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

		for key := range userPK {
			X.Add(X, universe[key].x)
		}
		X.Mod(X, bigint.GoToBigInt(params.Curve.Params().N))

		ux, uy := params.Curve.ScalarMult(key.UseToVerify.X.GetGoBigInt(), key.UseToVerify.Y.GetGoBigInt(), X.Bytes())
		key.UseToVerify.X, key.UseToVerify.Y = bigint.GoToBigInt(ux), bigint.GoToBigInt(uy)

		e := new(bigint.BigInt).SetBytes(sha256.New().Sum(m))
		inverseS, _ := ecdsa.CalcInverseElem(sig.S.GetGoBigInt(), params.Curve.Params().N)
		var u1 = new(bigint.BigInt).Mul(inverseS, e)
		var u2 = new(bigint.BigInt).Mul(inverseS, sig.R)
		var p = &ecdsa.EllipticCurvePoint{}
		px, py := params.Curve.ScalarBaseMult(u1.Bytes())
		p.X, p.Y = bigint.GoToBigInt(px), bigint.GoToBigInt(py)
		tmpX, tmpY := params.Curve.ScalarMult(key.UseToVerify.X.GetGoBigInt(), key.UseToVerify.Y.GetGoBigInt(), u2.Bytes())
		x, _ := params.Curve.Add(p.X.GetGoBigInt(), p.Y.GetGoBigInt(), tmpX, tmpY)
		if bigint.GoToBigInt(x).Cmp(sig.R) == 0 {
			return true
		} else {
			return false
		}
	}
	return false
}
