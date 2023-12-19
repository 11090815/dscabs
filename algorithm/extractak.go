package algorithm

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"

	"github.com/11090815/dscabs/ecdsa"
	"github.com/11090815/dscabs/ecdsa/bigint"
	"github.com/11090815/dscabs/sm2"
)

func ExtractAK(params *SystemParams, w []string) *AttributeKey {
	key := &AttributeKey{PublicKey: make(map[string]*ecdsa.EllipticCurvePoint)}
	var r *bigint.BigInt
	var zero = new(bigint.BigInt).SetInt64(0)

	for {
		r = ecdsa.RandNumOnCurve(params.Curve) // select a random number
		var R = &ecdsa.EllipticCurvePoint{}
		rx, ry := params.Curve.ScalarBaseMult(r.Bytes())
		R.X, R.Y = bigint.GoToBigInt(rx), bigint.GoToBigInt(ry)
		if R.X.Cmp(zero) != 0 && R.Y.Cmp(zero) != 0 {
			break
		}
	}

	var sk = new(bigint.BigInt).SetInt64(0)
	for _, attrVal := range w {
		attr := GetAttributeFromUniverse(attrVal)
		if attr == nil {
			attr = AddAttributeIntoUniverse(params, attrVal)
		}
		sk.Add(sk, attr.x)
		key.PublicKey[attr.hashVal] = &ecdsa.EllipticCurvePoint{}
		tmp := new(bigint.BigInt).Set(r)
		tmp.Mul(tmp, attr.x)
		tmp.Mod(tmp, bigint.GoToBigInt(params.Curve.Params().N))
		_x, _y := params.Curve.ScalarBaseMult(tmp.Bytes())
		key.PublicKey[attr.hashVal].X, key.PublicKey[attr.hashVal].Y = bigint.GoToBigInt(_x), bigint.GoToBigInt(_y)
	}
	sk.Mul(sk, r)
	sk.Mul(sk, params.MSK)
	sk.Mod(sk, bigint.GoToBigInt(params.Curve.Params().N))
	key.SecretKey = sk
	key.Attributes = make([]string, len(w))
	copy(key.Attributes, w)

	key.SM2SecretKey, _ = sm2.GenerateKey_(sk.GetGoBigInt(), params.Curve)

	return key
}

func GetAttributeFromUniverse(attrVal string) *attribute {
	var h = sha256.New().Sum([]byte(attrVal))
	hashVal := hex.EncodeToString(h)

	if attr, ok := universe[hashVal]; ok {
		return attr
	}
	return nil
}

func AddAttributeIntoUniverse(params *SystemParams, attrVal string) *attribute {
	var attr = &attribute{}
	var h = sha256.New().Sum([]byte(attrVal))
	attr.value, attr.hashVal = attrVal, hex.EncodeToString(h)
	x, ok := new(bigint.BigInt).SetString(attr.hashVal, 16)
	if !ok {
		panic("failed to convert string to big int")
	}
	x = x.Mul(x, params.MSK)

	attr.x = x.Mod(x, bigint.GoToBigInt(params.Curve.Params().N))
	attr.y = &ecdsa.EllipticCurvePoint{}
	attrYX, attrYY := params.Curve.ScalarBaseMult(attr.x.Bytes())
	attr.y.X, attr.y.Y = bigint.GoToBigInt(attrYX), bigint.GoToBigInt(attrYY)
	if universe == nil {
		universe = make(map[string]*attribute)
	}
	universe[attr.hashVal] = attr
	return attr
}

func (a *attribute) init(curve elliptic.Curve) {
	var h = sha256.New().Sum([]byte(a.value))
	a.hashVal = hex.EncodeToString(h)
	a.x = new(bigint.BigInt).Set(universe[a.hashVal].x)
	a.y = &ecdsa.EllipticCurvePoint{
		X: new(bigint.BigInt).Set(universe[a.hashVal].y.X),
		Y: new(bigint.BigInt).Set(universe[a.hashVal].y.Y),
	}
}
