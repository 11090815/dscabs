package ecdsa

import (
	"crypto/elliptic"
	"math/big"
	"math/rand"

	"github.com/11090815/dscabs/ecdsa/bigint"
)

// RandNumOnCurve. Get a random number from an elliptic curve
func RandNumOnCurve(curve elliptic.Curve) *bigint.BigInt {
	k := make([]byte, curve.Params().BitSize)
	rand.Seed(int64(Seed()))

	for i := 0; i < len(k); i++ {
		k[i] = byte(rand.Intn(255))
	}

	num := new(big.Int).SetBytes(k)
	num.Mod(num, curve.Params().N)

	res, err := bigint.NewBigInt(num.Bytes(), num.Sign())
	if err != nil {
		panic(err)
	}

	return res
}

func CalcInverseElem(a, b *big.Int) (*bigint.BigInt, error) {
	res := calcInverseElem(a, b)

	return bigint.NewBigInt(res.Bytes(), res.Sign())
}

// calcInverseElem. ax + by = 1，find the inverse of a mod b
func calcInverseElem(a, b *big.Int) *big.Int {
	var exgcd func(a, b, x, y *big.Int) *big.Int
	exgcd = func(a, b, x, y *big.Int) *big.Int {
		var d *big.Int
		if b.Cmp(new(big.Int).SetInt64(0)) == 0 {
			x.SetInt64(1)
			y.SetInt64(0)
			return new(big.Int).Set(a)
		}
		m := new(big.Int).Mod(a, b)
		d = exgcd(b, m, y, x)
		di := new(big.Int).Div(a, b)
		di.Mul(di, x)
		y.Sub(y, di)
		return new(big.Int).Set(d)
	}

	var d, x, y *big.Int
	x = new(big.Int)
	y = new(big.Int)
	d = exgcd(a, b, x, y)
	if d.Cmp(new(big.Int).SetInt64(1)) == 0 {
		xmod := new(big.Int).Mod(x, b)
		if xmod.Cmp(new(big.Int).SetInt64(0)) == -1 || xmod.Cmp(new(big.Int).SetInt64(0)) == 0 {
			return xmod.Add(xmod, b)
		} else {
			return xmod
		}
	} else {
		return new(big.Int).SetInt64(-1)
	}
}
