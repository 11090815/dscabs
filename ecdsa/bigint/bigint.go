package bigint

import (
	"errors"
	"math/big"
)

type BigInt struct {
	Content []byte `json:"bytes"`
	S       int    `json:"sign"`
}

func NewBigInt(bz []byte, sign int) (*BigInt, error) {
	if len(bz) == 0 && sign != 0 {
		return nil, errors.New("invalid bytes for big int, because sign is 0")
	}

	cp := make([]byte, len(bz))
	copy(cp, bz)

	return &BigInt{Content: cp, S: sign}, nil
}

func GoToBigInt(i *big.Int) *BigInt {
	res, _ := NewBigInt(i.Bytes(), i.Sign())
	return res
}

func (bi *BigInt) GetGoBigInt() *big.Int {
	res := new(big.Int).SetBytes(bi.Content)

	if bi.S < 0 {
		res.Neg(res)
	}

	return res
}

func (bi *BigInt) Mul(x, y *BigInt) *BigInt {
	xx := x.GetGoBigInt()
	yy := y.GetGoBigInt()

	xx.Mul(xx, yy)

	res, _ := NewBigInt(xx.Bytes(), xx.Sign())

	bi.Set(res)
	return bi
}

func (bi *BigInt) Div(x, y *BigInt) *BigInt {
	xx := x.GetGoBigInt()
	yy := y.GetGoBigInt()

	xx.Div(xx, yy)

	res, _ := NewBigInt(xx.Bytes(), xx.Sign())

	bi.Set(res)
	return bi
}

func (bi *BigInt) Mod(x, y *BigInt) *BigInt {
	xx := x.GetGoBigInt()
	yy := y.GetGoBigInt()

	xx.Mod(xx, yy)

	res, _ := NewBigInt(xx.Bytes(), xx.Sign())

	bi.Set(res)
	return bi
}

func (bi *BigInt) Add(x, y *BigInt) *BigInt {
	xx := x.GetGoBigInt()
	yy := y.GetGoBigInt()

	xx.Add(xx, yy)

	res, _ := NewBigInt(xx.Bytes(), xx.Sign())

	bi.Set(res)
	return bi
}

func (bi *BigInt) Sub(x, y *BigInt) *BigInt {
	xx := x.GetGoBigInt()
	yy := y.GetGoBigInt()

	xx.Sub(xx, yy)

	res, _ := NewBigInt(xx.Bytes(), xx.Sign())

	bi.Set(res)
	return bi
}

func (bi *BigInt) Exp(x, y, m *BigInt) *BigInt {
	xx := x.GetGoBigInt()
	yy := y.GetGoBigInt()
	mm := m.GetGoBigInt()

	xx.Exp(xx, yy, mm)

	res, _ := NewBigInt(xx.Bytes(), xx.Sign())

	bi.Set(res)
	return bi
}

func (bi *BigInt) SetInt64(i int64) *BigInt {
	n := new(big.Int).SetInt64(i)

	res, _ := NewBigInt(n.Bytes(), n.Sign())

	bi.Set(res)
	return bi
}

func (bi *BigInt) SetString(str string, base int) (*BigInt, bool) {
	n, ok := new(big.Int).SetString(str, base)
	if !ok {
		return nil, false
	}

	res, _ := NewBigInt(n.Bytes(), n.Sign())

	bi.Set(res)
	return bi, true
}

func (bi *BigInt) SetBytes(bz []byte) *BigInt {
	n := new(big.Int).SetBytes(bz)

	res, _ := NewBigInt(n.Bytes(), n.Sign())

	bi.Set(res)
	return bi
}

func (bi *BigInt) Set(o *BigInt) *BigInt {
	bi.Content = make([]byte, len(o.Bytes()))
	copy(bi.Content, o.Bytes())
	bi.S = o.Sign()

	return bi
}

func (bi *BigInt) Cmp(other *BigInt) int {
	me := bi.GetGoBigInt()
	o := other.GetGoBigInt()

	return me.Cmp(o)
}

func (bi *BigInt) Neg(x *BigInt) *BigInt {
	xx := x.GetGoBigInt()
	xx.Neg(xx)
	
	res, _ := NewBigInt(xx.Bytes(), xx.Sign())
	bi.Set(res)

	return bi
}

func (bi *BigInt) String() string {
	me := bi.GetGoBigInt()

	return me.String()
}

func (bi *BigInt) Bytes() []byte {
	bz := make([]byte, len(bi.Content))
	copy(bz, bi.Content)
	return bz
}

func (bi *BigInt) Sign() int {
	return bi.S
}
