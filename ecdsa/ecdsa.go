package ecdsa

import (
	"fmt"

	"github.com/11090815/dscabs/ecdsa/bigint"
)

var Bottom = &EllipticCurvePoint{}

type EllipticCurvePoint struct {
	X *bigint.BigInt `json:"x"`
	Y *bigint.BigInt `json:"y"`
}

func (point *EllipticCurvePoint) EqualBottom() bool {
	if point.X.Cmp(Bottom.X) == 0 && point.Y.Cmp(Bottom.Y) == 0 {
		return true
	}
	return false
}

func (point *EllipticCurvePoint) String() string {
	return fmt.Sprintf("x: %s\ny: %s", point.X.String(), point.Y.String())
}

type EllipticCurveSignature struct {
	S *bigint.BigInt
	R *bigint.BigInt
}
