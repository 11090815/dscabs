package algorithm

import (
	"github.com/11090815/dscabs/ecdsa"
	"github.com/11090815/dscabs/ecdsa/bigint"
	"github.com/11090815/dscabs/sm2"
)

func Setup(securityLevel int) *SystemParams {
	params := &SystemParams{}
	switch securityLevel {
	case 256:
		params.Curve = sm2.P256Sm2()
	default:
		params.Curve = sm2.P256Sm2()
	}

	params.MSK = ecdsa.RandNumOnCurve(params.Curve)

	ecdsa.Bottom.X = new(bigint.BigInt).SetInt64(-1)
	ecdsa.Bottom.Y = new(bigint.BigInt).SetInt64(-1)

	return params
}
