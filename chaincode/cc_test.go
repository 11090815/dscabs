package chaincode

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/11090815/dscabs/algorithm"
	"github.com/11090815/dscabs/ecdsa"
	"github.com/11090815/dscabs/ecdsa/bigint"
	"github.com/11090815/dscabs/sm2"
	"github.com/stretchr/testify/assert"
	"github.com/hyperledger/fabric/common/flogging"
)

func TestSM2Sign(t *testing.T) {
	params := algorithm.Setup(256)
	sk := algorithm.ExtractAK(params, []string{"教师", "正高职", "信息安全", "CCF-A-1"})
	msg := []byte(time.Now().Format(time.RFC3339Nano))

	sig, err := algorithm.Sign(sk.SM2SecretKey, msg)
	assert.NoError(t, err)

	bytesSig, err := hex.DecodeString(sig)
	assert.Nil(t, err)
	r, s, err := sm2.GetRSFromSig(bytesSig)
	assert.Nil(t, err)

	pk := algorithm.GenPK(params, `{{教师,正高职,女,信息安全,[4,2]},{CCF-A-1,CCF-B-2,CCF-C-4,[3,1]},[2,2]}`)

	res := algorithm.Verify(params, sk.PublicKey, &sk.SM2SecretKey.PublicKey, pk, msg, &ecdsa.EllipticCurveSignature{S: bigint.GoToBigInt(s), R: bigint.GoToBigInt(r)})

	fmt.Println(res)
}

func TestLogging(t *testing.T) {
	flogging.Init(flogging.Config{
		Format: "%{color}%{time:2006-01-02 15:04:05.000 MST} [%{module}] -> %{level:.5s} %{id:03x}%{color:reset} %{message}",
		LogSpec: "debug",
	})
	logger := flogging.MustGetLogger("smart_contract")
	logger.Debug("hello")
}
