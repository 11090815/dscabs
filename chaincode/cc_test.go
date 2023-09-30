package chaincode

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/11090815/dscabs/algorithm"
	"github.com/11090815/dscabs/ecdsa/bigint"
	"github.com/stretchr/testify/assert"
)

func TestProcess(t *testing.T) {
	params := algorithm.Setup(256)

	ak := algorithm.ExtractAK(params, []string{"a", "b", "c", "d"})
	fmt.Println(ak.SecretKey)

	pk := algorithm.GenPK(params, "{a,b,c,d,[4,4]}")

	sig := algorithm.Sign(params, []byte("hello"), ak.SecretKey)

	ok := algorithm.Verify(params, ak.PublicKey, pk, []byte("hello"), sig)

	assert.Equal(t, ok, true)
}

func TestSign(t *testing.T) {
	params := algorithm.Setup(256)
	ori := "12642144789571432543536238136988414452360763536599579669146462956379963041029"
	sk, _ := new(bigint.BigInt).SetString(ori, 10)

	now := time.Now().Format(time.RFC3339)
	fmt.Println("signed message:", now)

	sig := algorithm.Sign(params, []byte(fmt.Sprintf("tom:DogContract:AddDog:%s", now)), sk)

	fmt.Println("signature:", fmt.Sprintf("%s,%s", sig.S, sig.R))

}

func TestHex(t *testing.T) {
	str := "1234"

	bz, err := hex.DecodeString(str)
	assert.NoError(t, err)
	t.Log(bz)
}