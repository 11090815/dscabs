package sm2_test

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/11090815/dscabs/sm2"
	"github.com/stretchr/testify/assert"
)

func TestSM2GenerateKey(t *testing.T) {
	privkey, err := sm2.GenerateKey(nil)
	assert.NoError(t, err)

	msg := []byte("signed message")

	sig, err := privkey.Sign(rand.Reader, msg, nil)
	assert.Nil(t, err)

	strSig := hex.EncodeToString(sig)
	t.Log(strSig)

	sig, err = hex.DecodeString(strSig)
	assert.Nil(t, err)

	ver := privkey.PublicKey.Verify(msg, sig)
	assert.True(t, ver)
}
