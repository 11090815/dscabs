package compoments

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/11090815/dscabs/algorithm"
	"github.com/11090815/dscabs/ecdsa"
	"github.com/11090815/dscabs/ecdsa/bigint"
	"github.com/11090815/dscabs/sm2"
)

func GateKeeper(params *algorithm.SystemParams, userID string, contractName, functionName string, sig string, signedMessage string) (bool, error) {
	if userID == "" {
		return false, errors.New("user id must be different from \"\"")
	}

	if contractName == "" {
		return false, errors.New("contract name must be different from \"\"")
	}

	if functionName == "" {
		return false, errors.New("function name must be different from \"\"")
	}

	if sig == "" {
		return false, errors.New("signature must be different from \"\"")
	}

	var pk = GetSmartContractFunctionPolicyKey(contractName, functionName)
	var ak = GetUserAttributeKey(userID)

	if pk == nil {
		return false, fmt.Errorf("function [%s] is not registered", strings.Join([]string{contractName, functionName}, "."))
	}

	if ak == nil {
		return false, fmt.Errorf("user [%s] is not registered", userID)
	}

	bytesSig, err := hex.DecodeString(sig)
	if err != nil {
		return false, fmt.Errorf("invalid signture format")
	}
	r, s, err := sm2.GetRSFromSig(bytesSig)
	if err != nil {
		return false, fmt.Errorf("invalid signture format")
	}
	signature := &ecdsa.EllipticCurveSignature{S: bigint.GoToBigInt(s), R: bigint.GoToBigInt(r)}

	if ok := algorithm.Verify(params, ak.PublicKey, &ak.SM2SecretKey.PublicKey, pk, []byte(signedMessage), signature); ok {
		return true, nil
	} else {
		return false, nil
	}
}
