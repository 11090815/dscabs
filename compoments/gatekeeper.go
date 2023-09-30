package compoments

import (
	"errors"
	"fmt"
	"strings"

	"github.com/11090815/dscabs/algorithm"
	"github.com/11090815/dscabs/ecdsa"
	"github.com/11090815/dscabs/ecdsa/bigint"
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
		return false, errors.New("signature must be different from nil")
	}

	if !strings.Contains(sig, ",") {
		return false, fmt.Errorf("invalid signature: [%s]", sig)
	}

	var pk = GetSmartContractFunctionPolicyKey(contractName, functionName)
	var ak = GetUserAttributeKey(userID)

	if pk == nil {
		return false, fmt.Errorf("function [%s] is not registered", strings.Join([]string{contractName, functionName}, "."))
	}

	if ak == nil {
		return false, fmt.Errorf("user [%s] is not registered", userID)
	}

	sp := strings.Split(sig, ",")
	S, _ := new(bigint.BigInt).SetString(sp[0], 10)
	R, _ := new(bigint.BigInt).SetString(sp[1], 10)
	signature := &ecdsa.EllipticCurveSignature{S: S, R: R}

	if ok := algorithm.Verify(params, ak.PublicKey, pk, []byte(signedMessage), signature); ok {
		return true, nil
	} else {
		return false, nil
	}
}
