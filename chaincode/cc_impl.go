package chaincode

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/11090815/dscabs/algorithm"
	"github.com/11090815/dscabs/compoments"
	"github.com/11090815/dscabs/ecdsa"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type DSCABS struct {
	contractapi.Contract
}

type AccessLog struct {
	// signature => 0/1
	Log map[string]int `json:"log"`
}

func (s *DSCABS) InitLedger(ctx contractapi.TransactionContextInterface, sl string, seed string) error {

	securityLevel, _ := strconv.Atoi(sl)

	bz := sha256.Sum256([]byte(seed))

	var sseed int = 0
	for _, b := range bz {
		sseed += int(b)
	}

	ecdsa.InitSeed(sseed)

	params := algorithm.Setup(securityLevel)

	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return err
	}

	err = ctx.GetStub().PutState(DSCABSMSK, paramsJSON)
	if err != nil {
		return err
	}

	al := AccessLog{Log: make(map[string]int)}
	alJSON, err := json.Marshal(al)
	if err != nil {
		return err
	}

	err = ctx.GetStub().PutState(Log, alJSON)
	if err != nil {
		return err
	}

	return nil
}

func (s *DSCABS) ExtractAK(ctx contractapi.TransactionContextInterface, userID string, attributes string) (string, error) {
	if userID == "" {
		return "", errors.New("user id must be different from \"\"")
	}

	if attributes == "" {
		return "", errors.New("attributes must be different from \"\"")
	}

	params := &algorithm.SystemParams{Curve: new(elliptic.CurveParams)}

	paramsJSON, err := ctx.GetStub().GetState(DSCABSMSK)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(paramsJSON, &params)
	if err != nil {
		return "", err
	}

	var ak *algorithm.AttributeKey

	if strings.Contains(attributes, ",") {
		attributesSlice := strings.Split(attributes, ",")
		trim := make([]string, 0)
		for _, attr := range attributesSlice {
			trim = append(trim, strings.Trim(attr, "\""))
		}
		ak = compoments.AddUserAttributes(params, userID, trim)
	} else {
		ak = compoments.AddUserAttributes(params, userID, []string{strings.Trim(attributes, "\"")})
	}

	akJSON, err := json.Marshal(ak)
	if err != nil {
		return "", err
	}

	err = ctx.GetStub().PutState(AKTag(userID), akJSON)
	if err != nil {
		return "", err
	}

	return ak.SecretKey.String(), nil
}

func (s *DSCABS) GenPK(ctx contractapi.TransactionContextInterface, contractName string, functionName string, policy string) error {
	if contractName == "" {
		return errors.New("contract name must be different from \"\"")
	}

	if functionName == "" {
		return errors.New("function name must be different from \"\"")
	}

	if policy == "" {
		return errors.New("policy must be different from \"\"")
	}

	params := &algorithm.SystemParams{Curve: new(elliptic.CurveParams)}

	paramsJSON, err := ctx.GetStub().GetState(DSCABSMSK)
	if err != nil {
		return err
	}

	err = json.Unmarshal(paramsJSON, &params)
	if err != nil {
		return err
	}

	compoments.AddSmartContractFunctionPolicy(params, contractName, functionName, policy)

	return nil
}

func (s *DSCABS) Access(ctx contractapi.TransactionContextInterface, userID string, contractName string, functionName string, sig string, signedMessage string) (bool, error) {
	var ok bool

	params := &algorithm.SystemParams{Curve: new(elliptic.CurveParams)}

	paramsJSON, err := ctx.GetStub().GetState(DSCABSMSK)
	if err != nil {
		return false, err
	}

	if err := json.Unmarshal(paramsJSON, &params); err != nil {
		return false, err
	}

	if ok, err = compoments.GateKeeper(params, userID, contractName, functionName, sig, signedMessage); err != nil {
		return false, err
	}

	if !ok {
		return false, errors.New("invalid signature token")
	}

	al := &AccessLog{}

	alJSON, err := ctx.GetStub().GetState(Log)
	if err != nil {
		return false, err
	}

	err = json.Unmarshal(alJSON, al)
	if err != nil {
		return false, err
	}

	key := strings.Join([]string{contractName, functionName, sig, signedMessage}, ".")

	if al.Log[key] == 0 {
		al.Log[key] = 1
	} else {
		return false, errors.New("prohibit replay of signature token")
	}

	alJSON, err = json.Marshal(*al)
	if err != nil {
		return false, err
	}

	err = ctx.GetStub().PutState(Log, alJSON)
	if err != nil {
		return false, err
	}

	return ok, nil
}

func (s *DSCABS) GetAccessLog(ctx contractapi.TransactionContextInterface, userID string) (string, error) {
	al := &AccessLog{}

	alJSON, err := ctx.GetStub().GetState(Log)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(alJSON, al)
	if err != nil {
		return "", err
	}

	log, ok := al.Log[userID]
	if !ok {
		return "", fmt.Errorf("there is no such user: [%s]", userID)
	}

	return strconv.Itoa(log), nil
}
