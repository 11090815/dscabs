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
	"github.com/hyperledger/fabric/common/flogging"
)

type DSCABS struct {
	contractapi.Contract
	logger *flogging.FabricLogger
}

type AccessLog struct {
	// signature => 0/1
	Log map[string]int `json:"log"`
}

func (s *DSCABS) InitLedger(ctx contractapi.TransactionContextInterface, sl string, seed string) error {
	fmt.Printf("********************************************************************************\n")
	fmt.Printf("***************************** Initialisation Phase *****************************\n")
	flogging.Init(flogging.Config{
		Format:  "%{color}%{time:2006-01-02 15:04:05.000 MST} [%{module}] -> %{level:.5s} %{id:03x}%{color:reset} %{message}",
		LogSpec: "debug",
	})
	logger := flogging.MustGetLogger("smart_contract")

	s.logger = flogging.MustGetLogger("dscabs")
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

	logger.Info("Successfully initialised DSCABS using the [Setup] algorithm.")

	return nil
}

func (s *DSCABS) ExtractAK(ctx contractapi.TransactionContextInterface, userID string, attributes string) (string, error) {
	fmt.Println()
	fmt.Printf("********************************************************************************\n")
	fmt.Printf("*********************** Generate Attribute Keys for User ***********************\n")
	if userID == "" {
		return "", errors.New("user id must be different from \"\"")
	}

	if attributes == "" {
		return "", errors.New("attributes must be different from \"\"")
	}

	s.logger.Infof("Prepare to generate an attribute key for the user using the [GenAK] algorithm.")

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

	s.logger.Debug("Successfully generated an attribute key for the user.")

	akJSON, err := json.Marshal(ak)
	if err != nil {
		return "", err
	}

	err = ctx.GetStub().PutState(AKTag(userID), akJSON)
	if err != nil {
		return "", err
	}

	s.logger.Debug("After consensus, the user attribute public key is stored in the KM.")

	s.logger.Warnf("The user's attribute private key is [%s].", ak.SecretKey.String())

	return fmt.Sprintf("Successfully generated the attribute key for the user, where the attribute private key is [%s].", ak.SecretKey.String()), nil
}

func (s *DSCABS) GenPK(ctx contractapi.TransactionContextInterface, contractName string, functionName string, policy string) (string, error) {
	fmt.Println()
	fmt.Printf("********************************************************************************\n")
	fmt.Printf("************** Configure Access Policies for Contract Interfaces ***************\n")
	if contractName == "" {
		return "", errors.New("contract name must be different from \"\"")
	}

	if functionName == "" {
		return "", errors.New("function name must be different from \"\"")
	}

	if policy == "" {
		return "", errors.New("policy must be different from \"\"")
	}

	s.logger.Infof("Prepare to configure an access policy [%s] for interface [%s] of smart contract [%s] using the GenPK algorithm.", policy, functionName, contractName)

	params := &algorithm.SystemParams{Curve: new(elliptic.CurveParams)}

	paramsJSON, err := ctx.GetStub().GetState(DSCABSMSK)
	if err != nil {
		return "", err
	}

	err = json.Unmarshal(paramsJSON, &params)
	if err != nil {
		return "", err
	}

	compoments.AddSmartContractFunctionPolicy(params, contractName, functionName, policy)

	s.logger.Debugf("Successfully configure an access policy for interface [%s] of smart contract [%s]. After consensus, the generated policy key is stored in KM.", functionName, contractName)

	return fmt.Sprintf("Successfully set policy for method [%s] of smart contract [%s]. The policy has been converted into a policy key and stored at the KM.", functionName, contractName), nil
}

func (s *DSCABS) Access(ctx contractapi.TransactionContextInterface, userID string, contractName string, functionName string, sig string, signedMessage string) (bool, error) {
	fmt.Println()
	fmt.Printf("********************************************************************************\n")
	fmt.Printf("*********************** Authenticate User Access Rights ************************\n")
	var ok bool

	params := &algorithm.SystemParams{Curve: new(elliptic.CurveParams)}

	paramsJSON, err := ctx.GetStub().GetState(DSCABSMSK)
	if err != nil {
		return false, err
	}

	if err := json.Unmarshal(paramsJSON, &params); err != nil {
		return false, err
	}

	s.logger.Debugf("The interface [%s] of the smart contract [%s] redirects the access request of the user [%s] to the DSCABS, ready to check the user's access rights.", functionName, contractName, userID)

	s.logger.Debugf("Search for the policy key of interface [%s] of smart contract [%s] and the attribute public key of user [%s].", functionName, contractName, userID)

	s.logger.Debugf("The KM passes the policy key of interface [%s] of smart contract [%s] and the attribute public key of user [%s] to the DSCABS.", functionName, contractName, userID)

	s.logger.Info("DSCABS begins to use the [VerifyT] algorithm to verify that user %s's signature token satisfies the access policy of contract interface [%s].", userID, functionName)

	if ok, err = compoments.GateKeeper(params, userID, contractName, functionName, sig, signedMessage); err != nil {
		s.logger.Errorf("A serious error [%s] has occurred in the authentication process, prohibiting user [%s] from accessing contract interface [%s].", err.Error(), userID, functionName)
		return false, err
	}

	if !ok {
		s.logger.Error("The user's request for access to interface [%s] of smart contract [%s] is denied because the signature does not comply with the verification rules of the policy key.", functionName, contractName)
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
		s.logger.Errorf("Prohibit users from accessing the contract interface with duplicate signature tokens [%s]. (from Bloom filter checking results)", functionName)
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

	s.logger.Debugf("The user's signed token conforms to the access policy of contract interface [%s] and therefore allows user [%s] access to contract interface [%s].", functionName, userID, functionName)

	return ok, nil
}

func (*DSCABS) GetAccessLog(ctx contractapi.TransactionContextInterface, userID string) (string, error) {
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
