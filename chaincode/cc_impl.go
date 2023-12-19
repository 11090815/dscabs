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

	logger.Info("成功初始化【DSCABS】！！！")

	return nil
}

func (s *DSCABS) ExtractAK(ctx contractapi.TransactionContextInterface, userID string, attributes string) (string, error) {
	if userID == "" {
		return "", errors.New("用户的ID不能为空！！！")
	}

	if attributes == "" {
		return "", errors.New("提供的属性值不能为空！！！")
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

	s.logger.Debugf("用户“%s”的属性信息“{%s}”已被成功注册~~~", userID, attributes)

	s.logger.Warnf("此时用户可用于访问智能合约的【token】是“%s”~~~", ak.SecretKey.String())

	return fmt.Sprintf("[%s]", ak.SecretKey.String()), nil
}

func (s *DSCABS) GenPK(ctx contractapi.TransactionContextInterface, contractName string, functionName string, policy string) (string, error) {
	if contractName == "" {
		return "", errors.New("智能合约名不能为空！！！")
	}

	if functionName == "" {
		return "", errors.New("合约接口名不能为空！！！")
	}

	if policy == "" {
		return "", errors.New("访问策略不能为空！！！")
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

	compoments.AddSmartContractFunctionPolicy(params, contractName, functionName, policy)

	s.logger.Debugf("成功为智能合约“%s”的接口“%s”设置访问策略“%s”~~~", contractName, functionName, policy)

	return fmt.Sprintf("成功为智能合约“%s”的接口“%s”设置访问策略“%s”~~~", contractName, functionName, policy), nil
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

	s.logger.Debugf("智能合约“%s”的接口“%s”将用户“%s”的访问请求重定向给【DSCABS】，准备检查用户是否有权调用接口“%s”...", contractName, functionName, userID, functionName)

	s.logger.Infof("【DSCABS】开始验证用户“%s”权限是否满足函数“%s”的访问策略...", userID, functionName)

	if ok, err = compoments.GateKeeper(params, userID, contractName, functionName, sig, signedMessage); err != nil {
		s.logger.Errorf("在验证的过程中，发生了严重的错误“%s”, 禁止用户“%s”访问合约接口“%s”！！！", err.Error(), userID, functionName)
		return false, err
	}

	if !ok {
		s.logger.Errorf("用户“%s”访问合约接口“%s”的请求被拒绝了，因为用户权限不满足访问策略...", userID, functionName)
		return false, errors.New("没有权限")
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
		s.logger.Errorf("禁止用户“%s”重放访问请求！！！", userID)
		return false, errors.New("没有权限，因为滥用权限")
	}

	alJSON, err = json.Marshal(*al)
	if err != nil {
		return false, err
	}

	err = ctx.GetStub().PutState(Log, alJSON)
	if err != nil {
		return false, err
	}

	s.logger.Debugf("恭喜用户“%s”成功通过权限检查，具有访问智能合约“%s”的接口“%s”的权利~~~", functionName, userID, functionName)

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
		return "", fmt.Errorf("没有此用户：%s", userID)
	}

	return strconv.Itoa(log), nil
}
