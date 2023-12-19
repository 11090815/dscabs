package compoments

import (
	"strings"

	"github.com/11090815/dscabs/algorithm"
)

type SmartContractFunctionPolicy struct {
	contractName string
	functionName string
	policy       string
	policyKey    *algorithm.Key
}

func NewSmartContractFunctionPolicy(params *algorithm.SystemParams, contractName string, functionName string, policy string) *SmartContractFunctionPolicy {
	scfp := &SmartContractFunctionPolicy{
		contractName: contractName,
		functionName: functionName,
		policy:       policy,
	}
	scfp.policyKey = algorithm.GenPK(params, policy)
	return scfp
}

func (scfp *SmartContractFunctionPolicy) FullName() string {
	return strings.Join(append([]string{scfp.contractName}, scfp.functionName), ".")
}

func (scfp *SmartContractFunctionPolicy) Policy() string {
	return scfp.policy
}

func (scfp *SmartContractFunctionPolicy) PolicyKey() *algorithm.Key {
	return scfp.policyKey
}
