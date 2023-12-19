package compoments

import (
	"strings"
	"sync"

	"github.com/11090815/dscabs/algorithm"
)

type KeyLibrary struct {
	mu                         sync.RWMutex
	contractFunctionPolicyKeys map[string]*SmartContractFunctionPolicy
	userAttributesKeys         map[string]*UserAttributes
}

var KL *KeyLibrary

func AddSmartContractFunctionPolicy(params *algorithm.SystemParams, contractName, functionName, policy string) {
	if KL == nil {
		KL = NewKeyLibrary()
	}
	KL.AddSmartContractFunctionPolicy(params, contractName, functionName, policy)
}

func AddUserAttributes(params *algorithm.SystemParams, userID string, attributes []string) *algorithm.AttributeKey {
	if KL == nil {
		KL = NewKeyLibrary()
	}
	return KL.AddUserAttributes(params, userID, attributes)
}

func GetSmartContractFunctionPolicyKey(contractName, functionName string) *algorithm.Key {
	if KL == nil {
		return nil
	}
	return KL.GetSmartContractFunctionPolicyKey(contractName, functionName)
}

func GetUserAttributeKey(userID string) *algorithm.AttributeKey {
	if KL == nil {
		return nil
	}
	return KL.GetUserAttributeKey(userID)
}

func NewKeyLibrary() *KeyLibrary {
	return &KeyLibrary{
		contractFunctionPolicyKeys: make(map[string]*SmartContractFunctionPolicy),
		userAttributesKeys:         make(map[string]*UserAttributes),
	}
}

func (kl *KeyLibrary) AddSmartContractFunctionPolicy(params *algorithm.SystemParams, contractName, functionName, policy string) {
	scfp := NewSmartContractFunctionPolicy(params, contractName, functionName, policy)
	kl.mu.Lock()
	kl.contractFunctionPolicyKeys[scfp.FullName()] = scfp
	kl.mu.Unlock()
}

func (kl *KeyLibrary) DeleteSmartContractFunctionPolicy(contractName, functionName string) {
	fullName := strings.Join(append([]string{contractName}, functionName), ".")
	kl.mu.Lock()
	delete(kl.contractFunctionPolicyKeys, fullName)
	kl.mu.Unlock()
}

func (kl *KeyLibrary) AddUserAttributes(params *algorithm.SystemParams, userID string, attributes []string) *algorithm.AttributeKey {
	ua := NewUserAttributes(params, userID, attributes)
	kl.mu.Lock()
	kl.userAttributesKeys[userID] = ua
	kl.mu.Unlock()
	return ua.attributeKey
}

func (kl *KeyLibrary) DeleteUserAttributes(userID string) {
	kl.mu.Lock()
	delete(kl.userAttributesKeys, userID)
	kl.mu.Unlock()
}

func (kl *KeyLibrary) GetSmartContractFunctionPolicyKey(contractName, functionName string) *algorithm.Key {
	fullName := strings.Join(append([]string{contractName}, functionName), ".")
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	if exists, ok := kl.contractFunctionPolicyKeys[fullName]; ok {
		return exists.policyKey
	} else {
		return nil
	}
}

func (kl *KeyLibrary) GetUserAttributeKey(userID string) *algorithm.AttributeKey {
	kl.mu.RLock()
	defer kl.mu.RUnlock()
	if exists, ok := kl.userAttributesKeys[userID]; ok {
		return exists.attributeKey
	} else {
		return nil
	}
}
