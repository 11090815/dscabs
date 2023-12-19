package algorithm

import (
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"github.com/11090815/dscabs/ecdsa"
	"github.com/11090815/dscabs/ecdsa/bigint"
)

func GenPK(params *SystemParams, policy string) *Key {
	n := &AccessTreeNode{Policy: policy, Children: make(map[string]*AccessTreeNode)}
	ParsePolicy(params, policy, n)
	if n == nil {
		return nil
	}
	n.Init(params, nil)
	k := &Key{}
	n.PolicyKey(params, k, nil)
	return k
}

func NewPolynomial(a0 *bigint.BigInt, order int, curve elliptic.Curve) *Polynomial {
	polynomial := &Polynomial{Coefficients: make(map[int]*bigint.BigInt), Curve: curve}
	polynomial.Coefficients[0] = a0

	for o := 1; o <= order; o++ {
		polynomial.Coefficients[o] = ecdsa.RandNumOnCurve(curve)
	}

	return polynomial
}

func (poly *Polynomial) Compute(x *bigint.BigInt) *bigint.BigInt {
	res := new(bigint.BigInt).SetInt64(0)
	for order, coefficient := range poly.Coefficients {
		exp := new(bigint.BigInt).Exp(x, new(bigint.BigInt).SetInt64(int64(order)), bigint.GoToBigInt(poly.Curve.Params().N))
		mul := new(bigint.BigInt).Mul(coefficient, exp)
		res.Add(res, mul)
	}
	return res.Mod(res, bigint.GoToBigInt(poly.Curve.Params().N))
}

func (atn *AccessTreeNode) Init(params *SystemParams, parent *AccessTreeNode) {
	atn.parent = parent

	if atn.parent == nil {
		atn.polynomial = NewPolynomial(params.MSK, atn.T-1, params.Curve)
	} else {
		index := atn.parent.polynomial.Compute(new(bigint.BigInt).SetInt64(int64(atn.Index)))
		atn.polynomial = NewPolynomial(index, atn.T-1, params.Curve)
	}

	// leaf node of the access tree.
	if atn.Children == nil {
		atn.attribute.init(params.Curve)
		return
	}
	for _, child := range atn.Children {
		child.Init(params, atn)
	}
}

func (atn *AccessTreeNode) PolicyKey(params *SystemParams, key *Key, parent *Key) {
	key.Parent = parent
	key.Index, key.N, key.T = atn.Index, atn.N, atn.T
	if atn.Children == nil {
		key.HashVal = atn.attribute.hashVal
		inverseX, _ := ecdsa.CalcInverseElem(atn.attribute.x.GetGoBigInt(), params.Curve.Params().N)
		key.Du = new(bigint.BigInt).Mul(atn.polynomial.Compute(new(bigint.BigInt).SetInt64(0)), inverseX)
	}
	if key.Children == nil && atn.Children != nil {
		key.Children = make(map[string]*Key)
	}
	for s, child := range atn.Children {
		key.Children[s] = &Key{}
		child.PolicyKey(params, key.Children[s], key)
	}
}

// for print
func (n *AccessTreeNode) String() string {
	bz, err := json.Marshal(n)
	if err != nil {
		panic(err)
	}
	return string(bz)
}

func (k *Key) Size() int {
	size := 0
	if k.Du != nil {
		size += len(k.Du.Bytes())
		size += int(unsafe.Sizeof(k.N))
		size += int(unsafe.Sizeof(k.T))
	}

	if len(k.Children) != 0 {
		for _, key := range k.Children {
			size += key.Size()
		}
	}
	return size
}

func ParsePolicy(params *SystemParams, policy string, n *AccessTreeNode) {
	if policy == "{}" {
		n = nil
		return
	}
	if err := VerifyPolicy(policy); err != nil {
		panic(err)
	}

	if !strings.Contains(policy, "{") {
		return
	}

	lastRightMiddleBracketsIndex := strings.LastIndex(policy, "]")
	lastLeftMiddleBracketsIndex := strings.LastIndex(policy, "[")
	nt := policy[lastLeftMiddleBracketsIndex : lastRightMiddleBracketsIndex+1]
	nt = strings.TrimPrefix(nt, "[")
	nt = strings.TrimSuffix(nt, "]")
	if strings.Contains(nt, ",") {
		split := strings.Split(nt, ",")
		if len(split) != 2 {
			panic(fmt.Errorf("invalid threshold value: [%s]", nt))
		}
		nn, err := strconv.Atoi(split[0])
		if err != nil {
			panic(fmt.Errorf("invalid threshold value n: [%s]", err))
		}
		t, err := strconv.Atoi(split[1])
		if err != nil {
			panic(fmt.Errorf("invalid threshold value t: [%s]", err))
		}
		if nn < t {
			panic(fmt.Errorf("invalid threshold value t > n: [%d > %d]", t, nn))
		}
		n.N = nn
		n.T = t
	} else {
		panic(fmt.Errorf("invalid threshold value: [%s]", nt))
	}
	policy = strings.TrimPrefix(policy, "{")
	policy = strings.TrimSuffix(policy, "}")
	lastLeftMiddleBracketsIndex = strings.LastIndex(policy, "[")
	policy = policy[:lastLeftMiddleBracketsIndex-1]

	startLeftCurlyBracketsIndex := 0
	leftCurlyBracketsNum := 0
	rightCurlyBracketsNum := 0
	subPolicies := make([]string, 0)
	cursor := 0
	for i := 0; i < len(policy); i++ {
		if policy[i] == '{' {
			if leftCurlyBracketsNum == 0 {
				startLeftCurlyBracketsIndex = i
				if startLeftCurlyBracketsIndex > 0 {
					if policy[cursor:startLeftCurlyBracketsIndex] != "," {
						sub := policy[cursor:startLeftCurlyBracketsIndex]
						sub = strings.Trim(sub, ",")
						subPolicies = append(subPolicies, sub)
					}
				}
			}
			leftCurlyBracketsNum++
		}
		if policy[i] == '}' {
			rightCurlyBracketsNum++
			if rightCurlyBracketsNum == leftCurlyBracketsNum {
				subPolicies = append(subPolicies, policy[startLeftCurlyBracketsIndex:i+1])
				leftCurlyBracketsNum = 0
				rightCurlyBracketsNum = 0
				startLeftCurlyBracketsIndex = 0
				cursor = i + 1
			}
		}
	}

	if cursor < len(policy) {
		sub := policy[cursor:]
		sub = strings.Trim(sub, ",")
		subPolicies = append(subPolicies, sub)
	}

	for _, sub := range subPolicies {
		if strings.Contains(sub, ",") && !strings.Contains(sub, "{") {
			s := strings.Split(sub, ",")
			for _, attr := range s {
				AddAttributeIntoUniverse(params, attr)
				n.Children[attr] = &AccessTreeNode{Policy: fmt.Sprintf("{%s,[1,1]}", attr), N: 1, T: 1, Children: nil, attribute: &attribute{value: attr}, Index: len(n.Children) + 1}
			}
		} else if !strings.Contains(sub, ",") && !strings.Contains(sub, "{") {
			AddAttributeIntoUniverse(params, sub)
			n.Children[sub] = &AccessTreeNode{Policy: fmt.Sprintf("{%s,[1,1]}", sub), N: 1, T: 1, Children: nil, attribute: &attribute{value: sub}, Index: len(n.Children) + 1}
		} else {
			n.Children[sub] = &AccessTreeNode{Policy: sub, Children: make(map[string]*AccessTreeNode), Index: len(n.Children) + 1}
		}
	}

	for _, sub := range subPolicies {
		ParsePolicy(params, sub, n.Children[sub])
	}
}

func VerifyPolicy(policy string) error {
	match := map[byte]int{
		'{': 0,
		'}': 0,
		'[': 0,
		']': 0,
	}

	for index := 0; index < len(policy); index++ {
		if policy[index] == '{' {
			match['{']++
		} else if policy[index] == '}' {
			match['}']++
		} else if policy[index] == '[' {
			match['[']++
		} else if policy[index] == ']' {
			match[']']++
		}
	}

	if match['{'] != match['}'] {
		return fmt.Errorf("the quantities of '{' and '}' in policy are not equal: [%s]", policy)
	}
	if match['['] != match[']'] {
		return fmt.Errorf("the quantities of '[' and ']' in policy are not equal: [%s]", policy)
	}

	return nil
}
