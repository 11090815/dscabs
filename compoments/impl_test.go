package compoments_test

import (
	"testing"
	"time"

	"github.com/11090815/dscabs/algorithm"
	"github.com/11090815/dscabs/compoments"
	"github.com/11090815/dscabs/ecdsa"
	"github.com/stretchr/testify/assert"
)

func TestImpl(t *testing.T) {
	// 1. 初始化
	ecdsa.InitSeed(6757567687)
	params := algorithm.Setup(256)

	// 2. 为业务合约设置访问策略，生成策略密钥
	compoments.AddSmartContractFunctionPolicy(params, "BusinessContract", "Business1", `{{教师,正高职,女,信息安全,[4,2]},{CCF-A-1,CCF-B-2,CCF-C-4,[3,1]},[2,2]}`)

	// 3. 为用户注册属性，生成属性密钥
	ak := compoments.AddUserAttributes(params, "tom", []string{"正高职", "信息安全", "CCF-A-1"})

	// 4. 用户生成签名令牌，尝试访问业务合约
	msg := []byte(time.Now().String())
	sigToken, err := algorithm.Sign(ak.SM2SecretKey, msg)
	assert.Nil(t, err)

	// 5. DSCABS 验证用户的签名令牌是否合法
	ok, err := compoments.GateKeeper(params, "tom", "BusinessContract", "Business1", sigToken, string(msg))
	if err != nil {
		t.Log("不允许访问")
		return
	}
	if ok {
		t.Log("允许访问")
	} else {
		t.Log("不允许访问")
	}
}
