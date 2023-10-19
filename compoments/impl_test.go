package compoments_test

import (
	"fmt"
	"testing"

	"github.com/11090815/dscabs/algorithm"
	"github.com/11090815/dscabs/compoments"
	"github.com/11090815/dscabs/ecdsa"
)

func TestImpl(t *testing.T) {
	// 1. 初始化
	ecdsa.InitSeed(6757567687)
	params := algorithm.Setup(256)

	// 2. 为业务合约设置访问策略，生成策略密钥
	compoments.AddSmartContractFunctionPolicy(params, "BusinessContract", "Business1", `{语文,老师,中国籍,男,[4,3]}`)

	// 3. 为用户注册属性，生成属性密钥
	ak := compoments.AddUserAttributes(params, "alice", []string{"老师", "女", "语文", "26", "中国籍"})
	fmt.Println("secret key:", ak.SM2SecretKey.D.String())

	// 4. 用户生成签名令牌，尝试访问业务合约
	// msg := []byte(time.Now().String())
	// sigToken, err := algorithm.Sign(ak.SM2SecretKey, msg)
	// assert.Nil(t, err)
	var sigToken string
	fmt.Scanf("%s", sigToken)
	var msg string
	fmt.Scanf("%s", msg)

	fmt.Println("msg:", msg)
	fmt.Println("sig:", sigToken)

	// 5. DSCABS 验证用户的签名令牌是否合法
	ok, err := compoments.GateKeeper(params, "alice", "BusinessContract", "Business1", sigToken, string(msg))
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
