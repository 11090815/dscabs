// package main

// import (
// 	"flag"
// 	"fmt"
// 	"log"
// 	"math/big"
// 	"time"

// 	"github.com/11090815/dscabs/algorithm"
// 	"github.com/11090815/dscabs/sm2"
// )

// var sk string

// func init() {
// 	flag.StringVar(&sk, "sk", "", "user's attribute private key")
// }

// func main() {
// 	flag.Parse()

// 	curve := sm2.P256Sm2()

// 	d := big.NewInt(0)
// 	d.SetString(sk, 10)

// 	publicX, publicY := curve.ScalarBaseMult(d.Bytes())

// 	sm2PrivKey := &sm2.PrivateKey{
// 		D: new(big.Int),
// 		PublicKey: sm2.PublicKey{
// 			X: new(big.Int),
// 			Y: new(big.Int),
// 		},
// 	}
// 	sm2PrivKey.D.Set(d)
// 	sm2PrivKey.PublicKey.X.Set(publicX)
// 	sm2PrivKey.PublicKey.Y.Set(publicY)
// 	sm2PrivKey.Curve = curve

// 	msg := []byte(time.Now().Format(time.RFC3339Nano))
// 	token, err := algorithm.Sign(sm2PrivKey, msg)
// 	if err != nil {
// 		log.Fatalf("failed to generate access token: [%s]", err.Error())
// 	}

// 	fmt.Println("message:", string(msg))
// 	fmt.Println("signature:", token)
// }

package main

import (
	"fmt"
	"log"

	"github.com/11090815/dscabs/algorithm"
	"github.com/11090815/dscabs/compoments"
	"github.com/11090815/dscabs/ecdsa"
)

func main() {
	// 1. 初始化
	ecdsa.InitSeed(6757567687)
	params := algorithm.Setup(256)

	// 2. 为业务合约设置访问策略，生成策略密钥
	compoments.AddSmartContractFunctionPolicy(params, "BusinessContract", "Business1", `{语文,老师,中国籍,男,信大,[5,4]}`)

	// 3. 为用户注册属性，生成属性密钥
	ak := compoments.AddUserAttributes(params, "alice", []string{"老师", "女", "语文", "26", "中国籍", "信大"})
	fmt.Println("secret key:", ak.SM2SecretKey.D.String())

	// 4. 用户生成签名令牌，尝试访问业务合约
	// msg := []byte(time.Now().String())
	// sigToken, err := algorithm.Sign(ak.SM2SecretKey, msg)
	// assert.Nil(t, err)
	var sigToken string
	var msg string
	fmt.Scan(&msg, &sigToken)

	fmt.Println("msg:", msg)
	fmt.Println("sig:", sigToken)

	// 5. DSCABS 验证用户的签名令牌是否合法
	ok, err := compoments.GateKeeper(params, "alice", "BusinessContract", "Business1", sigToken, string(msg))
	if err != nil {
		log.Fatal("不允许访问")
		return
	}
	if ok {
		log.Println("允许访问")
	} else {
		log.Fatal("不允许访问")
	}
}
