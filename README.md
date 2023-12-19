# DSCABS

## Introduction

如果你想在联盟链中开发智能合约，并且想对智能合约施加动态的、细粒度的访问控制，那么可以选择 `DSCABS`。

`DSCABS` 实现了访问控制逻辑与智能合约的业务逻辑相互解耦的目的，它可以将智能合约的访问策略和用户的属性分别转化成策略密钥和属性密钥，用户基于属性密钥可以对特定的消息进行签名，如果用户的属性集满足智能合约的访问策略，那么用户生成的签名即可通过策略密钥的验证，因此，`DSCABS` 可将复杂多变的权限判决过程（访问控制逻辑）用签名的验证过程代替。这样一来，即便合约的访问策略或者用户的属性发生了变化，访问控制逻辑也无需跟着改变，因此，突破了更改访问策略就得重新部署智能合约的限制，实现了对智能合约的动态访问控制目的。

## Usage

### 开发智能合约

首先，我们利用 `Go` 语言编写一个智能合约，然后利用 `DSCABS` 对我们开发的智能合约进行访问控制。具体步骤如下所示：

1. 新建一个名为 `contracts` 的文件夹 :file_folder:，然后进入 `contracts` 文件夹中，新建一个 `go` 代码文件 `dog.go`，并在其中写入以下内容：
```go
package main

import (
	"encoding/json"
	"errors"

	"github.com/11090815/dscabs/chaincode"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type DogContract struct {
	contractapi.Contract
	DSCABS *chaincode.DSCABS
}

type Dog struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
	Kind string `json:"kind"`
}

func (s *DogContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	dogs := []Dog{
		{Name: "dog1", Age: 1, Kind: "dog"},
		{Name: "dog2", Age: 2, Kind: "dog"},
		{Name: "dog3", Age: 3, Kind: "dog"},
		{Name: "dog4", Age: 4, Kind: "dog"},
	}

	dogsJSON, err := json.Marshal(dogs)
	if err != nil {
		return err
	}

	err = ctx.GetStub().PutState("dogs", dogsJSON)
	if err != nil {
		return err
	}

	return nil
}

func (s *DogContract) GetDog(ctx contractapi.TransactionContextInterface, userID string, sig string, signedMessage string, name string) (*Dog, error) {
	access, err := s.DSCABS.Access(ctx, userID, "DogContract", "GetDog", sig, signedMessage)
	if !access || err != nil {
		return nil, errors.New("forbidden access")
	}

	dogsJSON, err := ctx.GetStub().GetState("dogs")
	if err != nil {
		return nil, err
	}
	dogs := []Dog{}

	err = json.Unmarshal(dogsJSON, &dogs)
	if err != nil {
		return nil, err
	}

	for _, dog := range dogs {
		if name == dog.Name {
			return &dog, nil
		}
	}

	return nil, nil
}

func (s *DogContract) AddDog(ctx contractapi.TransactionContextInterface, userID string, sig string, signedMessage string, name string, age int, kind string) error {
	access, err := s.DSCABS.Access(ctx, userID, "DogContract", "AddDog", sig, signedMessage)
	if !access || err != nil {
		return errors.New("forbidden access")
	}

	dogsJSON, err := ctx.GetStub().GetState("dogs")
	if err != nil {
		return err
	}
	dogs := []Dog{}

	err = json.Unmarshal(dogsJSON, &dogs)
	if err != nil {
		return err
	}

	extend := make([]Dog, len(dogs)+1)
	copy(extend[:], dogs[:])
	extend[len(dogs)] = Dog{
		Name: name,
		Age:  age,
		Kind: kind,
	}

	dogsJSON, err = json.Marshal(extend)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState("dogs", dogsJSON)
}
```

2. 继续在 `contracts` 目录下，新建 `main.go` 文件，并在其中写入以下内容：
```go
package main

import (
	"log"

	"github.com/11090815/dscabs/chaincode"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	dscabs := &chaincode.DSCABS{}
	dog := &DogContract{DSCABS: dscabs}
	contract, err := contractapi.NewChaincode(dog, dscabs)
	if err != nil {
		log.Panicf("Error creating Contract chaincode: %v", err)
	}

	if err := contract.Start(); err != nil {
		log.Panicf("Error starting Contract chaincode: %v", err)
	}
}

```

3. 打开终端，并切换到 `contracts` 目录下，执行 `go mod init github.com/{your_project_name}` 命令，然后在新生成的 `go.mod` 文件中追加以下内容：
```go
go 1.16

require (
	github.com/11090815/dscabs v1.0.1
	github.com/hyperledger/fabric-contract-api-go v1.1.0
)
```

4. 在终端中先后执行 `go mod tidy` 和 `go mod vendor` 命令，分别从 `GitHub` 中拉取依赖并将依赖打包进 `vendor` 文件夹中。

### 部署智能合约

首先根据 [Hyperledger Fabric 文档](https://hyperledger-fabric.readthedocs.io/en/release-2.3/) 的指示，搭建一个版本为 `2.3` 的联盟链。然后将 `contracts` 文件中的智能合约部署到区块链中。

**部署智能合约的命令**

```sh
# 在 fabric-samples/test-network 路径下执行以下命令
./network.sh deployCC -ccn contracts -ccp ../contracts -ccl go
```

注意：`network.sh` 文件是 `fabric-samples/test-network` 内的文件，从上面的命令也可以看出来，`contracts` 文件夹被放在了 `fabric-sample` 目录下。

**初始化DSCABS的命令**

```sh
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile ${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem -C mychannel -n contracts --peerAddresses localhost:7051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt --peerAddresses localhost:9051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt -c '{"function":"DSCABS:InitLedger","Args":["256","iuashdioahskdhilsahfiu"]}'
```

上面命令中，`"Args":["256","iuashdioahskdhilsahfiu"]` 里的 `"iuashdioahskdhilsahfiu"` 字符串是用来在初始化 `DSCABS` 合约时提供的一个随机种子，该字符串可以随意设置。

**初始化Dog合约的命令**

```sh
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile ${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem -C mychannel -n contracts --peerAddresses localhost:7051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt --peerAddresses localhost:9051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt -c '{"function":"DogContract:InitLedger","Args":[]}'
```

上面的初始化命令，是在区块链里注册了 `4` 只小狗：
```go
dogs := []Dog{
	{Name: "dog1", Age: 1, Kind: "dog"},
	{Name: "dog2", Age: 2, Kind: "dog"},
	{Name: "dog3", Age: 3, Kind: "dog"},
	{Name: "dog4", Age: 4, Kind: "dog"},
}
```

**为用户tom注册属性的命令**

```sh
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile ${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem -C mychannel -n contracts --peerAddresses localhost:7051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt --peerAddresses localhost:9051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt -c '{"function":"DSCABS:ExtractAK","Args":["tom","a,b,c"]}'
```
上面的命令表示用户 `tom` 拥有四个属性，分别是 `a`、`b`、`c` 和 `d`。上述令执行完后会返回一段字符串 `65654222723158089580309478147554531101290243011783304735517179386767087171939`，该段字符串即是 `tom` 的属性私钥，将来把属性私钥提交给签名预言机，可以生成 `tom` 的专属签名令牌，持有该令牌，`tom` 可以某些合约，这些合约的访问策略适用于 `tom` 的属性值。

**为Dog合约的GetDog设置访问策略的命令**

```sh
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile ${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem -C mychannel -n contracts --peerAddresses localhost:7051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt --peerAddresses localhost:9051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt -c '{"function":"DSCABS:GenPK","Args":["DogContract","GetDog","{a,b,c,d,[4,3]}"]}'
```

上述命令为 `DogContract` 智能合约中的 `GetDog` 方法注册了访问策略 `"{a,b,c,d,[4,3]}"`，该策略表示只要用户拥有 `a`、`b`、`c` 和 `d` 四个属性中任意三个或三个以上属性就可以满足该访问策略，继而可以访问 `DogContract` 智能合约中的 `GetDog` 方法。

**为Dog合约的AddDog设置访问策略的命令**

```sh
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile ${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem -C mychannel -n contracts --peerAddresses localhost:7051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt --peerAddresses localhost:9051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt -c '{"function":"DSCABS:GenPK","Args":["DogContract","AddDog","{a,b,c,d,[4,4]}"]}'
```

上述命令为 `DogContract` 智能合约中的 `AddDog` 方法注册了访问策略 `"{a,b,c,d,[4,4]}"`，该策略表示只要用户拥有 `a`、`b`、`c` 和 `d` 四个属性就可以满足该访问策略，继而可以访问 `DogContract` 智能合约中的 `AddDog` 方法。

**用户tom试图调用Dog合约的GetDog方法**

`tom` 将自己的属性私钥作为签名预言机 `sign` 的输入，然后得到被签名的消息和签名令牌：
```sh
# 在 dscabs 文件夹下有一个可执行文件：sign，该可执行文件可以利用用户的属性私钥生成签名令牌，如下命令所示：
./sign -sk 65654222723158089580309478147554531101290243011783304735517179386767087171939
```

上述命令执行完后，得到结果如下：
```sh
signed message: 2023-09-30T20:43:55+08:00
signature: 70575637034000971724969910111648117757602554926545225266685166753002292234323,114499258979695449655558653937005681558659168019570278734404181814185464382131
```

其中，`signed message` 就是被签名的消息，这里我们用调用签名预言机 `sign` 时的时间戳作为被签名的消息，`signature` 就是生成的签名令牌。

```sh
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile ${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem -C mychannel -n contracts --peerAddresses localhost:7051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt --peerAddresses localhost:9051 --tlsRootCertFiles ${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt -c '{"function":"DogContract:GetDog","Args":["tom","70575637034000971724969910111648117757602554926545225266685166753002292234323,114499258979695449655558653937005681558659168019570278734404181814185464382131","2023-09-30T20:43:55+08:00","dog4"]}'
```

上述命令中的 `"70575637034000971724969910111648117757602554926545225266685166753002292234323,114499258979695449655558653937005681558659168019570278734404181814185464382131"` 字符串是由签名预言机利用 `tom` 的属性私钥 `"65654222723158089580309478147554531101290243011783304735517179386767087171939"` 为消息 `"2023-09-30T20:43:55+08:00"` 生成的签名令牌。根据上面的描述，用户 `tom` 所拥有的属性是满足合约方法的访问策略的，所以，可以顺利完成访问请求，得到如下结果：
```sh
2023-09-30 20:44:16.465 CST [chaincodeCmd] chaincodeInvokeOrQuery -> INFO 001 Chaincode invoke successful. result: status:200 payload:"{\"name\":\"dog4\",\"age\":4,\"kind\":\"dog\"}"
```
