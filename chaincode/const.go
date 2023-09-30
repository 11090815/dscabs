package chaincode

import "fmt"

const (
	DSCABSMSK    = "DSCABS_MSK"
	AttributeKey = "AttributeKey"
	PolicyKey    = "PolicyKey"
	Log    = "AccessLog"
)

func AKTag(userID string) string {
	return fmt.Sprintf("%s:%s", userID, AttributeKey)
}

func PKTag(name string) string {
	return fmt.Sprintf("%s:%s", name, PolicyKey)
}
