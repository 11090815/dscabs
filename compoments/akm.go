package compoments

import "github.com/11090815/dscabs/algorithm"

type UserAttributes struct {
	userID       string
	attributes   []string
	attributeKey *algorithm.AttributeKey
}

func NewUserAttributes(params *algorithm.SystemParams, userID string, attributes []string) *UserAttributes {
	ua := &UserAttributes{
		userID:     userID,
		attributes: attributes,
	}
	ua.attributeKey = algorithm.ExtractAK(params, attributes)
	return ua
}

func (ua *UserAttributes) AttributeKey() *algorithm.AttributeKey {
	return ua.attributeKey
}
