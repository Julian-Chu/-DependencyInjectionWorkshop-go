package helper

import (
	"bytes"
	"encoding/json"
)

func EncodeAccountIdAsBody(accountId string) (*bytes.Buffer, error) {
	body := new(bytes.Buffer)
	err := json.NewEncoder(body).Encode(struct {
		accountId string `json:"accountId"`
	}{accountId: accountId})
	return body, err
}
