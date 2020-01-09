package AuthenticationService

import (
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

type OtpService struct {
	client *http.Client
}

func (o OtpService) getCurrentOtp(accountId string) (string, error) {
	body, err := EncodeAccountIdAsBody(accountId)
	if err != nil {
		return "", err
	}
	// Get otp
	otpResp, err := o.client.Post("http://joey.com/api/otp", "application/json", body)
	defer otpResp.Body.Close()
	if err != nil {
		return "", err
	}
	otpBytes, err := ioutil.ReadAll(otpResp.Body)
	if err != nil {
		return "", err
	}
	currentOtp := string(otpBytes)
	if otpResp.StatusCode != http.StatusOK {
		return "", errors.New(fmt.Sprintf("web api error, accountId:%s", accountId))
	}
	return currentOtp, nil
}

type IOtpService interface {
	getCurrentOtp(accountId string) (string, error)
}
