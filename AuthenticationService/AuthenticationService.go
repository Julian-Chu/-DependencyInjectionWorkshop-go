package AuthenticationService

import (
	"bytes"
	"encoding/json"
)

type AuthenticationService struct {
	failedCounterService FailedCounter
	profileDao           ProfileDao
	sha256Adapter        Sha256Adapter
	otpService           OtpService
	slackAdapter         SlackAdapter
	logger               DefaultLogger
}

func (a AuthenticationService) Verify(accountId, password, otp string) (bool, error) {
	isLocked, err := a.failedCounterService.getLock(accountId)
	switch {
	case err != nil:
		return false, err
	case isLocked:
		return false, FailedTooManyTimesError{AccountId: accountId}
	}

	passwordFromDB, err := a.profileDao.getPasswordFromDB(accountId)
	if err != nil {
		return false, err
	}

	hashedPassword, err := a.sha256Adapter.computeHash(password)
	if err != nil {
		return false, err
	}

	currentOtp, err := a.otpService.getCurrentOtp(accountId)
	if err != nil {
		return false, err
	}

	// compare
	if passwordFromDB == hashedPassword && currentOtp == otp {
		err := a.failedCounterService.reset("")
		if err != nil {
			return false, err
		}
		return true, nil
	}

	//Failed
	err = a.failedCounterService.addFailedCount(accountId)
	if err != nil {
		return false, err
	}

	failedCount, err := a.failedCounterService.getFailedCount("")
	if err != nil {
		return false, err
	}

	a.logger.log(accountId, failedCount)

	err = a.slackAdapter.notify(accountId)
	if err != nil {
		return false, err
	}

	return false, nil
}

func EncodeAccountIdAsBody(accountId string) (*bytes.Buffer, error) {
	body := new(bytes.Buffer)
	err := json.NewEncoder(body).Encode(struct {
		accountId string `json:"accountId"`
	}{accountId: accountId})
	return body, err
}
