package AuthenticationService

import (
	"bytes"
	"encoding/json"
)

type IAuthentication interface {
	Verify(accountId, password, otp string) (bool, error)
}

type AuthenticationService struct {
	failedCounter IFailedCounter
	profile       IProfile
	hash          IHash
	otpService    IOtpService
	notification  INotification
	logger        ILogger
}

func NewAuthenticationService(failedCounter IFailedCounter, profile IProfile, hash IHash, otpService IOtpService, notification INotification, logger ILogger) *AuthenticationService {
	return &AuthenticationService{failedCounter: failedCounter, profile: profile, hash: hash, otpService: otpService, notification: notification, logger: logger}
}

func (a AuthenticationService) Verify(accountId, password, otp string) (bool, error) {
	isLocked, err := a.failedCounter.getLock(accountId)
	switch {
	case err != nil:
		return false, err
	case isLocked:
		return false, FailedTooManyTimesError{AccountId: accountId}
	}

	passwordFromDB, err := a.profile.getPasswordFromDB(accountId)
	if err != nil {
		return false, err
	}

	hashedPassword, err := a.hash.compute(password)
	if err != nil {
		return false, err
	}

	currentOtp, err := a.otpService.getCurrentOtp(accountId)
	if err != nil {
		return false, err
	}

	// compare
	if passwordFromDB == hashedPassword && currentOtp == otp {
		err := a.failedCounter.reset("")
		if err != nil {
			return false, err
		}
		return true, nil
	}

	//Failed
	err = a.failedCounter.addFailedCount(accountId)
	if err != nil {
		return false, err
	}

	failedCount, err := a.failedCounter.getFailedCount("")
	if err != nil {
		return false, err
	}

	a.logger.log(accountId, failedCount)

	err = a.notification.notify(accountId)
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
