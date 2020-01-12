package AuthenticationService

import (
	"github.com/Julian-Chu/DependencyInjectionWorkshop/CustomErrors"
	"github.com/Julian-Chu/DependencyInjectionWorkshop/FailedCounter"
	"github.com/Julian-Chu/DependencyInjectionWorkshop/Hash"
	"github.com/Julian-Chu/DependencyInjectionWorkshop/Logger"
	"github.com/Julian-Chu/DependencyInjectionWorkshop/Notification"
	"github.com/Julian-Chu/DependencyInjectionWorkshop/OtpService"
	"github.com/Julian-Chu/DependencyInjectionWorkshop/Profile"
)

type IAuthentication interface {
	Verify(accountId, password, otp string) (bool, error)
}

type AuthenticationService struct {
	failedCounter FailedCounter.IFailedCounter
	profile       Profile.IProfile
	hash          Hash.IHash
	otpService    OtpService.IOtpService
	notification  Notification.INotification
	logger        Logger.ILogger
}

func NewAuthenticationService(failedCounter FailedCounter.IFailedCounter, profile Profile.IProfile, hash Hash.IHash, otpService OtpService.IOtpService, notification Notification.INotification, logger Logger.ILogger) *AuthenticationService {
	return &AuthenticationService{failedCounter: failedCounter, profile: profile, hash: hash, otpService: otpService, notification: notification, logger: logger}
}

func (a AuthenticationService) Verify(accountId, password, otp string) (bool, error) {
	isLocked, err := a.failedCounter.GetLock(accountId)
	switch {
	case err != nil:
		return false, err
	case isLocked:
		return false, CustomErrors.FailedTooManyTimesError{AccountId: accountId}
	}

	passwordFromDB, err := a.profile.GetPasswordFromDB(accountId)
	if err != nil {
		return false, err
	}

	hashedPassword, err := a.hash.Compute(password)
	if err != nil {
		return false, err
	}

	currentOtp, err := a.otpService.GetCurrentOtp(accountId)
	if err != nil {
		return false, err
	}

	// compare
	if passwordFromDB == hashedPassword && currentOtp == otp {
		err := a.failedCounter.Reset(accountId)
		if err != nil {
			return false, err
		}
		return true, nil
	}

	//Failed
	err = a.failedCounter.AddFailedCount(accountId)
	if err != nil {
		return false, err
	}

	failedCount, err := a.failedCounter.GetFailedCount("")
	if err != nil {
		return false, err
	}

	a.logger.Log(accountId, failedCount)

	err = a.notification.Notify(accountId)
	if err != nil {
		return false, err
	}

	return false, nil
}
