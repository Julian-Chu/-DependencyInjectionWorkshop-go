package tests

import (
	"github.com/Julian-Chu/DependencyInjectionWorkshop/AuthenticationService"
	"github.com/Julian-Chu/DependencyInjectionWorkshop/mocks"
	"github.com/stretchr/testify/mock"
	"os"
	"testing"
)

var DefaultAccountId string

var authService AuthenticationService.IAuthentication
var failedCounter *mocks.IFailedCounter
var profile *mocks.IProfile
var hash *mocks.IHash
var otpService *mocks.IOtpService
var notification *mocks.INotification
var logger *mocks.ILogger

func TestMain(m *testing.M) {
	failedCounter = &mocks.IFailedCounter{}
	DefaultAccountId = "joey"
	var err error
	GivenAddFailedCountReturn(DefaultAccountId, err)
	SetResetError(DefaultAccountId, err)
	profile = &mocks.IProfile{}
	hash = &mocks.IHash{}
	otpService = &mocks.IOtpService{}
	notification = &mocks.INotification{}
	SetNotifyError(DefaultAccountId, err)
	logger = &mocks.ILogger{}
	authService = AuthenticationService.NewAuthenticationService(failedCounter, profile, hash, otpService, notification, logger)
	exitCode := m.Run()
	os.Exit(exitCode)
}

func Test_isValid(t *testing.T) {
	GivenAccountIsLocked(DefaultAccountId, false, nil)
	GivenPasswordFromDB(DefaultAccountId, "my hashed password", nil)
	GivenHashedPassword("1234", "my hashed password", nil)
	GivenCurrentOtp(DefaultAccountId, "123456", nil)
	isValid, err := authService.Verify("joey", "1234", "123456")
	if err != nil {
		t.Fatalf("Get error: %s", err)
	}
	if !isValid {
		t.Error("Not valid")
	}
	failedCounter.AssertCalled(t, "Reset", DefaultAccountId)
}

func Test_isInvalid_InvalidOtp(t *testing.T) {
	GivenAccountIsLocked(DefaultAccountId, false, nil)
	GivenPasswordFromDB(DefaultAccountId, "my hashed password", nil)
	GivenHashedPassword("1234", "my hashedPassword", nil)
	GivenCurrentOtp(DefaultAccountId, "123456", nil)
	GivenFailedCount(DefaultAccountId, 2, nil)
	logger.On("Log", DefaultAccountId, 2)
	isValid, err := authService.Verify("joey", "1234", "wrong otp")
	if err != nil {
		t.Fatalf("Get error: %s", err)
	}
	if isValid {
		t.Error("Valid")
	}
	logger.AssertCalled(t, "Log", "joey", 2)
}
func SetNotifyError(accountId string, err error) *mock.Call {
	return notification.On("Notify", accountId).Return(err)
}

func GivenCurrentOtp(accountId string, otp string, err error) *mock.Call {
	return otpService.On("GetCurrentOtp", accountId).Return(otp, err)
}

func GivenHashedPassword(password string, hashedPassword string, err error) *mock.Call {
	return hash.On("Compute", password).Return(hashedPassword, err)
}

func GivenPasswordFromDB(accountId string, hashedPassword string, err error) *mock.Call {
	return profile.On("GetPasswordFromDB", accountId).Return(hashedPassword, err)
}

func SetResetError(accountId string, err error) *mock.Call {
	return failedCounter.On("Reset", accountId).Return(err)
}

func GivenFailedCount(accountId string, failedCount int, err error) *mock.Call {
	return failedCounter.On("GetFailedCount", accountId).Return(failedCount, err)
}

func GivenAddFailedCountReturn(accountId string, err error) *mock.Call {
	return failedCounter.On("AddFailedCount", accountId).Return(err)
}

func GivenAccountIsLocked(accountId string, isLocked bool, err error) *mock.Call {
	return failedCounter.On("GetLock", accountId).Return(isLocked, err)
}
