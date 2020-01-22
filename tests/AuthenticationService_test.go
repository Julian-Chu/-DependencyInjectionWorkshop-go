package tests

import (
	"github.com/Julian-Chu/DependencyInjectionWorkshop/AuthenticationService"
	"github.com/Julian-Chu/DependencyInjectionWorkshop/mocks"
	"github.com/stretchr/testify/mock"
	"testing"
)

const DefaultAccountId string = "joey"

var authService AuthenticationService.IAuthentication
var failedCounter *mocks.IFailedCounter
var profile *mocks.IProfile
var hash *mocks.IHash
var otpService *mocks.IOtpService
var notification *mocks.INotification
var logger *mocks.ILogger

func Test_Setup(t *testing.T) {
	cases := []struct {
		name     string
		testFunc func(t2 *testing.T)
	}{
		{
			name:     "isValid",
			testFunc: test_isValid,
		},
		{
			name:     "isInValid_InvalidOtp",
			testFunc: test_isInvalid_InvalidOtp,
		},
		{
			name:     "isInValid_add_failed_count_when_invalid",
			testFunc: test_add_failed_count_when_invalid,
		},
		{
			name:     "isInValid_Log_Failed",
			testFunc: test_log_failed_count_when_invalid,
		},
	}

	for _, tc := range cases {
		initAuthService()
		t.Run(tc.name, tc.testFunc)
	}
}

func initAuthService() {
	failedCounter = &mocks.IFailedCounter{}
	var err error
	GivenAddFailedCountReturn(DefaultAccountId, err)
	SetResetError(DefaultAccountId, err)
	profile = &mocks.IProfile{}
	hash = &mocks.IHash{}
	otpService = &mocks.IOtpService{}
	notification = &mocks.INotification{}
	SetNotifyError(DefaultAccountId, err)
	logger = &mocks.ILogger{}
	logger.On("Log", DefaultAccountId, mock.AnythingOfType("int"))
	authService = AuthenticationService.NewAuthenticationService(failedCounter, profile, hash, otpService, notification, logger)
}

func test_isValid(t *testing.T) {
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
}

func test_isInvalid_InvalidOtp(t *testing.T) {
	GivenAccountIsLocked(DefaultAccountId, false, nil)
	GivenPasswordFromDB(DefaultAccountId, "my hashed password", nil)
	GivenHashedPassword("1234", "my hashedPassword", nil)
	GivenCurrentOtp(DefaultAccountId, "123456", nil)
	GivenFailedCount(DefaultAccountId, 2, nil)
	isValid, err := authService.Verify("joey", "1234", "wrong otp")
	if err != nil {
		t.Fatalf("Get error: %s", err)
	}
	if isValid {
		t.Error("Valid")
	}
}

func test_add_failed_count_when_invalid(t *testing.T) {
	GivenAccountIsLocked(DefaultAccountId, false, nil)
	GivenPasswordFromDB(DefaultAccountId, "my hashed password", nil)
	GivenHashedPassword("1234", "my hashed Password", nil)
	GivenCurrentOtp(DefaultAccountId, "123456", nil)
	GivenFailedCount(DefaultAccountId, 2, nil)
	isValid, err := authService.Verify("joey", "1234", "wrong otp")
	if err != nil {
		t.Fatalf("Get error: %s", err)
	}
	if isValid {
		t.Error("Valid")
	}
	failedCounter.AssertCalled(t, "AddFailedCount", DefaultAccountId)
}

func test_log_failed_count_when_invalid(t *testing.T) {
	GivenAccountIsLocked(DefaultAccountId, false, nil)
	GivenPasswordFromDB(DefaultAccountId, "my hashed password", nil)
	GivenHashedPassword("1234", "my hashed Password", nil)
	GivenCurrentOtp(DefaultAccountId, "123456", nil)
	//failedCounter := &mocks.IFailedCounter{}
	failedCounter.On("GetLock", DefaultAccountId).Return(false, nil)
	failedCounter.On("GetFailedCount", DefaultAccountId).Return(1, nil)
	failedCounter.On("AddFailedCount", DefaultAccountId).Return(nil)
	failedCounter.On("Reset", DefaultAccountId).Return(nil)

	//authService := AuthenticationService.NewAuthenticationService(failedCounter, profile, hash, otpService, notification, logger)
	isValid, err := authService.Verify("joey", "1234", "wrong otp")

	if err != nil {
		t.Fatalf("Get error: %s", err)
	}
	if isValid {
		t.Error("Valid")
	}
	logger.AssertCalled(t, "Log", DefaultAccountId, 1)
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

func GivenFailedCount(accountId string, failedCount int, err error) {
	failedCounter.On("GetFailedCount", accountId).Return(failedCount, err)
}

func GivenAddFailedCountReturn(accountId string, err error) *mock.Call {
	return failedCounter.On("AddFailedCount", accountId).Return(err)
}

func GivenAccountIsLocked(accountId string, isLocked bool, err error) *mock.Call {
	return failedCounter.On("GetLock", accountId).Return(isLocked, err)
}
