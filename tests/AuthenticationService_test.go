package tests

import (
	"github.com/Julian-Chu/DependencyInjectionWorkshop/AuthenticationService"
	"github.com/Julian-Chu/DependencyInjectionWorkshop/mocks"
	"os"
	"testing"
)

var authService AuthenticationService.IAuthentication

func TestMain(m *testing.M) {
	failedCounter := &mocks.IFailedCounter{}
	failedCounter.On("GetLock", "joey").Return(false, nil)
	failedCounter.On("AddFailedCount", "joey").Return(nil)
	failedCounter.On("GetFailedCount", "joey").Return(0, nil)
	failedCounter.On("Reset", "joey").Return(nil)
	profile := &mocks.IProfile{}
	profile.On("GetPasswordFromDB", "joey").Return("my hashed password", nil)
	hash := &mocks.IHash{}
	hash.On("Compute", "1234").Return("my hashed password", nil)
	otpService := &mocks.IOtpService{}
	otpService.On("GetCurrentOtp", "joey").Return("123456", nil)
	notification := &mocks.INotification{}
	notification.On("Notify", "joey").Return(nil)
	logger := &mocks.ILogger{}
	authService = AuthenticationService.NewAuthenticationService(failedCounter, profile, hash, otpService, notification, logger)
	exitCode := m.Run()
	os.Exit(exitCode)
}
func Test_isValid(t *testing.T) {
	isValid, err := authService.Verify("joey", "1234", "123456")
	if err != nil {
		t.Fatalf("Get error: %s", err)
	}
	if !isValid {
		t.Error("Not valid")
	}
}
