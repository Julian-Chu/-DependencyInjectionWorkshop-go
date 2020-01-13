package tests

import (
	"github.com/Julian-Chu/DependencyInjectionWorkshop/AuthenticationService"
	"github.com/Julian-Chu/DependencyInjectionWorkshop/mocks"
	"github.com/stretchr/testify/mock"
	"os"
	"testing"
)

var authService AuthenticationService.IAuthentication

var failedCounter *mocks.IFailedCounter
var profile *mocks.IProfile
var hash *mocks.IHash

func TestMain(m *testing.M) {
	failedCounter = &mocks.IFailedCounter{}
	name := "joey"
	isLocked := false
	var err error
	GivenAccountIsLocked(name, isLocked, err)
	GivenAddFailedCountReturn(name, err)
	failedCount := 0
	GivenFailedCount(name, failedCount, err)
	GivenResetReturn(name, err)
	profile = &mocks.IProfile{}
	hashedPassword := "my hashed password"
	GivenPasswordFromDB(name, hashedPassword, err)
	hash = &mocks.IHash{}
	password := "1234"
	GivenHashedPassword(password, hashedPassword, err)
	otpService := &mocks.IOtpService{}
	otp := "123456"
	otpService.On("GetCurrentOtp", name).Return(otp, err)
	notification := &mocks.INotification{}
	notification.On("Notify", name).Return(err)
	logger := &mocks.ILogger{}
	authService = AuthenticationService.NewAuthenticationService(failedCounter, profile, hash, otpService, notification, logger)
	exitCode := m.Run()
	os.Exit(exitCode)
}

func GivenHashedPassword(password string, hashedPassword string, err error) *mock.Call {
	return hash.On("Compute", password).Return(hashedPassword, err)
}

func GivenPasswordFromDB(name string, hashedPassword string, err error) *mock.Call {
	return profile.On("GetPasswordFromDB", name).Return(hashedPassword, err)
}

func GivenResetReturn(name string, err error) *mock.Call {
	return failedCounter.On("Reset", name).Return(err)
}

func GivenFailedCount(name string, failedCount int, err error) *mock.Call {
	return failedCounter.On("GetFailedCount", name).Return(failedCount, err)
}

func GivenAddFailedCountReturn(name string, err error) *mock.Call {
	return failedCounter.On("AddFailedCount", name).Return(err)
}

func GivenAccountIsLocked(name string, isLocked bool, err error) *mock.Call {
	return failedCounter.On("GetLock", name).Return(isLocked, err)
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
