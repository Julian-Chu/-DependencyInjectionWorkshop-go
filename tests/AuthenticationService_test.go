package tests

import (
	"github.com/Julian-Chu/DependencyInjectionWorkshop/AuthenticationService"
	"github.com/Julian-Chu/DependencyInjectionWorkshop/mocks"
	"github.com/stretchr/testify/mock"
	"testing"
)

const DefaultAccountId string = "joey"

type mockCollection struct {
	failedCounter *mocks.IFailedCounter
	profile       *mocks.IProfile
	hash          *mocks.IHash
	otpService    *mocks.IOtpService
	notification  *mocks.INotification
	logger        *mocks.ILogger
}

func newMockCollection() *mockCollection {
	return &mockCollection{
		failedCounter: &mocks.IFailedCounter{},
		profile:       &mocks.IProfile{},
		hash:          &mocks.IHash{},
		otpService:    &mocks.IOtpService{},
		notification:  &mocks.INotification{},
		logger:        &mocks.ILogger{},
	}
}

func Test_Setup(t *testing.T) {
	cases := []struct {
		name     string
		testFunc func(AuthenticationService.IAuthentication, *mockCollection) func(*testing.T)
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
		authService, m := NewAuthService()
		t.Run(tc.name, tc.testFunc(authService, m))
	}
}

func NewAuthService() (*AuthenticationService.AuthenticationService, *mockCollection) {
	m := newMockCollection()
	var err error
	m.givenAddFailedCountReturn(DefaultAccountId, err)
	m.setResetError(DefaultAccountId, err)
	m.setNotifyError(DefaultAccountId, err)
	m.setLog(DefaultAccountId)
	return AuthenticationService.NewAuthenticationService(m.failedCounter, m.profile, m.hash, m.otpService, m.notification, m.logger), m
}

func test_isValid(authService AuthenticationService.IAuthentication, m *mockCollection) func(t *testing.T) {
	return func(t *testing.T) {
		m.givenAccountIsLocked(DefaultAccountId, false, nil)
		m.givenPasswordFromDB(DefaultAccountId, "my hashed password", nil)
		m.givenHashedPassword("1234", "my hashed password", nil)
		m.givenCurrentOtp(DefaultAccountId, "123456", nil)
		isValid, err := authService.Verify("joey", "1234", "123456")
		if err != nil {
			t.Fatalf("Get error: %s", err)
		}
		if !isValid {
			t.Error("Not valid")
		}
	}

}

func test_isInvalid_InvalidOtp(authService AuthenticationService.IAuthentication, m *mockCollection) func(t *testing.T) {
	return func(t *testing.T) {
		m.givenAccountIsLocked(DefaultAccountId, false, nil)
		m.givenPasswordFromDB(DefaultAccountId, "my hashed password", nil)
		m.givenHashedPassword("1234", "my hashedPassword", nil)
		m.givenCurrentOtp(DefaultAccountId, "123456", nil)
		m.givenFailedCount(DefaultAccountId, 2, nil)
		isValid, err := authService.Verify("joey", "1234", "wrong otp")
		if err != nil {
			t.Fatalf("Get error: %s", err)
		}
		if isValid {
			t.Error("Valid")
		}
	}
}

func test_add_failed_count_when_invalid(authService AuthenticationService.IAuthentication, m *mockCollection) func(t *testing.T) {
	return func(t *testing.T) {
		m.givenAccountIsLocked(DefaultAccountId, false, nil)
		m.givenPasswordFromDB(DefaultAccountId, "my hashed password", nil)
		m.givenHashedPassword("1234", "my hashed Password", nil)
		m.givenCurrentOtp(DefaultAccountId, "123456", nil)
		m.givenFailedCount(DefaultAccountId, 2, nil)
		isValid, err := authService.Verify("joey", "1234", "wrong otp")
		if err != nil {
			t.Fatalf("Get error: %s", err)
		}
		if isValid {
			t.Error("Valid")
		}
		m.failedCounter.AssertCalled(t, "AddFailedCount", DefaultAccountId)
	}
}

func test_log_failed_count_when_invalid(authService AuthenticationService.IAuthentication, m *mockCollection) func(t *testing.T) {
	return func(t *testing.T) {
		m.givenAccountIsLocked(DefaultAccountId, false, nil)
		m.givenPasswordFromDB(DefaultAccountId, "my hashed password", nil)
		m.givenHashedPassword("1234", "my hashed Password", nil)
		m.givenCurrentOtp(DefaultAccountId, "123456", nil)
		m.givenAccountIsLocked(DefaultAccountId, false, nil)
		m.givenFailedCount(DefaultAccountId, 1, nil)
		m.givenAddFailedCountReturn(DefaultAccountId, nil)
		isValid, err := authService.Verify("joey", "1234", "wrong otp")

		if err != nil {
			t.Fatalf("Get error: %s", err)
		}
		if isValid {
			t.Error("Valid")
		}
		m.logger.AssertCalled(t, "Log", DefaultAccountId, 1)
	}
}

func (m mockCollection) setNotifyError(accountId string, err error) {
	m.notification.On("Notify", accountId).Return(err)
}

func (m mockCollection) givenCurrentOtp(accountId string, otp string, err error) {
	m.otpService.On("GetCurrentOtp", accountId).Return(otp, err)
}

func (m mockCollection) givenHashedPassword(password string, hashedPassword string, err error) {
	m.hash.On("Compute", password).Return(hashedPassword, err)
}

func (m mockCollection) givenPasswordFromDB(accountId string, hashedPassword string, err error) {
	m.profile.On("GetPasswordFromDB", accountId).Return(hashedPassword, err)
}

func (m mockCollection) setResetError(accountId string, err error) {
	m.failedCounter.On("Reset", accountId).Return(err)
}

func (m mockCollection) givenFailedCount(accountId string, failedCount int, err error) {
	m.failedCounter.On("GetFailedCount", accountId).Return(failedCount, err)
}

func (m mockCollection) givenAddFailedCountReturn(accountId string, err error) {
	m.failedCounter.On("AddFailedCount", accountId).Return(err)
}

func (m mockCollection) givenAccountIsLocked(accountId string, isLocked bool, err error) {
	m.failedCounter.On("GetLock", accountId).Return(isLocked, err)
}

func (m mockCollection) setLog(accoundId string) {
	m.logger.On("Log", accoundId, mock.AnythingOfType("int"))
}
