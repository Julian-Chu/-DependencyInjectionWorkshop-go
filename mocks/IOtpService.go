// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// IOtpService is an autogenerated mock type for the IOtpService type
type IOtpService struct {
	mock.Mock
}

// GetCurrentOtp provides a mock function with given fields: accountId
func (_m *IOtpService) GetCurrentOtp(accountId string) (string, error) {
	ret := _m.Called(accountId)

	var r0 string
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(accountId)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(accountId)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
