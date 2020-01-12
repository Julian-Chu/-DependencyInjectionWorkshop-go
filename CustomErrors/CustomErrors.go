package CustomErrors

import "fmt"

type FailedTooManyTimesError struct {
	AccountId string
}

func (f FailedTooManyTimesError) Error() string {
	return fmt.Sprintf("%v login failed too many time", f.AccountId)
}

type StatusIsNotOkError struct {
	StatusCode int
	Message    string
}

func (s StatusIsNotOkError) Error() string {
	return fmt.Sprintf("status code: %v,  error message: %v", s.StatusCode, s.Message)
}
