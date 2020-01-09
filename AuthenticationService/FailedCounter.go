package AuthenticationService

import (
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"strconv"
)

type FailedCounter struct {
	client *http.Client
}

func (s FailedCounter) getLock(accountId string) (bool, error) {
	body, err := EncodeAccountIdAsBody(accountId)
	if err != nil {
		return false, err
	}
	// Get lock
	resp, err := s.client.Post("http://joey.com/api/failedCounter/IsLocked", "application/json", body)
	defer resp.Body.Close()
	if err != nil {
		return false, err
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	respBody := string(bodyBytes)
	if resp.StatusCode != http.StatusOK {
		return false, StatusIsNotOkError{StatusCode: resp.StatusCode, Message: respBody}
	}
	isLocked, err := strconv.ParseBool(respBody)
	return isLocked, nil
}

func (s FailedCounter) addFailedCount(accountId string) error {
	body, err := EncodeAccountIdAsBody(accountId)
	if err != nil {
		return err
	}

	addFailedCountResp, err := s.client.Post("http://joey.com/api/failedCount/Add", "application/json", body)
	defer addFailedCountResp.Body.Close()
	if err != nil {
		return err
	}
	if addFailedCountResp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("web api error, accountId:%s", accountId))
	}
	return nil
}

func (s FailedCounter) getFailedCount(accountId string) (int, error) {
	body, err := EncodeAccountIdAsBody(accountId)
	if err != nil {
		return 0, err
	}
	failedCountResp, err := s.client.Post("http://joey.com/failedCount/GetFailedCount", "application/json", body)
	defer failedCountResp.Body.Close()
	if err != nil {
		return 0, err
	}
	fBytes, err := ioutil.ReadAll(failedCountResp.Body)
	failedCountStr := string(fBytes)
	failedCount, err := strconv.Atoi(failedCountStr)
	if err != nil {
		return 0, err
	}
	if failedCountResp.StatusCode != http.StatusOK {
		return 0, StatusIsNotOkError{StatusCode: failedCountResp.StatusCode, Message: failedCountStr}
	}
	return failedCount, nil
}

func (s FailedCounter) reset(accountId string) error {
	body, err := EncodeAccountIdAsBody(accountId)
	if err != nil {
		return err
	}
	resetResp, err := s.client.Post("http://joey.com/api/failedCounter/Reset", "application/json", body)
	defer resetResp.Body.Close()
	if err != nil {
		return err
	}
	rBytes, err := ioutil.ReadAll(resetResp.Body)
	rBody := string(rBytes)
	if err != nil {
		return err
	}
	if resetResp.StatusCode != http.StatusOK {
		return StatusIsNotOkError{StatusCode: resetResp.StatusCode, Message: rBody}
	}
	return nil
}
