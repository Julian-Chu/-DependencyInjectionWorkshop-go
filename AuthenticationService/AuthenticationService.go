package AuthenticationService

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/nlopes/slack"
	"github.com/pkg/errors"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
)

type FailedTooManyTimesError struct {
	AccountId string
}

func (f FailedTooManyTimesError) Error() string {
	return fmt.Sprintf("%v login failed too many time", f.AccountId)
}

type AuthenticationService struct {
	client http.Client
}
type StatusIsNotOkError struct {
	StatusCode int
	Message    string
}

func (s StatusIsNotOkError) Error() string {
	return fmt.Sprintf("status code: %v,  error message: %v", s.StatusCode, s.Message)
}

func (a AuthenticationService) Verify(accountId, password, otp string) (bool, error) {
	body := new(bytes.Buffer)
	err := json.NewEncoder(body).Encode(struct{ accountId string }{accountId: accountId})
	if err != nil {
		return false, err
	}
	isLocked, err := a.getLock(err, body)
	switch {
	case err != nil:
		return false, err
	case isLocked:
		return false, FailedTooManyTimesError{AccountId: accountId}
	}

	passwordFromDB, err := a.getPasswordFromDB(accountId)
	if err != nil {
		return false, err
	}

	hashedPassword, err := a.computeHash(password)
	if err != nil {
		return false, err
	}

	currentOtp, err := a.getCurrentOtp(err, body, accountId)
	if err != nil {
		return false, err
	}

	// compare
	if passwordFromDB == hashedPassword && currentOtp == otp {
		err := a.Reset(body)
		if err != nil {
			return false, err
		}
		return true, nil
	}

	//Failed
	err = a.addFailedCount(body, accountId)
	if err != nil {
		return false, err
	}

	failedCount, err := a.getFailedCount(err, body)
	if err != nil {
		return false, err
	}

	// log
	a.log(accountId, failedCount)

	// notify
	err = a.notify(accountId)
	if err != nil {
		return false, err
	}

	return false, nil
}

func (a AuthenticationService) log(accountId string, failedCount int) {
	log.Printf(`accountId:{%s} failed times:{%v}`, accountId, failedCount)
}

func (a AuthenticationService) notify(accountId string) error {
	msg := fmt.Sprintf("account:{%s} try to login failed", accountId)
	api := slack.New("YOUR_TOKEN_HERE")
	channelID, timestamp, err := api.PostMessage("CHANNEL_ID", slack.MsgOptionText(msg, false))
	if err != nil {
		return errors.Errorf("Failed! Send message to channel %s at %s unsuccessfully", channelID, timestamp)
	}
	return nil
}

func (a AuthenticationService) addFailedCount(body *bytes.Buffer, accountId string) error {
	addFailedCountResp, err := a.client.Post("http://joey.com/api/failedCount/Add", "application/json", body)
	defer addFailedCountResp.Body.Close()
	if err != nil {
		return err
	}
	if addFailedCountResp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("web api error, accountId:%s", accountId))
	}
	return nil
}

func (a AuthenticationService) getFailedCount(err error, body *bytes.Buffer) (int, error) {
	failedCountResp, err := a.client.Post("http://joey.com/failedCount/GetFailedCount", "application/json", body)
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

func (a AuthenticationService) Reset(body *bytes.Buffer) error {
	resetResp, err := a.client.Post("http://joey.com/api/failedCounter/Reset", "application/json", body)
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

func (a AuthenticationService) getCurrentOtp(err error, body *bytes.Buffer, accountId string) (string, error) {
	// Get otp
	otpResp, err := a.client.Post("http://joey.com/api/otp", "application/json", body)
	defer otpResp.Body.Close()
	if err != nil {
		return "", err
	}
	otpBytes, err := ioutil.ReadAll(otpResp.Body)
	if err != nil {
		return "", err
	}
	currentOtp := string(otpBytes)
	if otpResp.StatusCode != http.StatusOK {
		return "", errors.New(fmt.Sprintf("web api error, accountId:%s", accountId))
	}
	return currentOtp, nil
}

func (a AuthenticationService) computeHash(password string) (string, error) {
	hash := sha256.New()
	_, err := hash.Write([]byte(password))
	if err != nil {
		return "", err
	}
	hashedPassword := string(hash.Sum(nil))
	return hashedPassword, nil
}

func (a AuthenticationService) getPasswordFromDB(accountId string) (string, error) {
	// Get password from DB
	db, err := sql.Open("postgres", "my connection string")
	if err != nil {
		return "", err
	}
	row := db.QueryRow("call spGetUserPassword($1)", accountId)
	var passwordFromDB string
	err = row.Scan(&passwordFromDB)
	if err != nil {
		return "", err
	}
	return passwordFromDB, nil
}

func (a AuthenticationService) getLock(err error, body *bytes.Buffer) (bool, error) {
	// Get lock
	resp, err := a.client.Post("http://joey.com/api/failedCounter/IsLocked", "application/json", body)
	defer resp.Body.Close()
	if err != nil {
		return false, err
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	respBody := string(bodyBytes)
	if err != nil {
		return false, err
	}
	if resp.StatusCode != http.StatusOK {
		return false, StatusIsNotOkError{StatusCode: resp.StatusCode, Message: respBody}
	}
	isLocked, err := strconv.ParseBool(respBody)
	return isLocked, nil
}
