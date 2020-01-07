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
	if err != nil {
		return false, err
	}
	if isLocked {
		return false, FailedTooManyTimesError{AccountId: accountId}
	}

	// Get password from DB
	db, err := sql.Open("postgres", "my connection string")
	if err != nil {
		log.Fatal(err)
	}
	row := db.QueryRow("call spGetUserPassword($1)", accountId)
	var passwordFromDB string
	row.Scan(&passwordFromDB)

	//  Hash:  simplify example without salt.
	hash := sha256.New()
	hash.Write([]byte(password))
	hashedPassword := string(hash.Sum(nil))

	// Get otp
	otpResp, err := a.client.Post("http://joey.com/api/otp", "application/json", body)
	defer otpResp.Body.Close()

	if err != nil {
		return false, err
	}
	otpBytes, err := ioutil.ReadAll(otpResp.Body)
	if err != nil {
		return false, err
	}
	currentOtp := string(otpBytes)
	if otpResp.StatusCode != http.StatusOK {
		return false, errors.New(fmt.Sprintf("web api error, accountId:%s", accountId))
	}

	// compare
	if passwordFromDB == hashedPassword && currentOtp == otp {
		r, err := a.client.Post("http://joey.com/api/otp", "application/json", body)
		defer r.Body.Close()
		if err != nil {
			return false, err
		}
		rBytes, err := ioutil.ReadAll(r.Body)
		rBody := string(rBytes)
		if err != nil {
			return false, err
		}
		if r.StatusCode != http.StatusOK {
			return false, StatusIsNotOkError{StatusCode: r.StatusCode, Message: rBody}
		}
		return true, nil
	}

	//Failed
	addFailedCountResp, err := a.client.Post("http://joey.com/api/failedCount/Add", "application/json", body)
	defer addFailedCountResp.Body.Close()

	if err != nil {
		return false, err
	}
	if addFailedCountResp.StatusCode != http.StatusOK {
		return false, errors.New(fmt.Sprintf("web api error, accountId:%s", accountId))
	}
	failedCountResp, err := a.client.Post("http://joey.com/api/otp", "application/json", body)
	defer failedCountResp.Body.Close()
	if err != nil {
		return false, err
	}
	fBytes, err := ioutil.ReadAll(failedCountResp.Body)
	fStr := string(fBytes)
	failedCount, err := strconv.Atoi(fStr)
	if err != nil {
		return false, err
	}
	if failedCountResp.StatusCode != http.StatusOK {
		return false, StatusIsNotOkError{StatusCode: failedCountResp.StatusCode, Message: fStr}
	}

	log.Printf(`accountId:{%s} failed times:{%v}`, accountId, failedCount)

	// notify
	msg := fmt.Sprintf("account:{%s} try to login failed", accountId)
	api := slack.New("YOUR_TOKEN_HERE")
	channelID, timestamp, err := api.PostMessage("CHANNEL_ID", slack.MsgOptionText(msg, false))
	if err != nil {
		return false, errors.Errorf("Failed! Send message to channel %s at %s unsuccessfully", channelID, timestamp)
	}

	return false, nil
}
