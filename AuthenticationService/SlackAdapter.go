package AuthenticationService

import (
	"fmt"
	"github.com/nlopes/slack"
	"github.com/pkg/errors"
)

type SlackAdapter struct {
}

func (s SlackAdapter) notify(accountId string) error {
	// notify
	msg := fmt.Sprintf("account:{%s} try to login failed", accountId)
	api := slack.New("YOUR_TOKEN_HERE")
	channelID, timestamp, err := api.PostMessage("CHANNEL_ID", slack.MsgOptionText(msg, false))
	if err != nil {
		return errors.Errorf("Failed! Send message to channel %s at %s unsuccessfully", channelID, timestamp)
	}
	return nil
}
