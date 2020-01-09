package AuthenticationService

import "log"

type DefaultLogger struct {
}

func (l DefaultLogger) log(accountId string, failedCount int) {
	log.Printf(`accountId:{%s} failed times:{%v}`, accountId, failedCount)
}

type ILogger interface {
	log(accountId string, failedCount int)
}
