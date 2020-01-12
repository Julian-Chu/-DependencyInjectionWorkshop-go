package Logger

import "log"

type DefaultLogger struct {
}

func (l DefaultLogger) Log(accountId string, failedCount int) {
	log.Printf(`accountId:{%s} failed times:{%v}`, accountId, failedCount)
}

type ILogger interface {
	Log(accountId string, failedCount int)
}
