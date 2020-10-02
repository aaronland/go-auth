package session

import (
	"time"
)

type SessionRecord struct {
	SessionId string
	Expires   int64
	AccountId int64
}

func IsExpired(sess *SessionRecord) bool {

	now := time.Now()
	ts := now.Unix()

	return ts >= sess.Expires
}
