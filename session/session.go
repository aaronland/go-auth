package session

import (
	"github.com/aaronland/go-string/random"
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

func NewSessionID() (string, error) {

	random_opts := random.DefaultOptions()
	random_opts.Length = 64
	random_opts.Chars = 64
	random_opts.Base32 = true

	return random.String(random_opts)
}
