package token

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/aaronland/go-http-auth/account"
	"github.com/aaronland/go-string/random"
	"time"
)

const TOKEN_STATUS_ENABLED int = 1
const TOKEN_STATUS_DISABLED int = 2
const TOKEN_STATUS_DELETED int = 3

const TOKEN_ROLE_ACCOUNT int = 0
const TOKEN_ROLE_SITE int = 1
const TOKEN_ROLE_INFRASTRUCTURE int = 2

const TOKEN_PERMISSIONS_LOGIN int = 0
const TOKEN_PERMISSIONS_READ int = 1
const TOKEN_PERMISSIONS_WRITE int = 2
const TOKEN_PERMISSIONS_DELETE int = 3

type Token struct {
	ID           int64  `json:"id"`
	AccessToken  string `json:"access_token"`
	AccountID    int64  `json:"account_id"`
	ApiKeyID     int64  `json:"api_key_id"`
	Created      int64  `json:"created"`
	Expires      int64  `json:"expires"`
	LastModified int64  `json:"lastmodified"`
	Permissions  int    `json:"permissions"`
	Role         int    `json:"role"`
	Status       int    `json:"status"`
}

func NewTokenForAccount(acct *account.Account, permissions int) (*Token, error) {

	if !IsValidPermission(permissions) {
		return nil, errors.New("Invalid permissions")
	}

	access_token, err := NewAccessToken()

	if err != nil {
		return nil, err
	}

	now := time.Now()

	t := Token{
		AccessToken:  access_token,
		AccountID:    acct.ID,
		Created:      now.Unix(),
		LastModified: now.Unix(),
		Expires:      0,
		Role:         TOKEN_ROLE_ACCOUNT,
		Status:       TOKEN_STATUS_ENABLED,
		Permissions:  permissions,
	}

	return &t, nil
}

func NewSiteTokenForAccount(acct *account.Account, permissions int) (*Token, error) {

	t, err := NewTokenForAccount(acct, permissions)

	if err != nil {
		return nil, err
	}

	t.Expires = t.Created + 3600 // make me an option...
	t.Role = TOKEN_ROLE_SITE

	return t, nil
}

func NewAccessToken() (string, error) {

	opts := random.DefaultOptions()
	opts.Chars = 100

	s, err := random.String(opts)

	if err != nil {
		return "", err
	}

	now := time.Now()
	raw := fmt.Sprintf("%s%d", s, now.Unix())

	sum := sha256.Sum256([]byte(raw))
	token := fmt.Sprintf("%x", sum)

	return token, nil
}

func IsValidPermission(permission int) bool {

	switch permission {
	case TOKEN_PERMISSIONS_LOGIN, TOKEN_PERMISSIONS_READ, TOKEN_PERMISSIONS_WRITE, TOKEN_PERMISSIONS_DELETE:
		return true
	default:
		return false
	}
}
