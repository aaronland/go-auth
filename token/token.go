package token

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-string/random"
	"time"
)

const TOKEN_STATUS_NONE int = 0
const TOKEN_STATUS_ENABLED int = 1
const TOKEN_STATUS_DISABLED int = 2
const TOKEN_STATUS_DELETED int = 3

const TOKEN_ROLE_NONE int = 0
const TOKEN_ROLE_ACCOUNT int = 1
const TOKEN_ROLE_SITE int = 2
const TOKEN_ROLE_INFRASTRUCTURE int = 3

const TOKEN_PERMISSIONS_NONE int = 0
const TOKEN_PERMISSIONS_LOGIN int = 1
const TOKEN_PERMISSIONS_READ int = 2
const TOKEN_PERMISSIONS_WRITE int = 3
const TOKEN_PERMISSIONS_DELETE int = 4

func IsValidPermission(permission int) bool {

	switch permission {
	case TOKEN_PERMISSIONS_LOGIN, TOKEN_PERMISSIONS_READ, TOKEN_PERMISSIONS_WRITE, TOKEN_PERMISSIONS_DELETE:
		return true
	default:
		return false
	}
}

func IsValidRole(role int) bool {

	switch role {
	case TOKEN_ROLE_ACCOUNT, TOKEN_ROLE_SITE, TOKEN_ROLE_INFRASTRUCTURE:
		return true
	default:
		return false
	}
}

func IsValidStatus(status int) bool {

	switch status {
	case TOKEN_STATUS_ENABLED, TOKEN_STATUS_DISABLED, TOKEN_STATUS_DELETED:
		return true
	default:
		return false
	}
}

type Token struct {
	ID           int64  `json:"id"`
	AccessToken  string `json:"access_token"`
	AccountID    int64  `json:"account_id"`
	ApiKeyID     int64  `json:"api_key_id"`
	Created      int64  `json:"created"`
	Deleted      int64  `json:"deleted"`
	Expires      int64  `json:"expires"`
	LastModified int64  `json:"lastmodified"`
	Permissions  int    `json:"permissions"`
	Role         int    `json:"role"`
	Status       int    `json:"status"`
}

func (t *Token) HasPermissions(permissions int) (bool, error) {

	if !IsValidPermission(permissions) {
		return false, errors.New("Invalid permissions")
	}

	if t.Permissions < permissions {
		return false, nil
	}

	return true, nil
}

func (t *Token) IsActive() bool {

	if !t.hasStatus(TOKEN_STATUS_ENABLED) {
		return false
	}

	if t.IsExpired() {
		return false
	}

	return true
}

func (t *Token) IsExpired() bool {

	if t.Expires == 0 {
		return false
	}

	now := time.Now()

	if now.Unix() < t.Expires {
		return false
	}

	return true
}

func (t *Token) IsSiteToken() bool {

	return t.hasRole(TOKEN_ROLE_SITE)
}

func (t *Token) IsInfrastructureToken() bool {

	return t.hasRole(TOKEN_ROLE_INFRASTRUCTURE)
}

func (t *Token) hasRole(role int) bool {

	if t.Role != role {
		return false
	}

	return true
}

func (t *Token) hasStatus(status int) bool {

	if t.Status != status {
		return false
	}

	return true
}

func NewToken() (*Token, error) {

	access_token, err := NewAccessToken()

	if err != nil {
		return nil, err
	}

	now := time.Now()

	t := Token{
		AccessToken:  access_token,
		Created:      now.Unix(),
		LastModified: now.Unix(),
		Expires:      0,
		Role:         TOKEN_ROLE_NONE,
		Status:       TOKEN_STATUS_NONE,
		Permissions:  TOKEN_PERMISSIONS_NONE,
	}

	return &t, nil
}

func NewTokenForAccount(acct *account.Account, permissions int) (*Token, error) {

	if !IsValidPermission(permissions) {
		return nil, errors.New("Invalid permissions")
	}

	t, err := NewToken()

	if err != nil {
		return nil, err
	}

	t.AccountID = acct.ID
	t.Permissions = permissions
	t.Role = TOKEN_ROLE_ACCOUNT
	t.Status = TOKEN_STATUS_ENABLED

	return t, nil
}

func NewSiteToken() (*Token, error) {

	t, err := NewToken()

	if err != nil {
		return nil, err
	}

	t.ApiKeyID = 0
	t.Role = TOKEN_ROLE_SITE
	t.Permissions = TOKEN_PERMISSIONS_NONE

	t.Expires = t.Created + 3600 // make me an option...
	t.Status = TOKEN_STATUS_ENABLED

	return t, nil
}

func NewSiteTokenForAccount(acct *account.Account) (*Token, error) {

	t, err := NewSiteToken()

	if err != nil {
		return nil, err
	}

	t.Permissions = TOKEN_PERMISSIONS_WRITE // delete?
	t.AccountID = acct.ID

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
