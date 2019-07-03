package account

import (
	"errors"
	"github.com/aaronland/go-password"
)

const ACCOUNT_STATUS_PENDING int = 0
const ACCOUNT_STATUS_ENABLED int = 1
const ACCOUNT_STATUS_DISABLED int = 2
const ACCOUNT_STATUS_DELETED int = 3

type Account struct {
	ID             int64           `json:"id"`
	Name           string          `json:"name"`
	NameURISafe    string          `json:"name_urisafe"`
	EmailAddresses []*EmailAddress `json:"email_addresses"`
	Password       *Password       `json:"password"`
	Created        int64           `json:"created"`
	LastModified   int64           `json:"lastmodified"`
	Status         int             `json:"status"`
}

type EmailAddress struct {
	Address   string `json:"address"`
	Primary   bool   `json:"primary"`
	Confirmed bool   `json:"confirmed"`
}

type Password struct {
	Model        string `json:"model"`
	Digest       string `json:"digest"`
	Salt         string `json:"salt"`
	LastModified int64  `json:"lastmodified"`
}

func (a *Account) GetPassword() (password.Password, error) {
	return nil, errors.New("Please write me")
}
