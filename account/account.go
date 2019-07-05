package account

import (
	"errors"
	"github.com/aaronland/go-password"
	"github.com/aaronland/go-ucd-username"
	"net/mail"
	"time"
)

const ACCOUNT_STATUS_PENDING int = 0
const ACCOUNT_STATUS_ENABLED int = 1
const ACCOUNT_STATUS_DISABLED int = 2
const ACCOUNT_STATUS_DELETED int = 3

// this will become an interface when the dust settles

type Account struct {
	ID           int64     `json:"id"`
	Address      *Address  `json:"address"`
	Password     *Password `json:"password"`
	Username     *Username `json:"username"`
	Created      int64     `json:"created"`
	LastModified int64     `json:"lastmodified"`
	Status       int       `json:"status"`
}

type Username struct {
	Raw  string `json:"raw"`
	Safe string `json:"safe"`
}

type Address struct {
	Model     string `json:"model"`
	URI       string `json:"uri"`
	Confirmed bool   `json:"confirmed"`
}

type Password struct {
	Model        string `json:"model"`
	Digest       string `json:"digest"`
	Salt         string `json:"salt"`
	LastModified int64  `json:"lastmodified"`
}

func NewAccount(email_raw string, password_raw string, username_raw string) (*Account, error) {

	emails, err := mail.ParseAddressList(email_raw)

	if err != nil {
		return nil, err
	}

	if len(emails) != 1 {
		return nil, errors.New("Invalid email address string")
	}

	ucd, err := username.NewUCDUsername()

	if err != nil {
		return nil, err
	}

	ucd.Debug = false
	ucd.AllowSpaces = false
	ucd.AllowPunctuation = false

	username_safe, err := ucd.Translate(username_raw)

	if err != nil {
		return nil, err
	}

	bcrypt_pswd, err := password.NewBCryptPassword(password_raw)

	if err != nil {
		return nil, err
	}

	now := time.Now()

	uname := &Username{
		Raw:  username_raw,
		Safe: username_safe,
	}

	addr := &Address{
		Model:     "email",
		URI:       emails[0].Address,
		Confirmed: false,
	}

	pswd := &Password{
		Model:        "bcrypt",
		Digest:       bcrypt_pswd.Digest(),
		Salt:         bcrypt_pswd.Salt(),
		LastModified: now.Unix(),
	}

	acct := &Account{
		Address:      addr,
		Password:     pswd,
		Username:     uname,
		Created:      now.Unix(),
		LastModified: now.Unix(),
		Status:       ACCOUNT_STATUS_PENDING,
	}

	return acct, nil
}

func (acct *Account) IsEnabled() bool {

	if acct.Status == ACCOUNT_STATUS_ENABLED {
		return true
	}

	return false
}

func (acct *Account) GetPassword() (password.Password, error) {
	return password.NewBCryptPasswordFromDigest(acct.Password.Digest, acct.Password.Salt)
}
