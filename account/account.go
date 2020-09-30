package account

import (
	"context"
	"errors"
	"fmt"
	"github.com/aaronland/go-password"
	"github.com/aaronland/go-ucd-username"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
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
	MFA          *MFA      `json:"mfa"`
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

type MFA struct {
	Model    string `json:"model"`
	URL      string `json:"uri"`
	LastAuth int64  `json:"lastauth"`
}

func (mfa *MFA) GetSecret() (string, error) {

	key, err := otp.NewKeyFromURL(mfa.URL)

	if err != nil {
		return "", err
	}

	return key.Secret(), nil
}

func (mfa *MFA) GetCode() (string, error) {

	key, err := otp.NewKeyFromURL(mfa.URL)

	if err != nil {
		return "", err
	}

	now := time.Now()

	return totp.GenerateCode(key.Secret(), now)
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

	pswd, err := newPassword(password_raw)

	if err != nil {
		return nil, err
	}

	totp_issuer := "FIX ME"
	totp_account := emails[0].Address

	totp_opts := totp.GenerateOpts{
		Issuer:      totp_issuer,
		AccountName: totp_account,
	}

	totp_key, err := totp.Generate(totp_opts)

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

	mfa := &MFA{
		Model: "totp",
		URL:   totp_key.URL(),
	}

	acct := &Account{
		// ID: -1,
		Address:      addr,
		Password:     pswd,
		Username:     uname,
		MFA:          mfa,
		Created:      now.Unix(),
		LastModified: now.Unix(),
		Status:       ACCOUNT_STATUS_PENDING,
	}

	return acct, nil
}

func (acct *Account) IsActive() bool {

	if acct.Status == ACCOUNT_STATUS_DELETED {
		return false
	}

	if acct.Status == ACCOUNT_STATUS_DISABLED {
		return false
	}

	return true
}

func (acct *Account) UpdatePassword(password_raw string) (*Account, error) {

	pswd, err := newPassword(password_raw)

	if err != nil {
		return acct, err
	}

	acct.Password = pswd
	return acct, nil
}

func newPassword(password_raw string) (*Password, error) {

	ctx := context.Background()
	bcrypt_pswd, err := password.NewBCryptPassword(ctx, password_raw)

	if err != nil {
		return nil, err
	}

	now := time.Now()

	pswd := &Password{
		Model:        "bcrypt",
		Digest:       bcrypt_pswd.Digest(),
		Salt:         bcrypt_pswd.Salt(),
		LastModified: now.Unix(),
	}

	return pswd, nil
}

func (acct *Account) GetPassword() (password.Password, error) {

	ctx := context.Background()
	uri := fmt.Sprintf("bcrypt://?digest=%s&salt=%s", acct.Password.Digest, acct.Password.Salt)

	return password.NewPassword(ctx, uri)
}

func (acct *Account) GetMFASecret() (string, error) {

	mfa := acct.MFA

	if mfa == nil {
		return "", errors.New("MFA is not configured for account")
	}

	return mfa.GetSecret()
}
