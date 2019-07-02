package membership

import (
	"encoding/json"
	"errors"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/account/username"
	"github.com/aaronland/go-password"
	"github.com/aaronland/go-uid"
	"github.com/tidwall/gjson"
	_ "github.com/tidwall/sjson"
	"net/mail"
)

type IndividualMembership struct {
	account.Membership `json:"omitempty"`
	id                 string `json:"id"`
	details            []byte `json:"details"`
}

type IndividualMembershipDetails struct {
	id       uid.UID           `json:"id"`
	username account.Username  `json:"username"`
	email    *mail.Address     `json:"address"`
	password password.Password `json:"password"`
}

var unique_identifiers = []string{
	"id",
	"email",
	"username",
	"access_token",
}

func NewIndividualMembershipFromStrings(str_email string, str_pswd string, str_user string) (account.Membership, error) {

	email, err := mail.ParseAddress(str_email)

	if err != nil {
		return nil, err
	}

	pswd, err := password.NewBCryptPassword(str_pswd)

	if err != nil {
		return nil, err
	}

	user, err := username.NewUCDUsername(str_user)

	if err != nil {
		return nil, err
	}

	return NewIndividualMembership(email, pswd, user)
}

func NewIndividualMembership(email *mail.Address, pswd password.Password, name account.Username) (account.Membership, error) {

	id, err := uid.NewStringUID(email.Address)

	if err != nil {
		return nil, err
	}

	details := IndividualMembershipDetails{
		id:       id,
		username: name,
		email:    email,
		password: pswd,
	}

	enc_details, err := json.Marshal(details)

	if err != nil {
		return nil, err
	}

	acct := IndividualMembership{
		id:      id.String(),
		details: enc_details,
	}

	return &acct, nil
}

func (m *IndividualMembership) Id() string {
	return m.id
}

func (m *IndividualMembership) Details() []byte {
	return m.details
}

func (m *IndividualMembership) Identifiers() []string {

	return unique_identifiers
}

func (m *IndividualMembership) GetProperty(key string) (interface{}, bool) {

	rsp := gjson.GetBytes(m.details, key)

	if !rsp.Exists() {
		return nil, false
	}

	return rsp.Value(), true
}

func (m *IndividualMembership) SetProperty(key string, value interface{}) error {
	return errors.New("please write me")
}
