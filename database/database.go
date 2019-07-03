package database

import (
	"github.com/aaronland/go-http-auth/account"
)

type ErrNoAccount struct {
	error
}

func (e *ErrNoAccount) String() string {
	return "Account does not exist"
}

func IsNotExist(e error) bool {

	switch e.(type) {
	case *ErrNoAccount:
		return true
	case ErrNoAccount:
		return true
	default:
		return false
	}
}

type AccountDatabase interface {
	GetAccountByID(int64) (*account.Account, error)
	GetAccountByEmailAddress(string) (*account.Account, error)
	GetAccountByNameURISafe(string) (*account.Account, error)
	AddAccount(*account.Account) error
	UpdateAccount(*account.Account) error
	DeleteAccount(*account.Account) error
}
