package database

import (
	"github.com/aaronland/go-auth/account"
)

type AccountsDatabase interface {
	GetAccountByID(int64) (*account.Account, error)
	GetAccountByEmailAddress(string) (*account.Account, error)
	GetAccountByURL(string) (*account.Account, error)
	AddAccount(*account.Account) (*account.Account, error)
	UpdateAccount(*account.Account) (*account.Account, error)
	RemoveAccount(*account.Account) (*account.Account, error)
}
