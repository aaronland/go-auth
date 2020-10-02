package database

import (
	"context"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-roster"
	"net/url"
)

type AccountsDatabase interface {
	GetAccountByID(int64) (*account.Account, error)
	GetAccountByEmailAddress(string) (*account.Account, error)
	GetAccountByURL(string) (*account.Account, error)
	AddAccount(*account.Account) (*account.Account, error)
	UpdateAccount(*account.Account) (*account.Account, error)
	RemoveAccount(*account.Account) (*account.Account, error)
}

type AccountsDatabaseInitializationFunc func(ctx context.Context, uri string) (AccountsDatabase, error)

var accounts_roster roster.Roster

func RegisterAccountsDatabase(ctx context.Context, scheme string, init_func AccountsDatabaseInitializationFunc) error {

	err := ensureAccountsDatabaseRoster()

	if err != nil {
		return err
	}

	return accounts_roster.Register(ctx, scheme, init_func)
}

func ensureAccountsDatabaseRoster() error {

	if accounts_roster == nil {

		r, err := roster.NewDefaultRoster()

		if err != nil {
			return err
		}

		accounts_roster = r
	}

	return nil
}

func NewAccountsDatabase(ctx context.Context, uri string) (AccountsDatabase, error) {

	u, err := url.Parse(uri)

	if err != nil {
		return nil, err
	}

	err = ensureAccountsDatabaseRoster()

	if err != nil {
		return nil, err
	}

	scheme := u.Scheme

	i, err := accounts_roster.Driver(ctx, scheme)

	if err != nil {
		return nil, err
	}

	init_func := i.(AccountsDatabaseInitializationFunc)
	return init_func(ctx, uri)
}

func AccountsDatabases() []string {
	ctx := context.Background()
	return accounts_roster.Drivers(ctx)
}
