package database

import (
	"context"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/token"
	"github.com/aaronland/go-roster"
	"net/url"
)

type ListAccessTokensFunc func(*token.Token) error

type AccessTokensDatabase interface {
	GetTokenByID(int64) (*token.Token, error)
	GetTokenByAccessToken(string) (*token.Token, error)
	AddToken(*token.Token) (*token.Token, error)
	UpdateToken(*token.Token) (*token.Token, error)
	RemoveToken(*token.Token) (*token.Token, error)
	ListAccessTokens(context.Context, ListAccessTokensFunc) error
	ListAccessTokensForAccount(context.Context, *account.Account, ListAccessTokensFunc) error
}

type AccessTokensDatabaseInitializationFunc func(ctx context.Context, uri string) (AccessTokensDatabase, error)

var accesstokens_roster roster.Roster

func RegisterAccessTokensDatabase(ctx context.Context, scheme string, init_func AccessTokensDatabaseInitializationFunc) error {

	err := ensureAccessTokensDatabaseRoster()

	if err != nil {
		return err
	}

	return accesstokens_roster.Register(ctx, scheme, init_func)
}

func ensureAccessTokensDatabaseRoster() error {

	if accesstokens_roster == nil {

		r, err := roster.NewDefaultRoster()

		if err != nil {
			return err
		}

		accesstokens_roster = r
	}

	return nil
}

func NewAccessTokensDatabase(ctx context.Context, uri string) (AccessTokensDatabase, error) {

	u, err := url.Parse(uri)

	if err != nil {
		return nil, err
	}

	err = ensureAccessTokensDatabaseRoster()

	if err != nil {
		return nil, err
	}

	scheme := u.Scheme

	i, err := accesstokens_roster.Driver(ctx, scheme)

	if err != nil {
		return nil, err
	}

	init_func := i.(AccessTokensDatabaseInitializationFunc)
	return init_func(ctx, uri)
}

func AccessTokensDatabases() []string {
	ctx := context.Background()
	return accesstokens_roster.Drivers(ctx)
}
