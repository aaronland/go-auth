package database

import (
	"context"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/token"
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
