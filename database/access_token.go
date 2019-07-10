package database

import (
	"github.com/aaronland/go-http-auth/account"
	"github.com/aaronland/go-http-auth/token"
)

type AccessTokenDatabase interface {
	GetTokenByID(int64) (*token.Token, error)
	GetTokenByAccessToken(string) (*token.Token, error)
	GetSiteTokenForAccount(*account.Account) (*token.Token, error)
	AddToken(*token.Token) (*token.Token, error)
	UpdateToken(*token.Token) (*token.Token, error)
	DeleteToken(*token.Token) (*token.Token, error)
}
