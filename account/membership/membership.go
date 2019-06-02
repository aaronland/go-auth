package membership

import (
	"errors"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/password"
)

func GetPassword(m account.Membership) (password.Password, error) {

	p, ok := m.GetProperty("password")

	if !ok {
		return nil, errors.New("No password")
	}

	return p.(password.Password), nil
}
