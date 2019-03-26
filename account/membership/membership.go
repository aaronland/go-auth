package membership

import (
	"errors"
	"github.com/straup/go-picturebox/auth/account"
	"github.com/straup/go-picturebox/auth/password"
)

func GetPassword(m account.Membership) (password.Password, error) {

	p, ok := m.GetProperty("password")

	if !ok {
		return nil, errors.New("No password")
	}

	return p.(password.Password), nil
}
