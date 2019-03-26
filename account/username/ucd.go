package username

import (
	"github.com/aaronland/go-ucd-username"
	"github.com/straup/go-picturebox/auth/account"
)

type UCDUsername struct {
	account.Username
	name string
	safe string
}

func NewUCDUsername(name string) (account.Username, error) {

	u, err := ucd.NewUCDUsername()

	if err != nil {
		return nil, err
	}

	safe, err := u.Translate(name)

	if err != nil {
		return nil, err
	}

	user := UCDUsername{
		name: name,
		safe: safe,
	}

	return &user, nil
}

func (u *UCDUsername) Name() string {
	return u.name
}

func (u *UCDUsername) URISafeName() string {
	return u.safe
}

func (u *UCDUsername) String() string {
	return u.Name()
}
