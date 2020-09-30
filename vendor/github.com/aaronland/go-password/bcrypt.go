package password

import (
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"github.com/patrickmn/go-hmaccrypt"
	"net/url"
	_ "log"
)

type BCryptPassword struct {
	Password
	crypt  *hmaccrypt.HmacCrypt
	digest string
	salt   string
}

func init() {

	ctx := context.Background()
	err := RegisterPassword(ctx, "bcrypt", NewBCryptPassword)

	if err != nil {
		panic(err)
	}
}

func NewBCryptPassword(ctx context.Context, uri string) (Password, error) {

	u, err := url.Parse(uri)

	if err != nil {
		return nil, err
	}

	pswd := u.Host

	q := u.Query()

	digest := q.Get("digest")
	salt := q.Get("salt")

	if salt == "" {

		s, err := NewSalt()

		if err != nil {
			return nil, err
		}

		salt = s
	}

	pepper := []byte(salt)
	crypt := hmaccrypt.New(sha512.New, pepper)

	if digest == "" {

		if len(pswd) < 8 {
			return nil, errors.New("Password too short")
		}

		d, err := crypt.Bcrypt([]byte(pswd), 10)

		if err != nil {
			return nil, err
		}

		digest = string(d)
	}

	p := BCryptPassword{
		digest: string(digest),
		crypt:  crypt,
		salt:   salt,
	}

	return &p, nil
}

func (p *BCryptPassword) Digest() string {
	return p.digest
}

func (p *BCryptPassword) Salt() string {
	return p.salt
}

func (p *BCryptPassword) Compare(pswd string) error {

	return p.crypt.BcryptCompare([]byte(p.digest), []byte(pswd))
}

func (p *BCryptPassword) String() string {
	return fmt.Sprintf("bcrypt:///?digest=%s&salt=%s", p.digest, p.salt)
}
