package password

import (
	"crypto/sha512"
	"github.com/patrickmn/go-hmaccrypt"
)

type BCryptPassword struct {
	Password
	crypt  *hmaccrypt.HmacCrypt
	digest string
	salt   string
}

func NewBCryptPasswordFromDigest(digest string, salt string) (Password, error) {

	pepper := []byte(salt)
	crypt := hmaccrypt.New(sha512.New, pepper)

	p := BCryptPassword{
		digest: digest,
		crypt:  crypt,
		salt:   salt,
	}

	return &p, nil
}

func NewBCryptPassword(pswd string) (Password, error) {

	salt, err := NewSalt()

	if err != nil {
		return nil, err
	}

	return NewBCryptPasswordWithSalt(pswd, salt)
}

func NewBCryptPasswordWithSalt(pswd string, salt string) (Password, error) {

	pepper := []byte(salt)
	crypt := hmaccrypt.New(sha512.New, pepper)

	b_pswd := []byte(pswd)
	digest, err := crypt.Bcrypt(b_pswd, 10)

	if err != nil {
		return nil, err
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
