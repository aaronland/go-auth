package password

import (
	"context"
	"github.com/aaronland/go-roster"
	"net/url"
)

type Password interface {
	Digest() string
	Salt() string
	Compare(string) error
	String() string
}

type PasswordInitializationFunc func(ctx context.Context, uri string) (Password, error)

var password_roster roster.Roster

func NewService(ctx context.Context, uri string) (Password, error) {

	err := ensurePasswordRoster()

	if err != nil {
		return nil, err
	}

	parsed, err := url.Parse(uri)

	if err != nil {
		return nil, err
	}

	scheme := parsed.Scheme

	i, err := password_roster.Driver(ctx, scheme)

	if err != nil {
		return nil, err
	}

	init_func := i.(PasswordInitializationFunc)
	return init_func(ctx, uri)
}

func RegisterPassword(ctx context.Context, scheme string, init_func PasswordInitializationFunc) error {

	err := ensurePasswordRoster()

	if err != nil {
		return err
	}

	return password_roster.Register(ctx, scheme, init_func)
}

func ensurePasswordRoster() error {

	if password_roster == nil {

		r, err := roster.NewDefaultRoster()

		if err != nil {
			return err
		}

		password_roster = r
	}

	return nil
}

func NewPassword(ctx context.Context, uri string) (Password, error) {

	u, err := url.Parse(uri)

	if err != nil {
		return nil, err
	}

	scheme := u.Scheme

	i, err := password_roster.Driver(ctx, scheme)

	if err != nil {
		return nil, err
	}

	init_func := i.(PasswordInitializationFunc)
	return init_func(ctx, uri)
}

func Passwords() []string {
	ctx := context.Background()
	return password_roster.Drivers(ctx)
}
