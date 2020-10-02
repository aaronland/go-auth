package cookie

import (
	"context"
	"github.com/aaronland/go-roster"
	"github.com/awnumar/memguard"
	"net/http"
	"net/url"
	"strings"
)

type Cookie interface {
	Get(*http.Request) (*memguard.LockedBuffer, error)
	GetString(*http.Request) (string, error)
	Set(http.ResponseWriter, *memguard.LockedBuffer) error
	SetString(http.ResponseWriter, string) error
	SetWithCookie(http.ResponseWriter, *memguard.LockedBuffer, *http.Cookie) error
	SetStringWithCookie(http.ResponseWriter, string, *http.Cookie) error
	Delete(http.ResponseWriter) error
}

type CookieInitializeFunc func(context.Context, string) (Cookie, error)

var cookies roster.Roster

func ensureCookies() error {

	if cookies == nil {

		r, err := roster.NewDefaultRoster()

		if err != nil {
			return err
		}

		cookies = r
	}

	return nil
}

func RegisterCookie(ctx context.Context, scheme string, f CookieInitializeFunc) error {

	err := ensureCookies()

	if err != nil {
		return err
	}

	return cookies.Register(ctx, scheme, f)
}

func NewCookie(ctx context.Context, uri string) (Cookie, error) {

	err := ensureCookies()

	if err != nil {
		return nil, err
	}

	u, err := url.Parse(uri)

	if err != nil {
		return nil, err
	}

	scheme := u.Scheme

	i, err := cookies.Driver(ctx, scheme)

	if err != nil {
		return nil, err
	}

	f := i.(CookieInitializeFunc)
	return f(ctx, uri)
}

func Schemes() []string {
	ctx := context.Background()
	return cookies.Drivers(ctx)
}

func SchemesAsString() string {
	schemes := Schemes()
	return strings.Join(schemes, ",")
}
