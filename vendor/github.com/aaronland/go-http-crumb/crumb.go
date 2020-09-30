package crumb

import (
	"context"
	"github.com/aaronland/go-roster"
	"net/http"
	"net/url"
	"strings"
)

type Crumb interface {
	Generate(*http.Request, ...string) (string, error)
	Validate(*http.Request, string, ...string) (bool, error)
	Key(*http.Request) string
	Base(*http.Request, ...string) (string, error)
}

type CrumbInitializeFunc func(context.Context, string) (Crumb, error)

var crumbs roster.Roster

func ensureCrumbs() error {

	if crumbs == nil {

		r, err := roster.NewDefaultRoster()

		if err != nil {
			return err
		}

		crumbs = r
	}

	return nil
}

func RegisterCrumb(ctx context.Context, scheme string, f CrumbInitializeFunc) error {

	err := ensureCrumbs()

	if err != nil {
		return err
	}

	return crumbs.Register(ctx, scheme, f)
}

func NewCrumb(ctx context.Context, uri string) (Crumb, error) {

	err := ensureCrumbs()

	if err != nil {
		return nil, err
	}

	u, err := url.Parse(uri)

	if err != nil {
		return nil, err
	}

	scheme := u.Scheme

	i, err := crumbs.Driver(ctx, scheme)

	if err != nil {
		return nil, err
	}

	f := i.(CrumbInitializeFunc)
	return f(ctx, uri)
}

func Schemes() []string {
	ctx := context.Background()
	return crumbs.Drivers(ctx)
}

func SchemesAsString() string {
	schemes := Schemes()
	return strings.Join(schemes, ",")
}
