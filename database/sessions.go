package database

import (
	"context"
	"github.com/aaronland/go-auth/session"
	"github.com/aaronland/go-roster"
	"net/url"
)

type SessionsDatabase interface {
	GetSessionWithId(context.Context, string) (*session.SessionRecord, error)
	AddSession(context.Context, *session.SessionRecord) error
	UpdateSession(context.Context, *session.SessionRecord) error
	RemoveSession(context.Context, *session.SessionRecord) error
}

type SessionsDatabaseInitializationFunc func(ctx context.Context, uri string) (SessionsDatabase, error)

var sessions_roster roster.Roster

func RegisterSessionsDatabase(ctx context.Context, scheme string, init_func SessionsDatabaseInitializationFunc) error {

	err := ensureSessionsDatabaseRoster()

	if err != nil {
		return err
	}

	return sessions_roster.Register(ctx, scheme, init_func)
}

func ensureSessionsDatabaseRoster() error {

	if sessions_roster == nil {

		r, err := roster.NewDefaultRoster()

		if err != nil {
			return err
		}

		sessions_roster = r
	}

	return nil
}

func NewSessionsDatabase(ctx context.Context, uri string) (SessionsDatabase, error) {

	u, err := url.Parse(uri)

	if err != nil {
		return nil, err
	}

	err = ensureSessionsDatabaseRoster()

	if err != nil {
		return nil, err
	}

	scheme := u.Scheme

	i, err := sessions_roster.Driver(ctx, scheme)

	if err != nil {
		return nil, err
	}

	init_func := i.(SessionsDatabaseInitializationFunc)
	return init_func(ctx, uri)
}

func SessionsDatabases() []string {
	ctx := context.Background()
	return sessions_roster.Drivers(ctx)
}
