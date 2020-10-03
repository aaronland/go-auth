package cookie

import (
	"context"
	"errors"
	"github.com/senseyeio/duration"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// https://github.com/golang/go/issues/25194

type Config struct {
	uri      string
	Name     string
	Domain   string
	Path     string
	Secure   bool
	SameSite http.SameSite
	TTL      *duration.Duration
}

// https://example.com/?name=test&ttl=PT1H&samesite=strict
// test=testing; Path=/; Domain=example.com; Expires=Sat, 03 Oct 2020 18:29:10 GMT; Secure; SameSite=Strict

func NewConfig(ctx context.Context, uri string) (*Config, error) {

	u, err := url.Parse(uri)

	if err != nil {
		return nil, err
	}

	q := u.Query()

	name := q.Get("name")

	if name == "" {
		return nil, errors.New("Missing name parameter")
	}

	cfg := &Config{
		uri:      uri,
		Name:     name,
		SameSite: http.SameSiteDefaultMode,
	}

	str_ttl := q.Get("ttl")

	if str_ttl != "" {

		ttl, err := duration.ParseISO8601(str_ttl)

		if err != nil {
			return nil, err
		}

		cfg.TTL = &ttl
	}

	samesite := q.Get("samesite")

	if samesite != "" {

		switch strings.ToLower(samesite) {
		case "lax":
			cfg.SameSite = http.SameSiteLaxMode
		case "strict":
			cfg.SameSite = http.SameSiteStrictMode
		case "none":
			cfg.SameSite = http.SameSiteNoneMode
		case "default":
			cfg.SameSite = http.SameSiteDefaultMode
		default:
			return nil, errors.New("Invalid samesite parameter")
		}
	}

	if u.Scheme == "https" {
		cfg.Secure = true
	}

	if u.Host != "" {
		cfg.Domain = u.Host
	}

	if u.Path != "" {
		cfg.Path = u.Path
	}

	return cfg, nil
}

func (cfg *Config) NewCookie(ctx context.Context, value string) (*http.Cookie, error) {

	ck := &http.Cookie{
		Name:     cfg.Name,
		Value:    value,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
	}

	if cfg.TTL != nil {
		now := time.Now()
		expires := cfg.TTL.Shift(now)
		ck.Expires = expires
	}

	if cfg.Domain != "" {
		ck.Domain = cfg.Domain
	}

	if cfg.Path != "" {
		ck.Path = cfg.Path
	}

	if ck.String() == "" {
		return nil, errors.New("Invalid cookie")
	}

	return ck, nil
}
