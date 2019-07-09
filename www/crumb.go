package www

import (
	"github.com/aaronland/go-http-crumb"
	"github.com/aaronland/go-string/random"
)

func NewCrumbConfig() (*crumb.CrumbConfig, error) {

	opts := random.DefaultOptions()
	opts.Length = 32

	s, err := random.String(opts)

	if err != nil {
		return nil, err
	}

	secret := s

	s, err = random.String(opts)

	if err != nil {
		return nil, err
	}

	extra := s

	sep := "\x00"

	crumb_cfg := crumb.CrumbConfig{
		Extra:     extra,
		Separator: sep,
		Secret:    secret,
		TTL:       300,
	}

	return &crumb_cfg, nil
}
