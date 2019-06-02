package uid

import (
	"github.com/aaronland/go-string/random"
)

type RandomUIDProvider struct {
	Provider
}

func NewRandomUIDProvider() (Provider, error) {

	pr := RandomUIDProvider{}
	return &pr, nil
}

func (pr *RandomUIDProvider) UID(...interface{}) (UID, error) {

	return NewRandomUID()
}

func NewRandomUID() (UID, error) {

	opts := random.DefaultOptions()
	opts.Length = 16
	opts.Chars = 16
	opts.ASCII = true
	opts.AlphaNumeric = true

	s, err := random.String(opts)

	if err != nil {
		return nil, err
	}

	return NewStringUID(s)
}
