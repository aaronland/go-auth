package uid

import (
	"errors"
	"github.com/aaronland/go-string/dsn"
)

type Provider interface {
	UID(...interface{}) (UID, error) // NOT SURE ABOUT THIS...
}

type UID interface {
	String() string
}

func NewUIDProviderWithDSN(str_dsn string) (Provider, error) {

	dsn_map, err := dsn.StringToDSNWithKeys(str_dsn, "provider")

	if err != nil {
		return nil, err
	}

	switch dsn_map["provider"] {

	case "artisanal":
		return NewArtisanalProxyUIDProvider(str_dsn)
	case "ymd":
		return NewYMDUIDProvider()
	default:
		return nil, errors.New("Invalid or unsupported UID provider")

	}
}
