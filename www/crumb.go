package www

import (
	"context"
	"github.com/aaronland/go-http-crumb"
)

func NewCrumbURI(ctx context.Context) (string, error) {

	ttl := 300
	key := ""

	return crumb.NewRandomEncryptedCrumbURI(ctx, ttl, key)
}
