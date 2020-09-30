package database

import (
	"context"
	"errors"
	"github.com/aaronland/go-artisanal-integers"
	"github.com/aaronland/go-artisanal-integers-proxy"
	"github.com/aaronland/go-pool"
	"sync"
)

var proxy_service artisanalinteger.Service
var proxy_init sync.Once

func proxy_setup() {

	ctx := context.Background()
	pl, err := pool.NewPool(ctx, "memory://")

	if err != nil {
		return
	}

	svc_args := proxy.ProxyServiceArgs{
		BrooklynIntegers: true,
		LondonIntegers:   false,
		MissionIntegers:  false,
		MinCount:         10,
	}

	svc, err := proxy.NewProxyServiceWithPool(pl, svc_args)

	if err != nil {
		return
	}

	proxy_service = svc
}

func NewID() (int64, error) {

	proxy_init.Do(proxy_setup)

	if proxy_service == nil {
		return -1, errors.New("Unable to initialize ID proxy")
	}

	return proxy_service.NextInt()
}
