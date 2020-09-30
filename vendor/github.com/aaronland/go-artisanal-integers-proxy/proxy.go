package proxy

import (
	"errors"
	"fmt"
	"github.com/aaronland/go-artisanal-integers"
	"github.com/aaronland/go-artisanal-integers-proxy/service"
	"github.com/aaronland/go-artisanal-integers/server"
	brooklyn_api "github.com/aaronland/go-brooklynintegers-api"
	london_api "github.com/aaronland/go-londonintegers-api"
	mission_api "github.com/aaronland/go-missionintegers-api"
	"github.com/aaronland/go-pool"
	"github.com/whosonfirst/go-whosonfirst-log"
	"net/url"
)

type ProxyServerArgs struct {
	Protocol string
	Host     string
	Port     int
}

type ProxyServiceArgs struct {
	BrooklynIntegers bool           `json:"brooklyn_integers"`
	LondonIntegers   bool           `json:"london_integers"`
	MissionIntegers  bool           `json:"mission_integers"`
	MinCount         int            `json:"min_count"`
	Logger           *log.WOFLogger `json:",omitempty"`
	Workers          int            `json:"workers"`
}

func NewProxyServiceWithPool(pl pool.Pool, args ProxyServiceArgs) (artisanalinteger.Service, error) {

	opts, err := service.DefaultProxyServiceOptions()

	if err != nil {
		return nil, err
	}

	opts.Pool = pl
	opts.Minimum = args.MinCount
	opts.Workers = args.Workers

	if args.Logger != nil {
		opts.Logger = args.Logger
	}

	clients := make([]artisanalinteger.Client, 0)

	if args.BrooklynIntegers {
		cl := brooklyn_api.NewAPIClient()
		clients = append(clients, cl)
	}

	if args.LondonIntegers {
		cl := london_api.NewAPIClient()
		clients = append(clients, cl)
	}

	if args.MissionIntegers {
		cl := mission_api.NewAPIClient()
		clients = append(clients, cl)
	}

	if len(clients) == 0 {
		return nil, errors.New("Insufficient clients")
	}

	return service.NewProxyService(opts, clients...)
}

func NewProxyServerWithService(svc artisanalinteger.Service, args ProxyServerArgs) (artisanalinteger.Server, error) {

	addr := fmt.Sprintf("%s://%s:%d", args.Protocol, args.Host, args.Port)
	u, err := url.Parse(addr)

	if err != nil {
		return nil, err
	}

	return server.NewArtisanalServer(args.Protocol, u)
}
