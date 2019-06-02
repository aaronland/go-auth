package uid

import (
	"github.com/aaronland/go-artisanal-integers"
	"github.com/aaronland/go-artisanal-integers-proxy/service"
	brooklyn_api "github.com/aaronland/go-brooklynintegers-api"
	boltdb_pool "github.com/whosonfirst/go-whosonfirst-pool-boltdb"
	"strconv"
)

func NewArtisanalProxyUIDProvider(dsn string) (Provider, error) {

	// please do something with dsn...

	// how to handle what are effectively nested DSN strings? (20190103/thisisaaronland)
	// provider=artisanal brooklyn=true mission=true london=true pool=boltdb boltdb_dsn=... boltdb_bucket=...
	// provider=artisanal brooklyn=true mission=true london=true pool=redis redis_dsn=... redis_key=...

	clients := make([]artisanalinteger.Client, 0)

	cl := brooklyn_api.NewAPIClient()
	clients = append(clients, cl)

	// please make me flags (see above)
	db := "integers.db"
	bucket := "integers"

	pool, err := boltdb_pool.NewBoltDBLIFOIntPool(db, bucket)

	if err != nil {
		return nil, err
	}

	opts, err := service.DefaultProxyServiceOptions()

	if err != nil {
		return nil, err
	}

	opts.Pool = pool
	opts.Minimum = 100

	svc, err := service.NewProxyService(opts, clients...)

	if err != nil {
		return nil, err
	}

	return NewArtisanalUIDProvider(svc)
}

type ArtisanalUIDProvider struct {
	Provider
	client artisanalinteger.Client
}

func NewArtisanalUIDProvider(client artisanalinteger.Client) (Provider, error) {

	pr := ArtisanalUIDProvider{
		client: client,
	}

	return &pr, nil
}

func (pr *ArtisanalUIDProvider) UID(...interface{}) (UID, error) {

	i, err := pr.client.NextInt()

	if err != nil {
		return nil, err
	}

	return NewArtisanalUID(i)
}

type ArtisanalUID struct {
	UID
	// integer artisanalinteger.Integer
	integer int64
}

func NewArtisanalUID(int int64) (UID, error) {

	u := ArtisanalUID{
		integer: int,
	}

	return &u, nil
}

func (u *ArtisanalUID) String() string {

	return strconv.FormatInt(u.integer, 10)
}
