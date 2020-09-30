# go-http-crumb

Go package for creating and validating (HTTP) crumbs.

## Example

_The following are abbreviated code examples. Error handling has been omitted for the sake of brevity._

### Simple (Encypted crumbs)

```
import (
       "context"
       "github.com/aaronland/go-http-crumb"
)

func main() {
	cr_uri := "encrypted://?extra=f3gKgLVX&key=&secret=oK5OFCjBsvAOrfJPnzAJqnkphkuDmyf9&separator=%3A&ttl=3600"
	cr, _ := crumb.NewCrumb(ctx, uri)
}

```

### HTTP (Simple)

Use the `crumb.EnsureCrumbHandler` middleware handler to automatically generate a new crumb string for all requests and append it to any HTML output as a `html/body@data-crumb` attribute value.

For `POST` and `PUT` requests the (middleware) handler intercept the current handler and look for a `crumb` form value and validate it before continuing.

```
import (
       "context"
       "github.com/aaronland/go-http-crumb"
       "net/http"
)

func MyHandler() http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {
		rsp.Write([]byte("Hello world"))
	}

	return http.HandlerFunc(fn)
}

func main() {

	ctx := context.Background()
	
	uri, _ := crumb.NewRandomEncryptedCrumbURI(ctx, 3600)
	cr, _ := crumb.NewCrumb(ctx, uri)

	mux := http.NewServeMux()
	
	my_handler, _ := MyHandler()
	my_handler = crumb.EnsureCrumbHandler(cr, my_handler)

	mux.Handle("/", my_handler)
}
```

### HTTP (Doing it yourself)

```
import (
       "context"
       "github.com/aaronland/go-http-crumb"
       "net/http"
)

func CrumbHandler() (http.Handler, error) {

	ctx := context.Background()
	
	uri, _ := crumb.NewRandomEncryptedCrumbURI(ctx, 3600)
	cr, _ := crumb.NewCrumb(ctx, uri)

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		if req.URL.Method == "GET" {
			cr_hash, _ := cr.Generate(req)
			// pass cr_hash to template
		} else {

			// read cr_hash from POST form here
			ok, _ := cr.Validate(req, cr_hash)	
		}
	}

	h := http.HandlerFunc(fn)
	return h, nil
}
```

## Interfaces

## Crumb

```
type Crumb interface {
	Generate(*http.Request, ...string) (string, error)
	Validate(*http.Request, string, ...string) (bool, error)
	Key(*http.Request) string
	Base(*http.Request, ...string) (string, error)
}
```

## Schemes

### encrypted:///?secret={SECRET}&extra={EXTRA}&ttl={TTL}&separator={SEPARATOR}

For example:

```
encrypted:///?secret={SECRET}&extra={EXTRA}&ttl={TTL}&separator={SEPARATOR}
```

| Parameter | Description | Required |
| --- | --- | --- |
| secret | A valid AES secret for encrypting the crumb | yes |
| extra | A string to include when generating crumb base | yes |
| separator | A string to separate crumb parts with | yes |
| ttl | Time to live (in seconds) | yes |
| key | A string to prepend crumb base with. Default is to use the path of the current HTTP request | no |