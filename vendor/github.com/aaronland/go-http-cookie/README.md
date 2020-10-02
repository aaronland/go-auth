# go-http-cookie

Go package for working with HTTP cookies.

## Example

_Error handling omitted for the sake of brevity._

```
package main

import (
	"fmt"
	"github.com/aaronland/go-http-cookie"	
)

func main() {

	name := "c"
	secret := "s33kret"
	salt := "s4lty"
	
	cookie_uri := fmt.Sprintf("encrypted://?name=%s&secret=%s&salt=%s", name, secret, salt)
	ck, _ := cookie.NewCookie(ctx, cookie_uri)
}
```

## Interfaces

type Cookie interface {
	Get(*http.Request) (*memguard.LockedBuffer, error)
	GetString(*http.Request) (string, error)
	Set(http.ResponseWriter, *memguard.LockedBuffer) error
	SetString(http.ResponseWriter, string) error
	SetWithCookie(http.ResponseWriter, *memguard.LockedBuffer, *http.Cookie) error
	SetStringWithCookie(http.ResponseWriter, string, *http.Cookie) error
	Delete(http.ResponseWriter) error
}

## See also

* https://github.com/aaronland/go-secretbox
* https://godoc.org/golang.org/x/crypto/nacl/secretbox
* https://github.com/awnumar/memguard