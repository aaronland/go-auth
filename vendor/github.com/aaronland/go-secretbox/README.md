# go-secretbox

A thin wrapper around the Golang [secretbox](https://godoc.org/golang.org/x/crypto/nacl/secretbox) package.

## Example

```
package main

import (
	"github.com/aaronland/go-secretbox"
	"github.com/aaronland/go-secretbox/salt"
)

func main() {

     	secret := "S33KRET"

     	st_opts := salt.DefaultSaltOptions()
	s, _ := salt.NewRandomSalt(st_opts)

	sb_opts := secretbox.NewSecretboxOptions()
	sb_opts.Salt = s

	sb, _ := secretbox.NewSecretbox(secret, sb_opts)

	sb_path, _ = sb.LockFile("/some/file/to/lock")

	// or this:
	// sb_path, _ = sb.UnlockFile("/some/file/to/unlock")	
}
```

_Error handling omitted for the sake of brevity._

## See also

* https://godoc.org/golang.org/x/crypto/nacl/secretbox
* https://github.com/aaronland/go-string
