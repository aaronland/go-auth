package password

import (
	"github.com/aaronland/go-string/random"
)

func NewRandomPassword() (string, error) {

	opts := random.DefaultOptions()
	opts.Length = 16
	opts.Chars = 16
	opts.Base32 = true

	return random.String(opts)
}
