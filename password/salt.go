package password

import (
	"github.com/aaronland/go-string/random"
)

func NewSalt() (string, error) {

	opts := random.DefaultOptions()
	return random.String(opts)
}
