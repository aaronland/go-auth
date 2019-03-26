package password

import ()

type Password interface {
	Digest() string
	Salt() string
	Compare(string) error
}
