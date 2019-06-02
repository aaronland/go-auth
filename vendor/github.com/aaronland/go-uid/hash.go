package uid

import (
	"encoding/hex"
	"hash"
)

func NewHashUID(h hash.Hash, body []byte) (UID, error) {

	r := h.Sum(body)
	s := hex.EncodeToString(r[:])

	return NewStringUID(s)
}

func NewSaltedHashUID(h hash.Hash, body []byte, salt []byte) (UID, error) {
	new_body := append(body, salt...)
	return NewHashUID(h, new_body)
}
