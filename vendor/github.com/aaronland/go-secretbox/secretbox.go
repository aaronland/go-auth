package secretbox

// https://godoc.org/golang.org/x/crypto/scrypt
// https://godoc.org/github.com/awnumar/memguard
// https://spacetime.dev/encrypting-secrets-in-memory

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/awnumar/memguard"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"io"
	
)

func init() {

	memguard.CatchInterrupt()
}

type Secretbox struct {
	enclave *memguard.Enclave
	options *SecretboxOptions
}

type SecretboxOptions struct {
	Salt   string
	Suffix string
	Debug  bool
}

func NewSecretboxOptions() *SecretboxOptions {

	opts := SecretboxOptions{
		Salt:   "",
		Suffix: "enc",
		Debug:  false,
	}

	return &opts
}

func NewSecretbox(pswd string, opts *SecretboxOptions) (*Secretbox, error) {

	buf := memguard.NewBufferFromBytes([]byte(pswd))
	defer buf.Destroy()

	return NewSecretboxWithBuffer(buf, opts)
}

func NewSecretboxWithBuffer(buf *memguard.LockedBuffer, opts *SecretboxOptions) (*Secretbox, error) {

	// PLEASE TRIPLE-CHECK opts.Salt HERE...

	N := 32768
	r := 8
	p := 1

	key, err := scrypt.Key(buf.Bytes(), []byte(opts.Salt), N, r, p, 32)

	if err != nil {
		return nil, err
	}

	enclave := memguard.NewEnclave(key)
	return NewSecretboxWithEnclave(enclave, opts)
}

func NewSecretboxWithEnclave(enclave *memguard.Enclave, opts *SecretboxOptions) (*Secretbox, error) {

	sb := Secretbox{
		enclave: enclave,
		options: opts,
	}

	return &sb, nil
}

func (sb Secretbox) Lock(body []byte) (string, error) {

	buf := memguard.NewBufferFromBytes(body)
	defer buf.Destroy()

	return sb.LockWithBuffer(buf)
}

func (sb Secretbox) LockWithReader(r io.Reader) (string, error) {

	buf, err := memguard.NewBufferFromEntireReader(r)

	if err != nil {
		return "", err
	}
	
	defer buf.Destroy()

	return sb.LockWithBuffer(buf)
}

func (sb Secretbox) LockWithBuffer(buf *memguard.LockedBuffer) (string, error) {

	var nonce [24]byte

	_, err := io.ReadFull(rand.Reader, nonce[:])

	if err != nil {
		return "", err
	}

	key, err := sb.enclave.Open()

	if err != nil {
		return "", err
	}

	defer key.Destroy()

	enc := secretbox.Seal(nonce[:], buf.Bytes(), &nonce, key.ByteArray32())
	enc_hex := base64.StdEncoding.EncodeToString(enc)

	return enc_hex, nil
}

func (sb Secretbox) Unlock(body_hex string) (*memguard.LockedBuffer, error) {

	body_str, err := base64.StdEncoding.DecodeString(body_hex)

	if err != nil {
		return nil, err
	}

	body := []byte(body_str)

	var nonce [24]byte
	copy(nonce[:], body[:24])

	key, err := sb.enclave.Open()

	if err != nil {
		return nil, err
	}

	defer key.Destroy()

	out, ok := secretbox.Open(nil, body[24:], &nonce, key.ByteArray32())

	if !ok {
		return nil, errors.New("Unable to open secretbox")
	}

	buf := memguard.NewBufferFromBytes(out)
	return buf, nil
}
