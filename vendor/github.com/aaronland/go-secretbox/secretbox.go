package secretbox

// https://godoc.org/golang.org/x/crypto/scrypt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type Secretbox struct {
	Key     [32]byte
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

	// PLEASE TRIPLE-CHECK opts.Salt HERE...

	N := 32768
	r := 8
	p := 1

	skey, err := scrypt.Key([]byte(pswd), []byte(opts.Salt), N, r, p, 32)

	if err != nil {
		return nil, err
	}

	var key [32]byte
	copy(key[:], skey)

	sb := Secretbox{
		Key:     key,
		options: opts,
	}

	return &sb, nil
}

func (sb Secretbox) Lock(body []byte) (string, error) {

	var nonce [24]byte

	_, err := io.ReadFull(rand.Reader, nonce[:])

	if err != nil {
		return "", err
	}

	enc := secretbox.Seal(nonce[:], body, &nonce, &sb.Key)
	enc_hex := base64.StdEncoding.EncodeToString(enc)

	return enc_hex, nil
}

func (sb Secretbox) LockFile(abs_path string) (string, error) {

	root := filepath.Dir(abs_path)
	fname := filepath.Base(abs_path)

	body, err := ReadFile(abs_path)

	if err != nil {
		return "", err
	}

	enc_hex, err := sb.Lock(body)

	if err != nil {
		return "", err
	}

	enc_fname := fmt.Sprintf("%s%s", fname, sb.options.Suffix)
	enc_path := filepath.Join(root, enc_fname)

	if sb.options.Debug {
		log.Printf("debugging is enabled so don't actually write %s\n", enc_path)
		return enc_path, nil
	}

	return WriteFile([]byte(enc_hex), enc_path)
}

func (sb Secretbox) Unlock(body_hex []byte) ([]byte, error) {

	body_str, err := base64.StdEncoding.DecodeString(string(body_hex))

	if err != nil {
		return nil, err
	}

	body := []byte(body_str)

	var nonce [24]byte
	copy(nonce[:], body[:24])

	out, ok := secretbox.Open(nil, body[24:], &nonce, &sb.Key)

	if !ok {
		return nil, errors.New("Unable to open secretbox")
	}

	return out, nil
}

func (sb Secretbox) UnlockFile(abs_path string) (string, error) {

	root := filepath.Dir(abs_path)
	fname := filepath.Base(abs_path)
	ext := filepath.Ext(abs_path)

	if ext != sb.options.Suffix {
		return "", errors.New("Unexpected suffix")
	}

	body_hex, err := ReadFile(abs_path)

	if err != nil {
		return "", err
	}

	out, err := sb.Unlock(body_hex)

	if err != nil {
		return "", err
	}

	out_fname := strings.TrimRight(fname, ext)
	out_path := filepath.Join(root, out_fname)

	if sb.options.Debug {
		log.Printf("debugging is enabled so don't actually write %s\n", out_path)
		return out_path, nil
	}

	return WriteFile(out, out_path)
}

func ReadFile(path string) ([]byte, error) {

	fh, err := os.Open(path)

	if err != nil {
		return nil, err
	}

	return ioutil.ReadAll(fh)
}

func WriteFile(body []byte, path string) (string, error) {

	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)

	if err != nil {
		return "", err
	}

	_, err = fh.Write(body)

	if err != nil {
		return "", err
	}

	err = fh.Close()

	if err != nil {
		return "", err
	}

	return path, nil
}
