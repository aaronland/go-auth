package crumb

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/aaronland/go-string/random"
	"io"
	_ "log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func init() {

	ctx := context.Background()
	RegisterCrumb(ctx, "encrypted", NewEncryptedCrumb)
}

type EncryptedCrumb struct {
	Crumb
	extra     string
	separator string
	secret    string
	ttl       int64
	key       string
}

func NewRandomEncryptedCrumbURI(ctx context.Context, ttl int, key string) (string, error) {

	r_opts := random.DefaultOptions()
	r_opts.AlphaNumeric = true

	s, err := random.String(r_opts)

	if err != nil {
		return "", err
	}

	r_opts.Length = 8
	e, err := random.String(r_opts)

	if err != nil {
		return "", err
	}

	params := url.Values{}
	params.Set("extra", e)
	params.Set("separator", ":")
	params.Set("secret", s)
	params.Set("ttl", strconv.Itoa(ttl))
	params.Set("key", key)

	uri := fmt.Sprintf("encrypted://?%s", params.Encode())
	return uri, nil
}

func NewEncryptedCrumb(ctx context.Context, uri string) (Crumb, error) {

	u, err := url.Parse(uri)

	if err != nil {
		return nil, err
	}

	q := u.Query()

	extra := q.Get("extra")
	separator := q.Get("separator")
	secret := q.Get("secret")
	str_ttl := q.Get("ttl")

	if extra == "" {
		return nil, errors.New("Empty extra= key")
	}

	if separator == "" {
		return nil, errors.New("Empty separator= key")
	}

	if secret == "" {
		return nil, errors.New("Empty secret= key")
	}

	if str_ttl == "" {
		return nil, errors.New("Empty ttl= key")
	}

	ttl, err := strconv.ParseInt(str_ttl, 10, 64)

	if err != nil {
		return nil, err
	}

	cr := &EncryptedCrumb{
		extra:     extra,
		separator: separator,
		secret:    secret,
		ttl:       ttl,
	}

	key := q.Get("key")

	if key != "" {
		cr.key = key
	}

	return cr, nil
}

func (cr *EncryptedCrumb) Generate(req *http.Request, extra ...string) (string, error) {

	crumb_base, err := cr.crumbBase(req, extra...)

	if err != nil {
		return "", err
	}

	crumb_hash, err := cr.hashCrumb(crumb_base)

	if err != nil {
		return "", err
	}

	now := time.Now()
	ts := now.Unix()

	str_ts := strconv.FormatInt(ts, 10)

	crumb_parts := []string{
		str_ts,
		crumb_hash,
	}

	crumb_var := strings.Join(crumb_parts, cr.separator)

	enc_var, err := cr.encryptCrumb(crumb_var)

	if err != nil {
		return "", err
	}

	return enc_var, nil
}

func (cr *EncryptedCrumb) Validate(req *http.Request, enc_var string, extra ...string) (bool, error) {

	crumb_var, err := cr.decryptCrumb(enc_var)

	if err != nil {
		return false, err
	}

	crumb_parts := strings.Split(crumb_var, cr.separator)

	if len(crumb_parts) != 2 {
		return false, errors.New("Invalid crumb")
	}

	crumb_ts := crumb_parts[0]
	crumb_test := crumb_parts[1]

	crumb_base, err := cr.crumbBase(req, extra...)

	if err != nil {
		return false, err
	}

	crumb_hash, err := cr.hashCrumb(crumb_base)

	if err != nil {
		return false, err
	}

	ok, err := cr.compareHashes(crumb_hash, crumb_test)

	if err != nil {
		return false, err
	}

	if !ok {
		return false, errors.New("Crumb mismatch")
	}

	if cr.ttl > 0 {

		then, err := strconv.ParseInt(crumb_ts, 10, 64)

		if err != nil {
			return false, err
		}

		now := time.Now()
		ts := now.Unix()

		if ts-then > cr.ttl {
			return false, errors.New("Crumb has expired")
		}
	}

	return true, nil
}

func (cr *EncryptedCrumb) Key(req *http.Request) string {

	switch cr.key {
	case "":
		return req.URL.Path
	default:
		return cr.key
	}
}

func (cr *EncryptedCrumb) crumbBase(req *http.Request, extra ...string) (string, error) {

	crumb_key := cr.Key(req)

	base := make([]string, 0)

	base = append(base, crumb_key)
	base = append(base, req.UserAgent())
	base = append(base, cr.extra)

	for _, e := range extra {
		base = append(base, e)
	}

	str_base := strings.Join(base, "-")
	return str_base, nil
}

func (cr *EncryptedCrumb) compareHashes(this_enc string, that_enc string) (bool, error) {

	if len(this_enc) != len(that_enc) {
		return false, nil
	}

	match := this_enc == that_enc
	return match, nil
}

func (cr *EncryptedCrumb) hashCrumb(raw string) (string, error) {

	msg := []byte(raw)

	mac := sha256.New()
	mac.Write(msg)
	hash := mac.Sum(nil)

	enc := hex.EncodeToString(hash[:])
	return enc, nil
}

// https://gist.github.com/manishtpatel/8222606
// https://github.com/blaskovicz/go-cryptkeeper/blob/master/encrypted_string.go

func (cr *EncryptedCrumb) encryptCrumb(text string) (string, error) {

	plaintext := []byte(text)
	secret := []byte(cr.secret)

	block, err := aes.NewCipher(secret)

	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))

	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	cipher.NewCFBEncrypter(block, iv).XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return hex.EncodeToString(ciphertext), nil
}

func (cr *EncryptedCrumb) decryptCrumb(enc_crumb string) (string, error) {

	ciphertext, err := hex.DecodeString(enc_crumb)

	if err != nil {
		return "", err
	}

	secret := []byte(cr.secret)
	block, err := aes.NewCipher(secret)

	if err != nil {
		return "", err
	}

	if byteLen := len(ciphertext); byteLen < aes.BlockSize {
		return "", fmt.Errorf("invalid cipher size %d.", byteLen)
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	cipher.NewCFBDecrypter(block, iv).XORKeyStream(ciphertext, ciphertext)
	return string(ciphertext), nil
}
