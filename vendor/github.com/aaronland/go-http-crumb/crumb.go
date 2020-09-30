package crumb

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/aaronland/go-string/dsn"
	_ "github.com/aaronland/go-string/random"
	"io"
	_ "log"
	go_http "net/http"
	"strconv"
	"strings"
	"time"
)

/*
var sep string
var secret string
var extra string

func init() {

	opts := random.DefaultOptions()
	opts.Length = 32

	var s string

	s, _ = random.String(opts)
	secret = s

	s, _ = random.String(opts)
	extra = s

	sep = "\x00"
}

type Crumb interface {
	Generate(*go_http.Request, ...string) (string, error)
	Validate(*go_http.Request, string, ...string) (bool, error)
	Key(*go_http.Request) string
	Base(*go_http.Request, ...string) (string, error)
}

*/

type CrumbConfig struct {
	Extra     string
	Separator string
	Secret    string
	TTL       int64
	Key       string
}

func NewCrumbConfigFromDSN(crumb_dsn string) (*CrumbConfig, error) {

	dsn_map, err := dsn.StringToDSNWithKeys(crumb_dsn, "extra", "separator", "secret", "ttl")

	if err != nil {
		return nil, err
	}

	extra := strings.TrimSpace(dsn_map["extra"])
	separator := strings.TrimSpace(dsn_map["separator"])
	secret := strings.TrimSpace(dsn_map["secret"])
	str_ttl := strings.TrimSpace(dsn_map["ttl"])

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

	cfg := &CrumbConfig{
		Extra:     extra,
		Separator: separator,
		Secret:    secret,
		TTL:       ttl,
	}

	key, ok := dsn_map["key"]

	if ok {
		cfg.Key = key
	}

	return cfg, nil
}

func GenerateCrumb(cfg *CrumbConfig, req *go_http.Request, extra ...string) (string, error) {

	crumb_base, err := CrumbBase(cfg, req, extra...)

	if err != nil {
		return "", err
	}

	crumb_hash, err := HashCrumb(cfg, crumb_base)

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

	crumb_var := strings.Join(crumb_parts, cfg.Separator)

	enc_var, err := EncryptCrumb(cfg, crumb_var)

	if err != nil {
		return "", err
	}

	return enc_var, nil
}

func ValidateCrumb(cfg *CrumbConfig, req *go_http.Request, enc_var string, extra ...string) (bool, error) {

	crumb_var, err := DecryptCrumb(cfg, enc_var)

	if err != nil {
		return false, err
	}

	crumb_parts := strings.Split(crumb_var, cfg.Separator)

	if len(crumb_parts) != 2 {
		return false, errors.New("Invalid crumb")
	}

	crumb_ts := crumb_parts[0]
	crumb_test := crumb_parts[1]

	crumb_base, err := CrumbBase(cfg, req, extra...)

	if err != nil {
		return false, err
	}

	crumb_hash, err := HashCrumb(cfg, crumb_base)

	if err != nil {
		return false, err
	}

	ok, err := CompareHashes(crumb_hash, crumb_test)

	if err != nil {
		return false, err
	}

	if !ok {
		return false, errors.New("Crumb mismatch")
	}

	if cfg.TTL > 0 {

		then, err := strconv.ParseInt(crumb_ts, 10, 64)

		if err != nil {
			return false, err
		}

		now := time.Now()
		ts := now.Unix()

		if ts-then > cfg.TTL {
			return false, errors.New("Crumb has expired")
		}
	}

	return true, nil
}

func CrumbKey(cfg *CrumbConfig, req *go_http.Request) string {

	switch cfg.Key {
	case "":
		return req.URL.Path
	default:
		return cfg.Key
	}
}

func CrumbBase(cfg *CrumbConfig, req *go_http.Request, extra ...string) (string, error) {

	crumb_key := CrumbKey(cfg, req)

	base := make([]string, 0)

	base = append(base, crumb_key)
	base = append(base, req.UserAgent())
	base = append(base, cfg.Extra)

	for _, e := range extra {
		base = append(base, e)
	}

	str_base := strings.Join(base, "-")
	return str_base, nil
}

func CompareHashes(this_enc string, that_enc string) (bool, error) {

	if len(this_enc) != len(that_enc) {
		return false, nil
	}

	match := this_enc == that_enc
	return match, nil
}

func HashCrumb(cfg *CrumbConfig, raw string) (string, error) {

	msg := []byte(raw)

	mac := sha256.New()
	mac.Write(msg)
	hash := mac.Sum(nil)

	enc := hex.EncodeToString(hash[:])
	return enc, nil
}

// https://gist.github.com/manishtpatel/8222606
// https://github.com/blaskovicz/go-cryptkeeper/blob/master/encrypted_string.go

func EncryptCrumb(cfg *CrumbConfig, text string) (string, error) {

	plaintext := []byte(text)
	secret := []byte(cfg.Secret)

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

func DecryptCrumb(cfg *CrumbConfig, enc_crumb string) (string, error) {

	ciphertext, err := hex.DecodeString(enc_crumb)

	if err != nil {
		return "", err
	}

	secret := []byte(cfg.Secret)
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
