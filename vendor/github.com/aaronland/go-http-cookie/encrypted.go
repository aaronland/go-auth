package cookie

import (
	"errors"
	"github.com/aaronland/go-secretbox"
	go_http "net/http"
)

type EncryptedCookie struct {
	Cookie
	name   string
	secret string
	salt   string
}

func NewEncryptedCookie(name string, secret string, salt string) (Cookie, error) {

	if name == "" {
		return nil, errors.New("Missing name")
	}

	if secret == "" {
		return nil, errors.New("Missing secret")
	}

	if salt == "" {
		return nil, errors.New("Missing salt")
	}

	c := EncryptedCookie{
		name:   name,
		secret: secret,
		salt:   salt,
	}

	return &c, nil
}

func (c *EncryptedCookie) Get(req *go_http.Request) (string, error) {

	http_cookie, err := req.Cookie(c.name)

	if err != nil {
		return "", err
	}

	opts := secretbox.NewSecretboxOptions()
	opts.Salt = c.salt

	sb, err := secretbox.NewSecretbox(c.secret, opts)

	if err != nil {
		return "", err
	}

	body, err := sb.Unlock([]byte(http_cookie.Value))

	if err != nil {
		return "", err
	}

	str_body := string(body)
	return str_body, nil
}

func (c *EncryptedCookie) Set(rsp go_http.ResponseWriter, body string) error {

	http_cookie := &go_http.Cookie{
		Value: body,
	}

	return c.SetCookie(rsp, http_cookie)
}

func (c *EncryptedCookie) SetCookie(rsp go_http.ResponseWriter, http_cookie *go_http.Cookie) error {

	if http_cookie.Name != "" {
		return errors.New("Cookie name already set")
	}

	body := http_cookie.Value

	opts := secretbox.NewSecretboxOptions()
	opts.Salt = c.salt

	sb, err := secretbox.NewSecretbox(c.secret, opts)

	if err != nil {
		return err
	}

	enc, err := sb.Lock([]byte(body))

	if err != nil {
		return err
	}

	http_cookie.Name = c.name
	http_cookie.Value = enc

	go_http.SetCookie(rsp, http_cookie)
	return nil
}

func (c *EncryptedCookie) Delete(rsp go_http.ResponseWriter) error {

	http_cookie := go_http.Cookie{
		Name:   c.name,
		Value:  "",
		MaxAge: -1,
	}

	go_http.SetCookie(rsp, &http_cookie)
	return nil
}
