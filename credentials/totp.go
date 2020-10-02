package credentials

import (
	"context"
	"errors"
	"fmt"
	"github.com/aaronland/go-auth"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/database"
	"github.com/aaronland/go-http-cookie"
	"github.com/aaronland/go-http-sanitize"
	"github.com/pquerna/otp/totp"
	"html/template"
	// "log"
	go_http "net/http"
	"strings"
	"time"
)

type TOTPCredentialsOptions struct {
	TTL          int64 // please make this a time.Duration...
	Force        bool
	SigninUrl    string
	CookieURI string
	CookieName   string	// deprecated
	CookieSecret string	// deprecated
	CookieSalt   string	// deprecated
}

func DefaultTOTPCredentialsOptions() *TOTPCredentialsOptions {

	opts := TOTPCredentialsOptions{
		TTL:       3600,
		Force:     false,
		SigninUrl: "/mfa",
	}

	return &opts
}

type TOTPCredentials struct {
	auth.Credentials
	account_db database.AccountsDatabase
	options    *TOTPCredentialsOptions
}

func NewTOTPCredentials(db database.AccountsDatabase, opts *TOTPCredentialsOptions) (auth.Credentials, error) {

	totp_auth := TOTPCredentials{
		account_db: db,
		options:    opts,
	}

	return &totp_auth, nil
}

func (totp_auth *TOTPCredentials) AuthHandler(next go_http.Handler) go_http.Handler {

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		acct, err := totp_auth.GetAccountForRequest(req)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
			return
		}

		if acct == nil {
			next.ServeHTTP(rsp, req)
			return
		}

		mfa := acct.MFA

		if mfa == nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
			return
		}

		require_code := true

		totp_cookie, totp_cookie_err := totp_auth.newTOTPCookie()

		if totp_auth.options.Force {

			// check to see if we've already auth-ed on this page
			// in the last (n) seconds

			if totp_cookie_err == nil {

				ok, _ := totp_auth.isRequestCookie(req, totp_cookie)

				if ok {
					require_code = false
				}
			}

		} else {

			now := time.Now()
			diff := now.Unix() - mfa.LastAuth

			if diff < totp_auth.options.TTL {
				require_code = false
			}
		}

		if require_code {
			redir_url := fmt.Sprintf("%s?redir=%s", totp_auth.options.SigninUrl, req.URL.Path)
			go_http.Redirect(rsp, req, redir_url, 303)
			return
		}

		if totp_cookie != nil {
			totp_auth.setTOTPCookie(rsp, req, totp_cookie)
		}

		req = auth.SetAccountContext(req, acct)
		next.ServeHTTP(rsp, req)
	}

	return go_http.HandlerFunc(fn)
}

func (totp_auth *TOTPCredentials) SigninHandler(templates *template.Template, t_name string, next go_http.Handler) go_http.Handler {

	type TOTPVars struct {
		PageTitle string
		SigninUrl string
		Redirect  string
		Error     error
	}

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		acct, err := auth.GetAccountContext(req)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
			return
		}

		if acct == nil {
			go_http.Error(rsp, "No user", go_http.StatusInternalServerError)
			return
		}

		mfa := acct.MFA

		if mfa == nil {
			go_http.Error(rsp, "MFA not configured", go_http.StatusInternalServerError)
			return
		}

		secret, err := mfa.GetSecret()

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
			return
		}

		vars := TOTPVars{
			PageTitle: "Two-Factor Authentication",
			SigninUrl: totp_auth.options.SigninUrl,
		}

		redir, err := sanitize.RequestString(req, "redir")

		if err == nil {
			vars.Redirect = redir
		}

		switch req.Method {

		case "GET":

			rsp.Header().Set("Content-type", "text/html")

			err := templates.ExecuteTemplate(rsp, t_name, vars)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			return

		case "POST":

			str_code, err := sanitize.PostString(req, "code")

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusBadRequest)
				return
			}

			valid := totp.Validate(str_code, secret)

			if !valid {

				rsp.Header().Set("Content-type", "text/html")

				vars.Error = errors.New("Invalid code")
				err := templates.ExecuteTemplate(rsp, t_name, vars)

				if err != nil {
					go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
					return
				}

				return
			}

			now := time.Now()
			ts := now.Unix()

			mfa.LastAuth = ts
			acct.MFA = mfa

			acct, err = totp_auth.account_db.UpdateAccount(acct)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			totp_cookie, err := totp_auth.newTOTPCookie()

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			totp_auth.setTOTPCookie(rsp, req, totp_cookie)

			req = auth.SetAccountContext(req, acct)
			next.ServeHTTP(rsp, req)
			return

		default:
			go_http.Error(rsp, "Unsupported method", go_http.StatusMethodNotAllowed)
			return
		}
	}

	return go_http.HandlerFunc(fn)
}

func (totp_auth *TOTPCredentials) SignupHandler(templates *template.Template, t_name string, next go_http.Handler) go_http.Handler {
	return auth.NotImplementedHandler()
}

func (totp_auth *TOTPCredentials) SignoutHandler(templates *template.Template, t_name string, next go_http.Handler) go_http.Handler {
	return auth.NotImplementedHandler()
}

func (totp_auth *TOTPCredentials) GetAccountForRequest(req *go_http.Request) (*account.Account, error) {
	return auth.GetAccountContext(req)
}

func (totp_auth *TOTPCredentials) newTOTPCookie() (cookie.Cookie, error) {
	ctx := context.Background()
	return cookie.NewCookie(ctx, totp_auth.options.CookieURI)
}

func (totp_auth *TOTPCredentials) setTOTPCookie(rsp go_http.ResponseWriter, req *go_http.Request, totp_cookie cookie.Cookie) error {

	now := time.Now()
	ts := now.Unix()

	ctx, _ := sanitize.GetString(req, "redir")

	if ctx == "" {
		ctx = req.URL.Path
	}

	cookie_str := fmt.Sprintf("%d:%s", ts, ctx)

	// log.Printf("TOTP COOKIE SET '%s'\n", cookie_str)

	raw_cookie := &go_http.Cookie{
		Value:  cookie_str,
		MaxAge: 300,
	}

	return totp_cookie.SetCookie(rsp, raw_cookie)
}

func (totp_auth *TOTPCredentials) isRequestCookie(req *go_http.Request, totp_cookie cookie.Cookie) (bool, error) {

	cookie_str, err := totp_cookie.GetString(req)

	if err != nil {
		return false, err
	}

	// log.Printf("TOTP COOKIE CHECK '%s' (%s)\n", cookie_str, req.URL.Path)

	cookie_parts := strings.Split(cookie_str, ":")

	if len(cookie_parts) != 2 {
		return false, errors.New("Invalid cookie string")
	}

	cookie_url := cookie_parts[1]

	if cookie_url != req.URL.Path {
		return false, nil
	}

	return true, nil
}
