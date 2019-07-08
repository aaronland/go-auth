package www

import (
	"errors"
	"github.com/aaronland/go-http-auth"
	"github.com/aaronland/go-http-auth/account"
	"github.com/aaronland/go-http-auth/database"
	"github.com/aaronland/go-http-sanitize"
	"github.com/pquerna/otp/totp"
	"html/template"
	"log"
	go_http "net/http"
	"time"
)

func NewTOTPRedirectHandler(totp_uri string) go_http.Handler {

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {
		go_http.Redirect(rsp, req, totp_uri, 303)
		return
	}

	return go_http.HandlerFunc(fn)
}

type TOTPAuthenticatorOptions struct {
	TTL       int64 // please make this a time.Duration...
	SigninUrl string
}

func DefaultTOTPAuthenticatorOptions() *TOTPAuthenticatorOptions {

	opts := TOTPAuthenticatorOptions{
		TTL:       3600,
		SigninUrl: "/mfa",
	}

	return &opts
}

type TOTPAuthenticator struct {
	auth.HTTPAuthenticator
	account_db database.AccountDatabase
	options    *TOTPAuthenticatorOptions
}

func NewTOTPAuthenticator(db database.AccountDatabase, opts *TOTPAuthenticatorOptions) (auth.HTTPAuthenticator, error) {

	totp_auth := TOTPAuthenticator{
		account_db: db,
		options:    opts,
	}

	return &totp_auth, nil
}

func (totp_auth *TOTPAuthenticator) AuthHandler(next go_http.Handler) go_http.Handler {

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		// this will not work when the user hits "submit" because we lose
		// the current context and we need to read from the cookie again...

		acct, err := totp_auth.GetAccountForRequest(req)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
			return
		}

		if acct == nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
			return
		}

		mfa := acct.MFA

		if mfa == nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
			return
		}

		require_code := true

		now := time.Now()

		if now.Unix()-mfa.LastAuth > totp_auth.options.TTL {
			require_code = true
		}

		if require_code {
			go_http.Redirect(rsp, req, totp_auth.options.SigninUrl, 303) // FIX ME...
			return
		}

		req = auth.SetAccountContext(req, acct)
		next.ServeHTTP(rsp, req)
	}

	return go_http.HandlerFunc(fn)
}

func (totp_auth *TOTPAuthenticator) SigninHandler(templates *template.Template, t_name string, next go_http.Handler) go_http.Handler {

	type TOTPVars struct {
		PageTitle string
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

		log.Println("SECRET", err)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
			return
		}

		vars := TOTPVars{
			PageTitle: "Two-Factor Authentication",
		}

		switch req.Method {

		case "GET":

		log.Println("TOTP GET")

			err := templates.ExecuteTemplate(rsp, t_name, vars)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			return

		case "POST":

		log.Println("TOTP POST")

			str_code, err := sanitize.PostString(req, "code")

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusBadRequest)
				return
			}

			valid := totp.Validate(str_code, secret)

			if !valid {

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

func (totp_auth *TOTPAuthenticator) SignupHandler(templates *template.Template, t_name string, next go_http.Handler) go_http.Handler {
	return auth.NotImplementedHandler()
}

func (totp_auth *TOTPAuthenticator) SignoutHandler(templates *template.Template, t_name string, next go_http.Handler) go_http.Handler {
	return auth.NotImplementedHandler()
}

func (totp_auth *TOTPAuthenticator) GetAccountForRequest(req *go_http.Request) (*account.Account, error) {
	return auth.GetAccountContext(req)
}
