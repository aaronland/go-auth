package www

import (
	_ "context"
	"errors"
	"fmt"
	"github.com/aaronland/go-http-auth"
	"github.com/aaronland/go-http-auth/account"
	"github.com/aaronland/go-http-auth/database"
	"github.com/aaronland/go-http-crumb"
	"github.com/aaronland/go-http-sanitize"
	"github.com/pquerna/otp/totp"
	"html/template"
	"log"
	go_http "net/http"
	"time"
)

const CONTEXT_TOTP_KEY string = "totp"
const COOKIE_TOTP_CRUMB string = "crumb"

type TOTPAuthenticatorOptions struct {
	TTL       int64 // please make this a time.Duration...
	Force     bool
	SigninUrl string
}

func DefaultTOTPAuthenticatorOptions() *TOTPAuthenticatorOptions {

	opts := TOTPAuthenticatorOptions{
		TTL:       3600,
		Force:     false,
		SigninUrl: "/mfa",
	}

	return &opts
}

type TOTPAuthenticator struct {
	auth.HTTPAuthenticator
	account_db   database.AccountDatabase
	options      *TOTPAuthenticatorOptions
	crumb_config *crumb.CrumbConfig
}

func NewTOTPAuthenticator(db database.AccountDatabase, opts *TOTPAuthenticatorOptions) (auth.HTTPAuthenticator, error) {

	crumb_cfg, err := NewCrumbConfig()

	if err != nil {
		return nil, err
	}

	crumb_cfg.TTL = 120

	totp_auth := TOTPAuthenticator{
		account_db:   db,
		options:      opts,
		crumb_config: crumb_cfg,
	}

	return &totp_auth, nil
}

func (totp_auth *TOTPAuthenticator) AuthHandler(next go_http.Handler) go_http.Handler {

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		log.Println("TOTP", "AUTH", "CHECK")

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
		log.Println("TOTP REQUIRE", require_code, req.URL.Path)

		if totp_auth.options.Force {

			crumb_cookie, err := req.Cookie(COOKIE_TOTP_CRUMB)

			if err == nil {

				crumb_var := crumb_cookie.Value

				log.Println("TOTP", "CRUMB", "VALIDATE", crumb_var)

				ok, err := crumb.ValidateCrumb(totp_auth.crumb_config, req, crumb_var)

				log.Println("TOTP", "CRUMB", "RESULT", err)

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

		log.Println("TOTP", "AUTH", "REQUIRE", require_code)

		if require_code {

			redir_url := fmt.Sprintf("%s?redir=%s", totp_auth.options.SigninUrl, req.URL.Path)
			log.Println("TOTP", "AUTH", "REDIRECT", redir_url)

			go_http.Redirect(rsp, req, redir_url, 303)
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

			if totp_auth.options.Force {

				crumb_var, err := crumb.GenerateCrumb(totp_auth.crumb_config, req)

				log.Println("CRUMB", "SET", crumb_var)

				if err != nil {
					go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
					return
				}

				crumb_cookie := go_http.Cookie{
					Name:   COOKIE_TOTP_CRUMB,
					Value:  crumb_var,
					MaxAge: int(totp_auth.crumb_config.TTL) - 1,
				}

				go_http.SetCookie(rsp, &crumb_cookie)
			}

			req = auth.SetAccountContext(req, acct)

			log.Println("TOTP", "OKAY", "NEXT")
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
