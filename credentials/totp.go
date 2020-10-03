package credentials

import (
	"context"
	"errors"
	"fmt"
	"github.com/aaronland/go-auth"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/cookie"
	"github.com/aaronland/go-auth/database"
	"github.com/aaronland/go-http-crumb"
	"github.com/aaronland/go-http-sanitize"
	"github.com/pquerna/otp/totp"
	"html/template"
	"log"
	"net/http"
	"time"
)

type TOTPCredentialsOptions struct {
	Force            bool
	SigninUrl        string
	TOTPCookieConfig *cookie.Config
	AccountsDatabase database.AccountsDatabase
	Crumb            crumb.Crumb
}

func DefaultTOTPCredentialsOptions() *TOTPCredentialsOptions {

	opts := TOTPCredentialsOptions{
		Force:     false,
		SigninUrl: "/mfa",
	}

	return &opts
}

type TOTPCredentials struct {
	auth.Credentials
	options *TOTPCredentialsOptions
}

func NewTOTPCredentials(ctx context.Context, opts *TOTPCredentialsOptions) (auth.Credentials, error) {

	if opts.AccountsDatabase == nil {
		return nil, errors.New("Missing accounts database")
	}

	if opts.TOTPCookieConfig == nil {
		return nil, errors.New("Missing session cookie config")
	}

	if opts.TOTPCookieConfig.TTL == nil {
		return nil, errors.New("Missing session cookie TTL")
	}

	if opts.Crumb == nil {
		return nil, errors.New("Missing crumb")
	}

	totp_auth := TOTPCredentials{
		options: opts,
	}

	return &totp_auth, nil
}

func (totp_auth *TOTPCredentials) AuthHandler(next http.Handler) http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		log.Println("MFA Auth Handler")

		acct, err := totp_auth.GetAccountForRequest(req)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		if acct == nil {

			log.Println("MFA missing account, go to signin")
			http.Redirect(rsp, req, "/signin", 303)
			return
		}

		mfa := acct.MFA

		if mfa == nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		require_code := true

		totp_cookie, err := req.Cookie(totp_auth.options.TOTPCookieConfig.Name)

		if totp_cookie != nil {
			require_code = false
		}

		log.Println("MFA require code", require_code, totp_cookie, err)

		if require_code {

			log.Println("MFA require code, redirect to", totp_auth.options.SigninUrl)
			redir_url := fmt.Sprintf("%s?redir=%s", totp_auth.options.SigninUrl, req.URL.Path)
			http.Redirect(rsp, req, redir_url, 303)
			return
		}

		log.Println("MFA set auth context")
		req = auth.SetAccountContext(req, acct)
		next.ServeHTTP(rsp, req)
	}

	return http.HandlerFunc(fn)
}

func (totp_auth *TOTPCredentials) SigninHandler(templates *template.Template, t_name string, next http.Handler) http.Handler {

	type TOTPVars struct {
		PageTitle string
		SigninUrl string
		Redirect  string
		Error     error
	}

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		log.Println("MFA sign in handler")

		acct, err := auth.GetAccountContext(req)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		if acct == nil {
			http.Error(rsp, "No user", http.StatusInternalServerError)
			return
		}

		mfa := acct.MFA

		if mfa == nil {
			http.Error(rsp, "MFA not configured", http.StatusInternalServerError)
			return
		}

		secret, err := mfa.GetSecret()

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
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
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			return

		case "POST":

			str_code, err := sanitize.PostString(req, "code")

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusBadRequest)
				return
			}

			valid := totp.Validate(str_code, secret)

			if !valid {

				rsp.Header().Set("Content-type", "text/html")

				vars.Error = errors.New("Invalid code")
				err := templates.ExecuteTemplate(rsp, t_name, vars)

				if err != nil {
					http.Error(rsp, err.Error(), http.StatusInternalServerError)
					return
				}

				return
			}

			now := time.Now()
			ts := now.Unix()

			// is this bit (updating accounts) really necessary?

			mfa.LastAuth = ts
			acct.MFA = mfa

			accounts_db := totp_auth.options.AccountsDatabase
			acct, err = accounts_db.UpdateAccount(acct)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			ctx := req.Context()
			ck, err := totp_auth.options.TOTPCookieConfig.NewCookie(ctx, "mfa")

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			http.SetCookie(rsp, ck)

			req = auth.SetAccountContext(req, acct)
			next.ServeHTTP(rsp, req)
			return

		default:
			http.Error(rsp, "Unsupported method", http.StatusMethodNotAllowed)
			return
		}
	}

	signin_handler := http.HandlerFunc(fn)

	return crumb.EnsureCrumbHandler(totp_auth.options.Crumb, signin_handler)
}

func (totp_auth *TOTPCredentials) SignupHandler(templates *template.Template, t_name string, next http.Handler) http.Handler {
	return auth.NotImplementedHandler()
}

func (totp_auth *TOTPCredentials) SignoutHandler(templates *template.Template, t_name string, next http.Handler) http.Handler {
	return auth.NotImplementedHandler()
}

func (totp_auth *TOTPCredentials) GetAccountForRequest(req *http.Request) (*account.Account, error) {
	return auth.GetAccountContext(req)
}
