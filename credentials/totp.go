package credentials

import (
	"context"
	"errors"
	"fmt"
	"github.com/aaronland/go-auth"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/database"
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
	CookieURI        string
	CookieName       string
	CookieTTL        int64 // please make this a time.Duration
	AccountsDatabase database.AccountsDatabase
}

func DefaultTOTPCredentialsOptions() *TOTPCredentialsOptions {

	opts := TOTPCredentialsOptions{
		Force:      false,
		SigninUrl:  "/mfa",
		CookieName: "m",
		CookieTTL:  3600,
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

	if opts.CookieName == "" {
		return nil, errors.New("Invalid cookie name")
	}

	if opts.CookieTTL <= 0 {
		return nil, errors.New("Invalid cookie TTL")
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
			log.Println("MFA Is auth, go to next...")
			next.ServeHTTP(rsp, req)
			return
		}

		mfa := acct.MFA

		if mfa == nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		require_code := true

		totp_cookie, err := req.Cookie(totp_auth.options.CookieName)

		if totp_cookie != nil {

			require_code = false

			/*
						/*
						// check to see if we've already auth-ed on this page
						// in the last (n) seconds

						if totp_auth.options.Force {

							cookie_str := ck.Value

				cookie_parts := strings.Split(cookie_str, ":")

				if len(cookie_parts) != 2 {
					return false, errors.New("Invalid cookie string")
				}

				cookie_url := cookie_parts[1]

				if cookie_url != req.URL.Path {
					return false, nil
				}

							ok, _ := totp_auth.isRequestCookie(req, totp_cookie)

							if ok {
								require_code = false
							}
						}

					} else {

						_, err := totp_cookie.Get(req)

						if err == nil {

						now := time.Now()
						diff := now.Unix() - mfa.LastAuth

						if diff < totp_auth.options.TTL {
							require_code = false
						}
					}
				}
			*/
		}

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

			expires := ts + totp_auth.options.CookieTTL
			t_expires := time.Unix(expires, 0)

			ck := &http.Cookie{
				Name:     totp_auth.options.CookieName,
				Value:    "mfa",
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
				Expires:  t_expires,
				// Domain:
				// Path:
			}

			if ck.String() == "" {
				http.Error(rsp, "Invalid cookie", http.StatusInternalServerError)
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

	return http.HandlerFunc(fn)
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
