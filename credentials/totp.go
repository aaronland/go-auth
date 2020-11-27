package credentials

import (
	"context"
	"errors"
	"fmt"
	"github.com/aaronland/go-auth"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/cookie"
	"github.com/aaronland/go-auth/database"
	"github.com/aaronland/go-auth/session"
	"github.com/aaronland/go-http-crumb"
	"github.com/aaronland/go-http-sanitize"
	"github.com/pquerna/otp/totp"
	"github.com/sfomuseum/logger"
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
	SessionsDatabase database.SessionsDatabase
	Crumb            crumb.Crumb
	Logger           *logger.Logger
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

	if opts.SessionsDatabase == nil {
		return nil, errors.New("Missing sessions database")
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

		totp_auth.log("MFA Auth Handler %s", req.URL.Path)

		acct, err := totp_auth.GetAccountForRequest(req)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		if acct == nil {
			totp_auth.log("MFA missing account, go to signin")
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

		totp_auth.log("MFA cookie %v", totp_cookie)
		
		if totp_cookie != nil {

			sessions_db := totp_auth.options.SessionsDatabase

			session_id := totp_cookie.Value
			ctx := req.Context()

			sess, err := sessions_db.GetSessionWithId(ctx, session_id)

			if err == nil && !session.IsExpired(sess) {
				require_code = false
			}
		}

		if require_code {
			totp_auth.log("MFA require code, redirect to '%s'", totp_auth.options.SigninUrl)
			redir_url := fmt.Sprintf("%s?redir=%s", totp_auth.options.SigninUrl, req.URL.Path)
			http.Redirect(rsp, req, redir_url, 303)
			return
		}

		totp_auth.log("MFA set auth context")
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

		totp_auth.log("MFA sign in handler %s", req.URL.Path)

		acct, err := auth.GetAccountContext(req)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		if acct == nil {
			http.Redirect(rsp, req, "/signin", 303)
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

			// is this bit (updating accounts) really necessary?

			now := time.Now()
			ts := now.Unix()

			mfa.LastAuth = ts
			acct.MFA = mfa

			accounts_db := totp_auth.options.AccountsDatabase
			acct, err = accounts_db.UpdateAccount(acct)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			err = totp_auth.SetAccountForResponse(rsp, acct)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

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

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		totp_auth.log("MFA Signout Handler %s (%s)", req.URL.Path, req.Method)

		acct, err := totp_auth.GetAccountForRequest(req)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		if acct == nil {
			totp_auth.log("No account, go to /signout")
			http.Redirect(rsp, req, "/signout", 303)
			return
		}

		totp_cookie, err := req.Cookie(totp_auth.options.TOTPCookieConfig.Name)

		totp_auth.log("MFA signout cookie %v (%s)", totp_cookie, totp_auth.options.TOTPCookieConfig.Name)

		if totp_cookie != nil {

			totp_auth.log("MFA WTF HEADER %s", rsp.Header())

			/*
			ck := &http.Cookie{
				Name:   totp_auth.options.TOTPCookieConfig.Name,
				Value:  "m",
				MaxAge: -1,
			}
			*/

			ctx := req.Context()
			ck, err := totp_auth.options.TOTPCookieConfig.NewCookie(ctx, "")
			
			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
			}

			now := time.Now()
			then := now. AddDate(0, -1, -1)
			
			ck.Expires = then
			ck.MaxAge = int(then.Unix())
			
			totp_auth.log("MFA signout cookie remove")
			http.SetCookie(rsp, ck)

			totp_auth.log("MFA WTF HEADER 2 %s", rsp.Header())
		}

		next.ServeHTTP(rsp, req)
	}

	// crumb?

	signout_handler := http.HandlerFunc(fn)
	return signout_handler
}

func (totp_auth *TOTPCredentials) GetAccountForRequest(req *http.Request) (*account.Account, error) {
	return auth.GetAccountContext(req)
}

func (totp_auth *TOTPCredentials) SetAccountForResponse(rsp http.ResponseWriter, acct *account.Account) error {

	ctx := context.Background()

	ttl := totp_auth.options.TOTPCookieConfig.TTL

	if ttl == nil {
		return errors.New("Invalid cookie TTL")
	}

	now := time.Now()
	then := ttl.Shift(now)

	diff := then.Sub(now)
	session_ttl := int64(diff.Seconds())

	sessions_db := totp_auth.options.SessionsDatabase

	sess, err := database.NewSessionRecord(ctx, sessions_db, session_ttl)

	if err != nil {
		return err
	}

	ck, err := totp_auth.options.TOTPCookieConfig.NewCookie(ctx, sess.SessionId)

	if err != nil {
		return err
	}

	http.SetCookie(rsp, ck)
	return nil
}

func (totp_auth *TOTPCredentials) log(msg string, args ...interface{}) {

	if totp_auth.options.Logger != nil {
		totp_auth.options.Logger.Printf(msg, args...)
		return
	}

	log.Printf(msg, args...)
}
