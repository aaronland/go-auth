package credentials

import (
	"context"
	"errors"
	"github.com/aaronland/go-auth"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/database"
	"github.com/aaronland/go-auth/session"
	"github.com/aaronland/go-http-crumb"
	"github.com/aaronland/go-http-sanitize"
	"html/template"
	go_http "net/http"
	"time"
)

type EmailPasswordCredentialsOptions struct {
	RootURL           string
	SigninURL         string
	SignupURL         string
	SignoutURL        string
	CookieURI         string // deprecated
	SessionCookieName string
	SessionCookieTTL  int64
	Crumb             crumb.Crumb
	AccountsDatabase  database.AccountsDatabase
	SessionsDatabase  database.SessionsDatabase
}

func DefaultEmailPasswordCredentialsOptions() *EmailPasswordCredentialsOptions {

	opts := EmailPasswordCredentialsOptions{
		RootURL:           "/",
		SigninURL:         "/signin",
		SignupURL:         "/signup",
		SignoutURL:        "/signout",
		SessionCookieName: "s",
		SessionCookieTTL:  3600,
	}

	return &opts
}

type EmailPasswordCredentials struct {
	auth.Credentials
	options *EmailPasswordCredentialsOptions
}

func NewEmailPasswordCredentials(ctx context.Context, opts *EmailPasswordCredentialsOptions) (auth.Credentials, error) {

	if opts.AccountsDatabase == nil {
		return nil, errors.New("Missing accounts database")
	}

	if opts.SessionsDatabase == nil {
		return nil, errors.New("Missing sessions database")
	}

	if opts.SessionCookieName == "" {
		return nil, errors.New("Invalid session cookie name")
	}

	if opts.SessionCookieTTL <= 0 {
		return nil, errors.New("Invalid session cookie TTL")
	}

	ep_auth := EmailPasswordCredentials{
		options: opts,
	}

	return &ep_auth, nil
}

func (ep_auth *EmailPasswordCredentials) AppendCredentialsHandler(prev go_http.Handler) go_http.Handler {
	return auth.NotImplementedHandler()
}

func (ep_auth *EmailPasswordCredentials) AuthHandler(next go_http.Handler) go_http.Handler {

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		acct, err := ep_auth.GetAccountForRequest(req)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
			return
		}

		if acct == nil {
			go_http.Redirect(rsp, req, ep_auth.options.SigninURL, 303)
			return
		}

		req = auth.SetAccountContext(req, acct)
		next.ServeHTTP(rsp, req)
	}

	return go_http.HandlerFunc(fn)
}

func (ep_auth *EmailPasswordCredentials) SigninHandler(templates *template.Template, t_name string, next go_http.Handler) go_http.Handler {

	type SigninVars struct {
		PageTitle string
		SigninURL string
		SignupURL string
		Error     error
	}

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		ok, err := auth.IsAuthenticated(ep_auth, req)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
		}

		if ok {
			// go_http.Redirect(rsp, req, ep_auth.options.RootURL, 303) // check for ?redir=
			next.ServeHTTP(rsp, req)
			return
		}

		switch req.Method {

		case "GET":

			vars := SigninVars{
				PageTitle: "Sign in",
				SigninURL: ep_auth.options.SigninURL,
				SignupURL: ep_auth.options.SignupURL,
			}

			rsp.Header().Set("Content-type", "text/html")

			err := templates.ExecuteTemplate(rsp, t_name, vars)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			return

		case "POST":

			str_email, err := sanitize.PostString(req, "email")

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusBadRequest)
				return
			}

			str_password, err := sanitize.PostString(req, "password")

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusBadRequest)
				return
			}

			acct_db := ep_auth.options.AccountsDatabase

			acct, err := acct_db.GetAccountByEmailAddress(str_email)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			if !acct.IsActive() {
				go_http.Error(rsp, "Invalid user", go_http.StatusBadRequest)
				return
			}

			p, err := acct.GetPassword()

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			err = p.Compare(str_password)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			err = ep_auth.SetAccountForResponse(rsp, acct)

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

	signin_handler := go_http.HandlerFunc(fn)

	return crumb.EnsureCrumbHandler(ep_auth.options.Crumb, signin_handler)
}

func (ep_auth *EmailPasswordCredentials) SignupHandler(templates *template.Template, t_name string, next go_http.Handler) go_http.Handler {

	type SignupVars struct {
		PageTitle string
		SigninURL string
		SignupURL string
		Error     error
	}

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		ok, err := auth.IsAuthenticated(ep_auth, req)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
		}

		if ok {
			next.ServeHTTP(rsp, req)
			return
		}

		vars := SignupVars{
			PageTitle: "Sign up",
			SigninURL: ep_auth.options.SigninURL,
			SignupURL: ep_auth.options.SignupURL,
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

			str_email, err := sanitize.PostString(req, "email")

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusBadRequest)
				return
			}

			str_username, err := sanitize.PostString(req, "username")

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusBadRequest)
				return
			}

			str_password, err := sanitize.PostString(req, "password")

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusBadRequest)
				return
			}

			acct, err := account.NewAccount(str_email, str_password, str_username)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			acct_db := ep_auth.options.AccountsDatabase

			acct, err = acct_db.AddAccount(acct)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			err = ep_auth.SetAccountForResponse(rsp, acct)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			next.ServeHTTP(rsp, req)
			return

		default:
			go_http.Error(rsp, "Unsupported method", go_http.StatusMethodNotAllowed)
			return
		}
	}

	signup_handler := go_http.HandlerFunc(fn)

	return crumb.EnsureCrumbHandler(ep_auth.options.Crumb, signup_handler)
}

func (ep_auth *EmailPasswordCredentials) SignoutHandler(templates *template.Template, t_name string, next go_http.Handler) go_http.Handler {

	type SignoutVars struct {
		PageTitle  string
		Error      error
		SignoutURL string
	}

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		ok, err := auth.IsAuthenticated(ep_auth, req)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
		}

		if !ok {
			next.ServeHTTP(rsp, req)
			return
		}

		vars := SignoutVars{
			PageTitle:  "Sign out",
			SignoutURL: ep_auth.options.SignoutURL,
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

			ck := go_http.Cookie{
				Name:   ep_auth.options.SessionCookieName,
				Value:  "",
				MaxAge: -1,
			}

			go_http.SetCookie(rsp, &ck)

			next.ServeHTTP(rsp, req)
			return

		default:
			go_http.Error(rsp, "Unsupported method", go_http.StatusMethodNotAllowed)
			return
		}
	}

	signout_handler := go_http.HandlerFunc(fn)

	return crumb.EnsureCrumbHandler(ep_auth.options.Crumb, signout_handler)
}

func (ep_auth *EmailPasswordCredentials) GetAccountForRequest(req *go_http.Request) (*account.Account, error) {

	ctx := req.Context()

	ck, err := req.Cookie(ep_auth.options.SessionCookieName)

	if err != nil {

		if err == go_http.ErrNoCookie {
			return nil, nil
		}

		return nil, err
	}

	session_id := ck.Value

	sessions_db := ep_auth.options.SessionsDatabase
	accounts_db := ep_auth.options.AccountsDatabase

	sess, err := sessions_db.GetSessionWithId(ctx, session_id)

	if err != nil {
		return nil, err
	}

	if session.IsExpired(sess) {
		return nil, errors.New("Session expired")
	}

	account_id := sess.AccountId

	acct, err := accounts_db.GetAccountByID(account_id)

	if err != nil {
		return nil, err
	}

	if !acct.IsActive() {
		return nil, errors.New("User is not active")
	}

	return acct, nil
}

func (ep_auth *EmailPasswordCredentials) SetAccountForResponse(rsp go_http.ResponseWriter, acct *account.Account) error {

	ctx := context.Background()

	sessions_db := ep_auth.options.SessionsDatabase

	sess, err := database.NewSessionRecord(ctx, sessions_db, ep_auth.options.SessionCookieTTL)

	if err != nil {
		return err
	}

	sess.AccountId = acct.ID

	err = sessions_db.UpdateSession(ctx, sess)

	if err != nil {
		return err
	}

	t_expires := time.Unix(sess.Expires, 0)

	ck := &go_http.Cookie{
		Name:     ep_auth.options.SessionCookieName,
		Value:    sess.SessionId,
		Secure:   true,
		SameSite: go_http.SameSiteLaxMode,
		Expires:  t_expires,
		// Domain:
		// Path:
	}

	if ck.String() == "" {
		return errors.New("Invalid cookie")
	}

	go_http.SetCookie(rsp, ck)
	return nil
}
