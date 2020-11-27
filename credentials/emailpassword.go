package credentials

import (
	"context"
	"errors"
	"github.com/aaronland/go-auth"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/cookie"
	"github.com/aaronland/go-auth/database"
	"github.com/aaronland/go-auth/session"
	"github.com/aaronland/go-http-crumb"
	"github.com/aaronland/go-http-sanitize"
	"github.com/sfomuseum/logger"
	"html/template"
	"log"
	"net/http"
	"time"
)

type EmailPasswordCredentialsOptions struct {
	RootURL             string
	SigninURL           string
	SignupURL           string
	SignoutURL          string
	SessionCookieConfig *cookie.Config
	Crumb               crumb.Crumb
	AccountsDatabase    database.AccountsDatabase
	SessionsDatabase    database.SessionsDatabase
	Logger              *logger.Logger
}

func DefaultEmailPasswordCredentialsOptions() *EmailPasswordCredentialsOptions {

	opts := EmailPasswordCredentialsOptions{
		RootURL:    "/",
		SigninURL:  "/signin",
		SignupURL:  "/signup",
		SignoutURL: "/signout",
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

	if opts.SessionCookieConfig == nil {
		return nil, errors.New("Missing session cookie config")
	}

	if opts.SessionCookieConfig.TTL == nil {
		return nil, errors.New("Missing session cookie TTL")
	}

	ep_auth := EmailPasswordCredentials{
		options: opts,
	}

	return &ep_auth, nil
}

func (ep_auth *EmailPasswordCredentials) AppendCredentialsHandler(prev http.Handler) http.Handler {
	return auth.NotImplementedHandler()
}

func (ep_auth *EmailPasswordCredentials) AuthHandler(next http.Handler) http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		ep_auth.log("EP Auth handler %s (%s)", req.URL.Path, req.Method)

		acct, err := ep_auth.GetAccountForRequest(req)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		if acct == nil {

			ep_auth.log("EP no account, redirect to %s", ep_auth.options.SigninURL)
			http.Redirect(rsp, req, ep_auth.options.SigninURL, 303)
			return
		}

		ep_auth.log("EP set account context")
		req = auth.SetAccountContext(req, acct)

		ep_auth.log("EP go to next %v", next)
		next.ServeHTTP(rsp, req)
	}

	return http.HandlerFunc(fn)
}

func (ep_auth *EmailPasswordCredentials) SigninHandler(templates *template.Template, t_name string, next http.Handler) http.Handler {

	type SigninVars struct {
		PageTitle string
		SigninURL string
		SignupURL string
		Error     error
	}

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		ep_auth.log("EP sign in URL %s", req.URL.Path)

		ok, err := auth.IsAuthenticated(ep_auth, req)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
		}

		ep_auth.log("EP is auth: %v, %v", ok, err)

		if ok {

			ep_auth.log("EP is auth, go to next %v", next)
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
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			return

		case "POST":

			str_email, err := sanitize.PostString(req, "email")

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusBadRequest)
				return
			}

			str_password, err := sanitize.PostString(req, "password")

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusBadRequest)
				return
			}

			acct_db := ep_auth.options.AccountsDatabase

			acct, err := acct_db.GetAccountByEmailAddress(str_email)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			if !acct.IsActive() {
				http.Error(rsp, "Invalid user", http.StatusBadRequest)
				return
			}

			p, err := acct.GetPassword()

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			err = p.Compare(str_password)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			err = ep_auth.SetAccountForResponse(rsp, acct)

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
	//return signin_handler

	return crumb.EnsureCrumbHandler(ep_auth.options.Crumb, signin_handler)
}

func (ep_auth *EmailPasswordCredentials) SignupHandler(templates *template.Template, t_name string, next http.Handler) http.Handler {

	type SignupVars struct {
		PageTitle string
		SigninURL string
		SignupURL string
		Error     error
	}

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		ok, err := auth.IsAuthenticated(ep_auth, req)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
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
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			return

		case "POST":

			str_email, err := sanitize.PostString(req, "email")

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusBadRequest)
				return
			}

			str_username, err := sanitize.PostString(req, "username")

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusBadRequest)
				return
			}

			str_password, err := sanitize.PostString(req, "password")

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusBadRequest)
				return
			}

			acct, err := account.NewAccount(str_email, str_password, str_username)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			acct_db := ep_auth.options.AccountsDatabase

			acct, err = acct_db.AddAccount(acct)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			err = ep_auth.SetAccountForResponse(rsp, acct)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			next.ServeHTTP(rsp, req)
			return

		default:
			http.Error(rsp, "Unsupported method", http.StatusMethodNotAllowed)
			return
		}
	}

	signup_handler := http.HandlerFunc(fn)

	return crumb.EnsureCrumbHandler(ep_auth.options.Crumb, signup_handler)
}

func (ep_auth *EmailPasswordCredentials) SignoutHandler(templates *template.Template, t_name string, next http.Handler) http.Handler {

	type SignoutVars struct {
		PageTitle  string
		Error      error
		SignoutURL string
	}

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		ep_auth.log("EP signout handler %s (%s)", req.URL.Path, req.Method)

		ok, err := auth.IsAuthenticated(ep_auth, req)

		ep_auth.log("EP signout handler is auth %v, %v", ok, err)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
		}

		if !ok {

			ep_auth.log("EP signout handler not auth, go to next")
			next.ServeHTTP(rsp, req)
			return
		}

		vars := SignoutVars{
			PageTitle:  "Sign out",
			SignoutURL: ep_auth.options.SignoutURL,
		}

		switch req.Method {

		case "GET":

			ep_auth.log("EP signout handler GET")

			rsp.Header().Set("Content-type", "text/html")

			err := templates.ExecuteTemplate(rsp, t_name, vars)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			return

		case "POST":

			ep_auth.log("EP signout handler POST")

			ck := http.Cookie{
				Name:   ep_auth.options.SessionCookieConfig.Name,
				Value:  "",
				MaxAge: -1,
			}

			// FIX ME: COOKIE IS NOT BEING REMOVED?

			ep_auth.log("EP signout handler remove cookie '%s'", ep_auth.options.SessionCookieConfig.Name)
			http.SetCookie(rsp, &ck)

			ep_auth.log("EP signout handler go to next, %v", next)			
			next.ServeHTTP(rsp, req)
			return

		default:
			http.Error(rsp, "Unsupported method", http.StatusMethodNotAllowed)
			return
		}
	}

	signout_handler := http.HandlerFunc(fn)

	return crumb.EnsureCrumbHandler(ep_auth.options.Crumb, signout_handler)
}

func (ep_auth *EmailPasswordCredentials) GetAccountForRequest(req *http.Request) (*account.Account, error) {

	ep_auth.log("EP Auth handler get account %s", req.URL.Path)

	ctx := req.Context()

	ck, err := req.Cookie(ep_auth.options.SessionCookieConfig.Name)

	ep_auth.log("EP Auth handler get account cookie %v, %v", ep_auth.options.SessionCookieConfig.Name, ck)

	if err != nil {

		if err == http.ErrNoCookie {
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

	ep_auth.log("EP Auth handler get account return %s", "ACCT")
	return acct, nil
}

func (ep_auth *EmailPasswordCredentials) SetAccountForResponse(rsp http.ResponseWriter, acct *account.Account) error {

	ctx := context.Background()

	ttl := ep_auth.options.SessionCookieConfig.TTL

	if ttl == nil {
		return errors.New("Invalid cookie TTL")
	}

	now := time.Now()
	then := ttl.Shift(now)

	diff := then.Sub(now)
	session_ttl := int64(diff.Seconds())

	sessions_db := ep_auth.options.SessionsDatabase

	sess, err := database.NewSessionRecord(ctx, sessions_db, session_ttl)

	if err != nil {
		return err
	}

	sess.AccountId = acct.ID

	err = sessions_db.UpdateSession(ctx, sess)

	if err != nil {
		return err
	}

	ck, err := ep_auth.options.SessionCookieConfig.NewCookie(ctx, sess.SessionId)

	if err != nil {
		return err
	}

	http.SetCookie(rsp, ck)
	return nil
}

func (ep_auth *EmailPasswordCredentials) log(msg string, args ...interface{}) {

	if ep_auth.options.Logger != nil {
		ep_auth.options.Logger.Printf(msg, args...)
		return
	}

	log.Printf(msg, args...)
}
