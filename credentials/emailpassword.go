package credentials

import (
	"errors"
	"fmt"
	"github.com/aaronland/go-auth"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/database"
	"github.com/aaronland/go-http-cookie"
	"github.com/aaronland/go-http-crumb"
	"github.com/aaronland/go-http-sanitize"
	"html/template"
	_ "log"
	go_http "net/http"
	"strconv"
	"strings"
)

type EmailPasswordCredentialsOptions struct {
	RootURL      string
	SigninURL    string
	SignupURL    string
	SignoutURL   string
	CookieName   string
	CookieSecret string
	CookieSalt   string
	CrumbConfig  *crumb.CrumbConfig
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
	account_db database.AccountsDatabase
	options    *EmailPasswordCredentialsOptions
}

func NewEmailPasswordCredentials(db database.AccountsDatabase, opts *EmailPasswordCredentialsOptions) (auth.Credentials, error) {

	ep_auth := EmailPasswordCredentials{
		account_db: db,
		options:    opts,
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

			acct, err := ep_auth.account_db.GetAccountByEmailAddress(str_email)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
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

			err = ep_auth.setAuthCookie(rsp, acct)

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

	return crumb.EnsureCrumbHandler(ep_auth.options.CrumbConfig, signin_handler)
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

			acct, err = ep_auth.account_db.AddAccount(acct)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			err = ep_auth.setAuthCookie(rsp, acct)

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

	return crumb.EnsureCrumbHandler(ep_auth.options.CrumbConfig, signup_handler)
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

			ck, err := ep_auth.newAuthCookie()

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			err = ck.Delete(rsp)

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

	signout_handler := go_http.HandlerFunc(fn)

	return crumb.EnsureCrumbHandler(ep_auth.options.CrumbConfig, signout_handler)
}

func (ep_auth *EmailPasswordCredentials) GetAccountForRequest(req *go_http.Request) (*account.Account, error) {

	ck, err := ep_auth.newAuthCookie()

	if err != nil {
		return nil, err
	}

	body, err := ck.Get(req)

	if err != nil && err == go_http.ErrNoCookie {
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	// WRAP THIS IN A FUNCTION

	parts := strings.Split(body, ":")

	if len(parts) != 2 {
		return nil, errors.New("Invalid cookie")
	}

	str_id := parts[0]
	pswd := parts[1]

	id, err := strconv.ParseInt(str_id, 10, 64)

	if err != nil {
		return nil, err
	}

	acct, err := ep_auth.account_db.GetAccountByID(id)

	if err != nil {
		return nil, err
	}

	p, err := acct.GetPassword()

	if p.Digest() != pswd {
		return nil, errors.New("Invalid user")
	}

	if !acct.IsActive() {
		return nil, errors.New("User is not active")
	}

	return acct, nil
}

func (ep_auth *EmailPasswordCredentials) SetAccountForResponse(rsp go_http.ResponseWriter, acct *account.Account) error {

	return ep_auth.setAuthCookie(rsp, acct)
}

func (ep_auth *EmailPasswordCredentials) newAuthCookie() (cookie.Cookie, error) {

	return cookie.NewAuthCookie(ep_auth.options.CookieName, ep_auth.options.CookieSecret, ep_auth.options.CookieSalt)
}

func (ep_auth *EmailPasswordCredentials) setAuthCookie(rsp go_http.ResponseWriter, acct *account.Account) error {

	p, err := acct.GetPassword()

	if err != nil {
		return err
	}

	ck, err := ep_auth.newAuthCookie()

	if err != nil {
		return err
	}

	cookie_str := fmt.Sprintf("%d:%s", acct.ID, p.Digest()) // WRAP THIS IN A FUNCTION

	raw_cookie := &go_http.Cookie{
		Value:    cookie_str,
		Secure:   true,
		SameSite: go_http.SameSiteLaxMode,
		Path:     "/",
	}

	return ck.SetCookie(rsp, raw_cookie)
}
