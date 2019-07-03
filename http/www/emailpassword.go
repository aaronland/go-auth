package www

import (
	"errors"
	"fmt"
	"github.com/aaronland/go-http-auth/account"
	"github.com/aaronland/go-http-auth/database"
	"github.com/aaronland/go-http-auth/http"
	"github.com/aaronland/go-http-cookie"
	"github.com/aaronland/go-http-sanitize"
	"html/template"
	_ "log"
	go_http "net/http"
	"strings"
)

type EmailPasswordAuthenticatorOptions struct {
	RootURL      string
	SigninURL    string
	SignupURL    string
	SignoutURL   string
	CookieName   string
	CookieSecret string
	CookieSalt   string
}

func DefaultEmailPasswordAuthenticatorOptions() *EmailPasswordAuthenticatorOptions {

	opts := EmailPasswordAuthenticatorOptions{
		RootURL:    "/",
		SigninURL:  "/signin",
		SignupURL:  "/signup",
		SignoutURL: "/signout",
	}

	return &opts
}

type EmailPasswordAuthenticator struct {
	http.HTTPAuthenticator
	account_db database.AccountDatabase
	options    *EmailPasswordAuthenticatorOptions
}

func NewEmailPasswordAuthenticator(db database.AccountDatabase, opts *EmailPasswordAuthenticatorOptions) (http.HTTPAuthenticator, error) {

	auth := EmailPasswordAuthenticator{
		account_db: db,
		options:    opts,
	}

	return &auth, nil
}

func (auth *EmailPasswordAuthenticator) AppendCredentialsHandler(prev go_http.Handler) go_http.Handler {
	return http.NotImplementedHandler()
}

func (auth *EmailPasswordAuthenticator) AuthHandler(next go_http.Handler) go_http.Handler {

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		acct, err := auth.GetMembershipForRequest(req)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
			return
		}

		if acct == nil {
			go_http.Redirect(rsp, req, auth.options.SigninURL, 303)
			return
		}

		req = http.SetMembershipContext(req, acct)
		next.ServeHTTP(rsp, req)
	}

	return go_http.HandlerFunc(fn)
}

func (auth *EmailPasswordAuthenticator) SigninHandler(templates *template.Template, t_name string) go_http.Handler {

	type SigninVars struct {
		PageTitle string
		SignupURL string
		Error     error
	}

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		ok, err := http.IsAuthenticated(auth, req)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
		}

		if ok {
			go_http.Redirect(rsp, req, auth.options.RootURL, 303) // check for ?redir=
			return
		}

		switch req.Method {

		case "GET":

			vars := SigninVars{
				PageTitle: "Sign in",
				SignupURL: auth.options.SignupURL,
			}

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

			acct, err := auth.account_db.GetAccountByEmailAddress(str_email)

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

			err = auth.setAuthCookie(rsp, m)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			go_http.Redirect(rsp, req, auth.options.RootURL, 303)
			return

		default:
			go_http.Error(rsp, "Unsupported method", go_http.StatusMethodNotAllowed)
			return
		}
	}

	return go_http.HandlerFunc(fn)
}

func (auth *EmailPasswordAuthenticator) SignupHandler(templates *template.Template, t_name string) go_http.Handler {

	type SignupVars struct {
		PageTitle string
		SigninURL string
		Error     error
	}

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		ok, err := http.IsAuthenticated(auth, req)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
		}

		if ok {
			go_http.Redirect(rsp, req, auth.options.RootURL, 303) // check for ?redir=
			return
		}

		vars := SignupVars{
			PageTitle: "Sign up",
			SigninURL: auth.options.SigninURL,
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

			// FIX ME

			acct, err := membership.NewIndividualMembershipFromStrings(str_email, str_password, str_username)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			err = auth.account_db.AddAccount(acct)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			err = auth.setAuthCookie(rsp, acct)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			// FIX ME: CHECK COOKIE...

			go_http.Redirect(rsp, req, auth.options.RootURL, 303)
			return

		default:
			go_http.Error(rsp, "Unsupported method", go_http.StatusMethodNotAllowed)
			return
		}
	}

	return go_http.HandlerFunc(fn)
}

func (auth *EmailPasswordAuthenticator) SignoutHandler(templates *template.Template, t_name string) go_http.Handler {

	type SignoutVars struct {
		PageTitle string
		Error     error
	}

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		ok, err := http.IsAuthenticated(auth, req)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
		}

		if !ok {
			go_http.Redirect(rsp, req, auth.options.RootURL, 303)
			return
		}

		vars := SignoutVars{
			PageTitle: "Sign out",
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

			ck, err := auth.newAuthCookie()

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			err = ck.Delete(rsp)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			go_http.Redirect(rsp, req, auth.options.RootURL, 303)
			return

		default:
			go_http.Error(rsp, "Unsupported method", go_http.StatusMethodNotAllowed)
			return
		}
	}

	return go_http.HandlerFunc(fn)

}

func (auth *EmailPasswordAuthenticator) GetAccountForRequest(req *go_http.Request) (*account.Account, error) {

	ck, err := auth.newAuthCookie()

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

	id := parts[0]
	pswd := parts[1]

	acct, err := auth.account_db.GetAccountById(id)

	if err != nil {
		return nil, err
	}

	p, err := acct.GetPassword(m)

	if p.Digest() != pswd {
		return nil, errors.New("Invalid user")
	}

	return m, nil
}

func (auth *EmailPasswordAuthenticator) newAuthCookie() (cookie.Cookie, error) {

	return cookie.NewAuthCookie(auth.options.CookieName, auth.options.CookieSecret, auth.options.CookieSalt)
}

func (auth *EmailPasswordAuthenticator) setAuthCookie(rsp go_http.ResponseWriter, acct *account.Account) error {

	p, err := acct.GetPassword()

	if err != nil {
		return err
	}

	ck, err := auth.newAuthCookie()

	if err != nil {
		return err
	}

	ck_value := fmt.Sprintf("%s:%s", m.Id(), p.Digest()) // WRAP THIS IN A FUNCTION

	return ck.Set(rsp, ck_value)
}
