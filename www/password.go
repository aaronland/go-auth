package www

import (
	"errors"
	"github.com/aaronland/go-auth"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/database"
	"github.com/aaronland/go-http-crumb"
	"github.com/aaronland/go-http-sanitize"
	"html/template"
	_ "log"
	"net/http"
)

type PasswordHandlerOptions struct {
	Credentials      auth.Credentials
	AccountsDatabase database.AccountsDatabase
	CrumbConfig      *crumb.CrumbConfig
}

func PasswordHandler(opts *PasswordHandlerOptions, templates *template.Template, t_name string) http.Handler {

	type PasswordVars struct {
		Account *account.Account
		Error   error
	}

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		acct, err := opts.Credentials.GetAccountForRequest(req)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		vars := PasswordVars{
			Account: acct,
		}

		render := func(with_vars PasswordVars) {

			rsp.Header().Set("Content-type", "text/html")

			err := templates.ExecuteTemplate(rsp, t_name, with_vars)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
			}

			return
		}

		render_error := func(with_vars PasswordVars, err error) {
			with_vars.Error = err
			render(with_vars)
			return
		}

		render_errorString := func(with_vars PasswordVars, err_str string) {
			err := errors.New(err_str)
			render_error(vars, err)
			return
		}

		switch req.Method {

		case "GET":

			render(vars)
			return

		case "POST":

			str_old_password, err := sanitize.PostString(req, "old_password")

			if err != nil {
				render_error(vars, err)
				return
			}

			str_new_password, err := sanitize.PostString(req, "new_password")

			if err != nil {
				render_error(vars, err)
				return
			}

			if str_old_password == str_new_password {
				render_errorString(vars, "passwords are the same")
				return
			}

			p, err := acct.GetPassword()

			if err != nil {
				render_error(vars, err)
				return
			}

			err = p.Compare(str_old_password)

			if err != nil {
				render_error(vars, err)
				return
			}

			acct, err = acct.UpdatePassword(str_new_password)

			if err != nil {
				render_error(vars, err)
				return
			}

			acct, err = opts.AccountsDatabase.UpdateAccount(acct)

			if err != nil {
				render_error(vars, err)
				return
			}

			err = opts.Credentials.SetAccountForResponse(rsp, acct)

			if err != nil {
				render_error(vars, err)
				return
			}

			http.Redirect(rsp, req, req.URL.Path, 303)
			return

		default:
			http.Error(rsp, "Unsupported method", http.StatusMethodNotAllowed)
			return
		}

		return
	}

	password_handler := http.HandlerFunc(fn)
	return crumb.EnsureCrumbHandler(opts.CrumbConfig, password_handler)
}
