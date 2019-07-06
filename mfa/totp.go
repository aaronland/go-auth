package otp

import (
	"github.com/aaronland/go-http-auth"
	_ "github.com/aaronland/go-http-auth/account"
	_ "github.com/aaronland/go-http-cookie"
	"github.com/aaronland/go-http-sanitize"
	"github.com/pquerna/otp/totp"
	"html/template"
	go_http "net/http"
	"time"
)

type TOTPAuthenticatorOptions struct {
	CookieName   string
	CookieSecret string
	CookieSalt   string
	CookieTTL    time.Duration
}

func TOTPHandler(templates *template.Template, t_name string, next go_http.Handler) go_http.Handler {

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
			next.ServeHTTP(rsp, req)
			return
		}

		// get TOTP cookie here
		// check TOTP cookie here

		vars := TOTPVars{
			PageTitle: "Two-Factor Authentication",
			// SignoutURL: ep_auth.options.SignoutURL,
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

			secret, err := acct.GetMFASecret()

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			valid := totp.Validate(str_code, secret)

			if !valid {
				// what?
				return
			}

			// new TOTP cookie here
			// set TOTP cookie here... with what?

			next.ServeHTTP(rsp, req)
			return

		default:
			go_http.Error(rsp, "Unsupported method", go_http.StatusMethodNotAllowed)
			return
		}
	}

	return go_http.HandlerFunc(fn)
}
