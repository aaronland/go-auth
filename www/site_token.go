package www

import (
	"github.com/aaronland/go-http-auth"
	"github.com/aaronland/go-http-auth/database"
	"github.com/aaronland/go-http-sanitize"
	"github.com/pquerna/otp/totp"
	"log"
	"net/http"
)

type SiteTokenHandlerOptions struct {
	Credentials     auth.Credentials
	AccountDatabase database.AccountDatabase
	AccessTokenDatabase database.AccessTokenDatabase
}

func SiteTokenHandler(opts *SiteTokenHandlerOptions) http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		switch req.Method {

		case "POST":

			email, err := sanitize.PostString(req, "email")

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			if email == "" {
				http.Error(rsp, "Missing email", http.StatusInternalServerError)
				return
			}

			password, err := sanitize.PostString(req, "password")

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			if password == "" {
				http.Error(rsp, "Missing password", http.StatusInternalServerError)
				return
			}

			code, err := sanitize.PostString(req, "code")

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			if code == "" {
				http.Error(rsp, "Missing code", http.StatusInternalServerError)
				return
			}

			acct, err := opts.AccountDatabase.GetAccountByEmailAddress(email)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			if !acct.IsEnabled() {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			pswd, err := acct.GetPassword()

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			err = pswd.Compare(password)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
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

			valid := totp.Validate(code, secret)

			if !valid {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			site_token, err := opts.AccessTokenDatabase.GetSiteTokenForAccount(acct)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			log.Println(site_token)

		default:
			http.Error(rsp, "Unsupported method", http.StatusMethodNotAllowed)
			return

		}
	}

	return http.HandlerFunc(fn)
}
