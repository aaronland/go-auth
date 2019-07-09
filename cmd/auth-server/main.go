package main

import (
	"flag"
	"fmt"
	"github.com/aaronland/go-http-auth"
	"github.com/aaronland/go-http-auth/account"
	"github.com/aaronland/go-http-auth/database/fs"
	"github.com/aaronland/go-http-auth/www"
	"github.com/aaronland/go-string/dsn"
	"html/template"
	"log"
	"net/http"
)

func IndexHandler(auth auth.HTTPAuthenticator, templates *template.Template, t_name string) http.Handler {

	type IndexVars struct {
		Account *account.Account
	}

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		acct, err := auth.GetAccountForRequest(req)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		vars := IndexVars{
			Account: acct,
		}

		err = templates.ExecuteTemplate(rsp, t_name, vars)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		return
	}

	return http.HandlerFunc(fn)
}

func PasswordHandler(auth auth.HTTPAuthenticator, templates *template.Template, t_name string) http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		rsp.Write([]byte("PASSWORD"))
		return
	}

	return http.HandlerFunc(fn)
}

func main() {

	host := flag.String("host", "localhost", "...")
	port := flag.Int("port", 8080, "...")
	templates := flag.String("templates", "", "...")
	accts_dsn := flag.String("accounts-dsn", "", "...")
	cookie_dsn := flag.String("cookie-dsn", "", "...")

	// require_mfa := flag.Bool("require-mfa", true, "...")

	mfa_signin_url := flag.String("mfa-signin-url", "/mfa", "...")
	mfa_ttl := flag.Int64("mfa-ttl", 3600, "...")

	// please update to use this
	// https://gocloud.dev/howto/secrets

	flag.Parse()

	accts_cfg, err := dsn.StringToDSNWithKeys(*accts_dsn, "root")

	if err != nil {
		log.Fatal(err)
	}

	cookie_cfg, err := dsn.StringToDSNWithKeys(*cookie_dsn, "name", "secret", "salt")

	if err != nil {
		log.Fatal(err)
	}

	account_db, err := fs.NewFSAccountDatabase(accts_cfg["root"])

	if err != nil {
		log.Fatal(err)
	}

	auth_templates, err := template.ParseGlob(*templates)

	if err != nil {
		log.Fatal(err)
	}

	query_redirect_opts := www.DefaultQueryRedirectHandlerOptions()
	query_redirect_handler := www.NewQueryRedirectHandler(query_redirect_opts)

	ep_opts := www.DefaultEmailPasswordAuthenticatorOptions()

	ep_opts.CookieName = cookie_cfg["name"]
	ep_opts.CookieSecret = cookie_cfg["secret"]
	ep_opts.CookieSalt = cookie_cfg["salt"]

	ep_auth, err := www.NewEmailPasswordAuthenticator(account_db, ep_opts)

	if err != nil {
		log.Fatal(err)
	}

	common_totp_opts := www.DefaultTOTPAuthenticatorOptions()
	common_totp_opts.SigninUrl = *mfa_signin_url
	common_totp_opts.TTL = *mfa_ttl

	strict_totp_opts := www.DefaultTOTPAuthenticatorOptions()
	strict_totp_opts.SigninUrl = *mfa_signin_url
	strict_totp_opts.Force = true

	common_totp_auth, err := www.NewTOTPAuthenticator(account_db, common_totp_opts)

	if err != nil {
		log.Fatal(err)
	}

	strict_totp_auth, err := www.NewTOTPAuthenticator(account_db, strict_totp_opts)

	if err != nil {
		log.Fatal(err)
	}

	common_auth_handler := func(final_handler http.Handler) http.Handler {
		auth_handler := common_totp_auth.AuthHandler(final_handler)
		auth_handler = ep_auth.AuthHandler(auth_handler)
		return auth_handler
	}

	strict_auth_handler := func(final_handler http.Handler) http.Handler {
		auth_handler := strict_totp_auth.AuthHandler(final_handler)
		auth_handler = ep_auth.AuthHandler(auth_handler)
		return auth_handler
	}

	mfa_redirect_handler := www.NewRedirectHandler(*mfa_signin_url)

	mfa_signin_handler := strict_totp_auth.SigninHandler(auth_templates, "totp", query_redirect_handler)
	mfa_signin_handler = ep_auth.AuthHandler(mfa_signin_handler)

	signin_handler := ep_auth.SigninHandler(auth_templates, "signin", mfa_redirect_handler)

	signup_handler := ep_auth.SignupHandler(auth_templates, "signup", query_redirect_handler)
	signout_handler := ep_auth.SignoutHandler(auth_templates, "signout", query_redirect_handler)

	index_handler := IndexHandler(ep_auth, auth_templates, "index")
	index_handler = common_auth_handler(index_handler)

	pswd_handler := PasswordHandler(ep_auth, auth_templates, "password")
	pswd_handler = strict_auth_handler(pswd_handler)

	mux := http.NewServeMux()

	mux.Handle(ep_opts.SigninURL, signin_handler)
	mux.Handle(ep_opts.SignupURL, signup_handler)
	mux.Handle(ep_opts.SignoutURL, signout_handler)

	mux.Handle(*mfa_signin_url, mfa_signin_handler)

	mux.Handle(ep_opts.RootURL, index_handler)
	mux.Handle("/password", pswd_handler)

	endpoint := fmt.Sprintf("%s:%d", *host, *port)
	log.Printf("Listening for requests on %s\n", endpoint)

	err = http.ListenAndServe(endpoint, mux)

	if err != nil {
		log.Fatal(err)
	}
}
