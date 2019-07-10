package main

import (
	"flag"
	"fmt"
	"github.com/aaronland/go-http-auth"
	"github.com/aaronland/go-http-auth/account"
	"github.com/aaronland/go-http-auth/credentials"
	"github.com/aaronland/go-http-auth/database/fs"
	"github.com/aaronland/go-http-auth/www"
	"github.com/aaronland/go-string/dsn"
	"html/template"
	"log"
	"net/http"
)

func IndexHandler(creds auth.Credentials, templates *template.Template, t_name string) http.Handler {

	type IndexVars struct {
		Account *account.Account
	}

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		acct, err := creds.GetAccountForRequest(req)

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

func main() {

	host := flag.String("host", "localhost", "...")
	port := flag.Int("port", 8080, "...")
	templates := flag.String("templates", "", "...")
	accts_dsn := flag.String("accounts-dsn", "", "...")
	auth_cookie_dsn := flag.String("auth-cookie-dsn", "", "...")

	require_mfa := flag.Bool("mfa", true, "...")
	mfa_cookie_dsn := flag.String("mfa-cookie-dsn", "", "...")
	mfa_signin_url := flag.String("mfa-signin-url", "/mfa", "...")
	mfa_ttl := flag.Int64("mfa-ttl", 3600, "...")

	// please update to use this
	// https://gocloud.dev/howto/secrets

	flag.Parse()

	accts_cfg, err := dsn.StringToDSNWithKeys(*accts_dsn, "root")

	if err != nil {
		log.Fatal(err)
	}

	auth_cookie_cfg, err := dsn.StringToDSNWithKeys(*auth_cookie_dsn, "name", "secret", "salt")

	if err != nil {
		log.Fatal(err)
	}

	mfa_cookie_cfg, err := dsn.StringToDSNWithKeys(*mfa_cookie_dsn, "name", "secret", "salt")

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

	// TO DO : read from CLI

	crumb_cfg, err := www.NewCrumbConfig()

	if err != nil {
		log.Fatal(err)
	}

	ep_opts := credentials.DefaultEmailPasswordCredentialsOptions()

	ep_opts.CookieName = auth_cookie_cfg["name"]
	ep_opts.CookieSecret = auth_cookie_cfg["secret"]
	ep_opts.CookieSalt = auth_cookie_cfg["salt"]
	ep_opts.CrumbConfig = crumb_cfg

	ep_auth, err := credentials.NewEmailPasswordCredentials(account_db, ep_opts)

	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// at this point the order of the handlers is relevant which is unfortunate
	// but there you go... because MFA is optional (20190710/thisisaaronland)

	ep_auth_handler := func(final_handler http.Handler) http.Handler {
		auth_handler := ep_auth.AuthHandler(final_handler)
		return auth_handler
	}

	basic_auth_handler := ep_auth_handler
	strict_auth_handler := ep_auth_handler

	query_redirect_opts := www.DefaultQueryRedirectHandlerOptions()
	query_redirect_handler := www.NewQueryRedirectHandler(query_redirect_opts)

	signin_complete_handler := query_redirect_handler

	if *require_mfa {

		common_totp_opts := credentials.DefaultTOTPCredentialsOptions()
		common_totp_opts.SigninUrl = *mfa_signin_url
		common_totp_opts.TTL = *mfa_ttl

		common_totp_opts.CookieName = mfa_cookie_cfg["name"]
		common_totp_opts.CookieSecret = mfa_cookie_cfg["secret"]
		common_totp_opts.CookieSalt = mfa_cookie_cfg["salt"]

		strict_totp_opts := credentials.DefaultTOTPCredentialsOptions()
		strict_totp_opts.SigninUrl = *mfa_signin_url
		strict_totp_opts.Force = true

		strict_totp_opts.CookieName = mfa_cookie_cfg["name"]
		strict_totp_opts.CookieSecret = mfa_cookie_cfg["secret"]
		strict_totp_opts.CookieSalt = mfa_cookie_cfg["salt"]

		common_totp_auth, err := credentials.NewTOTPCredentials(account_db, common_totp_opts)

		if err != nil {
			log.Fatal(err)
		}

		strict_totp_auth, err := credentials.NewTOTPCredentials(account_db, strict_totp_opts)

		if err != nil {
			log.Fatal(err)
		}

		basic_auth_handler = func(final_handler http.Handler) http.Handler {
			auth_handler := common_totp_auth.AuthHandler(final_handler)
			return ep_auth_handler(auth_handler)
		}

		strict_auth_handler = func(final_handler http.Handler) http.Handler {
			auth_handler := strict_totp_auth.AuthHandler(final_handler)
			return ep_auth_handler(auth_handler)
		}

		mfa_signin_handler := strict_totp_auth.SigninHandler(auth_templates, "totp", query_redirect_handler)
		mfa_signin_handler = ep_auth_handler(mfa_signin_handler)

		mfa_redirect_handler := www.NewRedirectHandler(*mfa_signin_url)
		signin_complete_handler = mfa_redirect_handler

		mux.Handle(*mfa_signin_url, mfa_signin_handler)
		// mux.Handle(*mfa_signup_url, mfa_signup_handler)
	}

	signin_handler := ep_auth.SigninHandler(auth_templates, "signin", signin_complete_handler)
	signup_handler := ep_auth.SignupHandler(auth_templates, "signup", query_redirect_handler)
	signout_handler := ep_auth.SignoutHandler(auth_templates, "signout", query_redirect_handler)

	index_handler := IndexHandler(ep_auth, auth_templates, "index")
	index_handler = basic_auth_handler(index_handler)

	pswd_handler_opts := &www.PasswordHandlerOptions{
		Credentials:     ep_auth,
		AccountDatabase: account_db,
		CrumbConfig:     crumb_cfg,
	}

	pswd_handler := www.PasswordHandler(pswd_handler_opts, auth_templates, "password")
	pswd_handler = strict_auth_handler(pswd_handler)

	mux.Handle(ep_opts.SigninURL, signin_handler)
	mux.Handle(ep_opts.SignupURL, signup_handler)
	mux.Handle(ep_opts.SignoutURL, signout_handler)

	mux.Handle(ep_opts.RootURL, index_handler)
	mux.Handle("/password", pswd_handler)

	endpoint := fmt.Sprintf("%s:%d", *host, *port)
	log.Printf("Listening for requests on %s\n", endpoint)

	err = http.ListenAndServe(endpoint, mux)

	if err != nil {
		log.Fatal(err)
	}
}
