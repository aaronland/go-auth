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

func main() {

	host := flag.String("host", "localhost", "...")
	port := flag.Int("port", 8080, "...")
	templates := flag.String("templates", "", "...")
	accts_dsn := flag.String("accounts-dsn", "", "...")
	cookie_dsn := flag.String("cookie-dsn", "", "...")

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

	ep_opts := www.DefaultEmailPasswordAuthenticatorOptions()

	ep_opts.CookieName = cookie_cfg["name"]
	ep_opts.CookieSecret = cookie_cfg["secret"]
	ep_opts.CookieSalt = cookie_cfg["salt"]

	ep_auth, err := www.NewEmailPasswordAuthenticator(account_db, ep_opts)

	if err != nil {
		log.Fatal(err)
	}

	auth_templates, err := template.ParseGlob(*templates)

	if err != nil {
		log.Fatal(err)
	}

	signin_handler := ep_auth.SigninHandler(auth_templates, "signin")
	signup_handler := ep_auth.SignupHandler(auth_templates, "signup")
	signout_handler := ep_auth.SignoutHandler(auth_templates, "signout")

	index_handler := IndexHandler(ep_auth, auth_templates, "index")

	/*
		signin_handler = crumb.EnsureCrumbHandler(crumb_cfg, signin_handler)
		signup_handler = crumb.EnsureCrumbHandler(crumb_cfg, signup_handler)
		signout_handler = crumb.EnsureCrumbHandler(crumb_cfg, signout_handler)
	*/

	mux := http.NewServeMux()

	mux.Handle(ep_opts.SigninURL, signin_handler)
	mux.Handle(ep_opts.SignupURL, signup_handler)
	mux.Handle(ep_opts.SignoutURL, signout_handler)
	mux.Handle(ep_opts.RootURL, index_handler)

	endpoint := fmt.Sprintf("%s:%d", *host, *port)
	log.Printf("Listening for requests on %s\n", endpoint)

	err = http.ListenAndServe(endpoint, mux)

	if err != nil {
		log.Fatal(err)
	}
}