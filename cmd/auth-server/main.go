package main

import (
	"flag"
	"fmt"
	"github.com/aaronland/go-http-auth/database/fs"
	"github.com/aaronland/go-http-auth/www"
	"github.com/aaronland/go-string/dsn"
	"html/template"
	"log"
	"net/http"
)

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

	/*
	signin_handler = crumb.EnsureCrumbHandler(crumb_cfg, signin_handler)
	signup_handler = crumb.EnsureCrumbHandler(crumb_cfg, signup_handler)
	signout_handler = crumb.EnsureCrumbHandler(crumb_cfg, signout_handler)
	*/

	mux := http.NewServeMux()

	mux.Handle(ep_opts.SigninURL, signin_handler)
	mux.Handle(ep_opts.SignupURL, signup_handler)
	mux.Handle(ep_opts.SignoutURL, signout_handler)

	endpoint := fmt.Sprintf("%s:%d", *host, *port)
	log.Printf("Listening for requests on %s\n", endpoint)

	err = http.ListenAndServe(endpoint, mux)

	if err != nil {
		log.Fatal(err)
	}
}

