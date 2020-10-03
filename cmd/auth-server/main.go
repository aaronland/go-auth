package main

import (
	"context"
	"flag"
	"github.com/aaronland/go-auth"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/credentials"
	"github.com/aaronland/go-auth/database"
	_ "github.com/aaronland/go-auth/database/fs"
	"github.com/aaronland/go-auth/www"
	"github.com/aaronland/go-http-crumb"
	"github.com/aaronland/go-http-server"
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

		rsp.Header().Set("Content-type", "text/html")
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

	server_uri := flag.String("server-uri", "http://localhost:8080", "...")

	templates := flag.String("templates", "./templates/*.html", "...")
	accounts_uri := flag.String("accounts-uri", "", "...")
	sessions_uri := flag.String("sessions-uri", "", "...")

	crumb_uri := flag.String("crumb-uri", "debug", "...")

	session_cookie_name := flag.String("session-cookie-name", "s", "...")
	session_cookie_ttl := flag.Int64("session-cookie-ttl", 3600, "...")

	// require_mfa := flag.Bool("mfa", true, "...")
	mfa_signin_url := flag.String("mfa-signin-url", "/mfa", "...")

	mfa_cookie_name := flag.String("mfa-cookie-name", "m", "...")
	mfa_cookie_ttl := flag.Int64("mfa-cookie-ttl", 3600, "...")

	// allow_tokens := flag.Bool("tokens", false, "...")
	// tokens_uri := flag.String("tokens-uri", "", "...")

	flag.Parse()

	ctx := context.Background()

	accounts_db, err := database.NewAccountsDatabase(ctx, *accounts_uri)

	if err != nil {
		log.Fatal(err)
	}

	sessions_db, err := database.NewSessionsDatabase(ctx, *sessions_uri)

	if err != nil {
		log.Fatal(err)
	}

	auth_templates, err := template.ParseGlob(*templates)

	if err != nil {
		log.Fatal(err)
	}

	if *crumb_uri == "debug" {

		uri, err := crumb.NewRandomEncryptedCrumbURI(ctx, 3600, "debug")

		if err != nil {
			log.Fatal(err)
		}

		*crumb_uri = uri
	}

	cr, err := crumb.NewCrumb(ctx, *crumb_uri)

	if err != nil {
		log.Fatal(err)
	}

	ep_opts := credentials.DefaultEmailPasswordCredentialsOptions()

	ep_opts.AccountsDatabase = accounts_db
	ep_opts.SessionsDatabase = sessions_db
	ep_opts.SessionCookieName = *session_cookie_name
	ep_opts.SessionCookieTTL = *session_cookie_ttl
	ep_opts.Crumb = cr

	ep_creds, err := credentials.NewEmailPasswordCredentials(ctx, ep_opts)

	if err != nil {
		log.Fatalf("Failed to create email/password credentials", err)
	}
	
	mfa_opts := credentials.DefaultTOTPCredentialsOptions()
	mfa_opts.SigninUrl = *mfa_signin_url
	mfa_opts.CookieName = *mfa_cookie_name
	mfa_opts.CookieTTL = *mfa_cookie_ttl
	mfa_opts.AccountsDatabase = accounts_db

	mfa_creds, err := credentials.NewTOTPCredentials(ctx, mfa_opts)

	if err != nil {
		log.Fatalf("Failed to create MFA credentials", err)
	}
	
	mux := http.NewServeMux()

	index_handler := IndexHandler(ep_creds, auth_templates, "index")
	index_handler = mfa_creds.AuthHandler(index_handler)
	index_handler = ep_creds.AuthHandler(index_handler)

	mux.Handle("/", index_handler)
	
	query_redirect_opts := www.DefaultQueryRedirectHandlerOptions()
	query_redirect_handler := www.NewQueryRedirectHandler(query_redirect_opts)

	signin_handler := ep_creds.SigninHandler(auth_templates, "signin", query_redirect_handler)
	signin_handler = mfa_creds.AuthHandler(signin_handler)
	// signin_handler = ep_creds.AuthHandler(signin_handler)	

	mux.Handle(ep_opts.SigninURL, signin_handler)
	
	// signup_handler := ep_creds.SignupHandler(auth_templates, "signup", query_redirect_handler)
	// mux.Handle(ep_opts.SignupURL, signup_handler)
	
	signout_handler := ep_creds.SignoutHandler(auth_templates, "signout", query_redirect_handler)
	// STUFF HERE
	mux.Handle(ep_opts.SignoutURL, signout_handler)
	
	mfa_handler := mfa_creds.SigninHandler(auth_templates, "totp", query_redirect_handler)
	//mfa_handler = mfa_creds.AuthHandler(mfa_handler)
	mfa_handler = ep_creds.AuthHandler(mfa_handler)	

	mux.Handle("/mfa", mfa_handler)
	
	/*
	pswd_handler_opts := &www.PasswordHandlerOptions{
		Credentials:      ep_creds,
		AccountsDatabase: accounts_db,
		Crumb:            cr,
	}

	pswd_handler := www.PasswordHandler(pswd_handler_opts, auth_templates, "password")
	pswd_handler = strict_auth_handler(pswd_handler)
	*/
	
	s, err := server.NewServer(ctx, *server_uri)

	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Listening for requests on %s\n", s.Address())

	err = s.ListenAndServe(ctx, mux)

	if err != nil {
		log.Fatal(err)
	}
}
