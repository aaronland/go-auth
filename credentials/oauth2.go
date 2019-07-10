package credentials

import (
	"errors"
	"github.com/aaronland/go-auth"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/database"
	"github.com/aaronland/go-http-rewrite"
	"golang.org/x/net/html"
	"html/template"
	"io"
	_ "log"
	go_http "net/http"
)

type OAuth2Credentials struct {
	auth.Credentials
	account_db database.AccountsDatabase
}

func NewOAuth2Credentials(db database.AccountsDatabase) (auth.Credentials, error) {

	o_auth := OAuth2Credentials{
		account_db: db,
	}

	return &o_auth, nil
}

func (o_auth *OAuth2Credentials) AppendCredentialsHandler(prev go_http.Handler) go_http.Handler {

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		acct, err := auth.GetAccountContext(req)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
			return
		}

		if acct == nil {
			return
		}

		rewrite_func := NewAccessTokenRewriteFunc(acct)
		rewrite_handler := rewrite.RewriteHTMLHandler(prev, rewrite_func)

		rewrite_handler.ServeHTTP(rsp, req)
		return
	}

	return go_http.HandlerFunc(fn)
}

func (o_auth *OAuth2Credentials) AuthHandler(next go_http.Handler) go_http.Handler {

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		acct, err := o_auth.GetAccountForRequest(req)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
			return
		}

		if acct == nil {
			go_http.Error(rsp, "Forbidden", go_http.StatusForbidden)
			return
		}

		req = auth.SetAccountContext(req, acct)
		next.ServeHTTP(rsp, req)
	}

	return go_http.HandlerFunc(fn)
}

func (o_auth *OAuth2Credentials) SigninHandler(*template.Template, string, go_http.Handler) go_http.Handler {
	return auth.NotImplementedHandler()
}

func (o_auth *OAuth2Credentials) SignupHandler(*template.Template, string, go_http.Handler) go_http.Handler {
	return auth.NotImplementedHandler()
}

func (o_auth *OAuth2Credentials) SignoutHandler(*template.Template, string, go_http.Handler) go_http.Handler {
	return auth.NotImplementedHandler()
}

func (o_auth *OAuth2Credentials) GetAccountForRequest(req *go_http.Request) (*account.Account, error) {

	token := req.FormValue("access_token")

	// check for bearer token...

	if token == "" {
		return nil, errors.New("Missing access token")
	}

	return nil, errors.New("Please write me")
}

func (o_auth *OAuth2Credentials) SetAccountForReponse(go_http.ResponseWriter, *account.Account) error {
	return errors.New("Not implemented")
}

func NewAccessTokenRewriteFunc(acct *account.Account) rewrite.RewriteHTMLFunc {

	var rewrite_func rewrite.RewriteHTMLFunc

	rewrite_func = func(n *html.Node, w io.Writer) {

		if n.Type == html.ElementNode && n.Data == "body" {

			token_ns := ""
			token_key := "data-oauth2-access-token"
			token_value := "FIXME"

			token_attr := html.Attribute{token_ns, token_key, token_value}
			n.Attr = append(n.Attr, token_attr)
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			rewrite_func(c, w)
		}
	}

	return rewrite_func
}
