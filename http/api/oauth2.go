package api

import (
	"errors"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/http"
	"github.com/aaronland/go-http-rewrite"
	"golang.org/x/net/html"
	"html/template"
	"io"
	_ "log"
	go_http "net/http"
)

type OAuth2Authenticator struct {
	http.HTTPAuthenticator
	membership account.MembershipDatabase
}

func NewOAuth2Authenticator(db account.MembershipDatabase) (http.HTTPAuthenticator, error) {

	auth := OAuth2Authenticator{
		membership: db,
	}

	return &auth, nil
}

func (auth *OAuth2Authenticator) AppendCredentialsHandler(prev go_http.Handler) go_http.Handler {

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		acct, err := http.GetMembershipContext(req)

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

func (auth *OAuth2Authenticator) AuthHandler(next go_http.Handler) go_http.Handler {

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		m, err := auth.GetMembershipForRequest(req)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
			return
		}

		if m == nil {
			go_http.Error(rsp, "Forbidden", go_http.StatusForbidden)
			return
		}

		req = http.SetMembershipContext(req, m)
		next.ServeHTTP(rsp, req)
	}

	return go_http.HandlerFunc(fn)
}

func (auth *OAuth2Authenticator) SigninHandler(*template.Template, string) go_http.Handler {
	return http.NotImplementedHandler()
}

func (auth *OAuth2Authenticator) SignupHandler(*template.Template, string) go_http.Handler {
	return http.NotImplementedHandler()
}

func (auth *OAuth2Authenticator) SignoutHandler(*template.Template, string) go_http.Handler {
	return http.NotImplementedHandler()
}

func (auth *OAuth2Authenticator) GetMembershipForRequest(req *go_http.Request) (account.Membership, error) {

	token := req.FormValue("access_token")

	// check for bearer token...

	if token == "" {
		return nil, errors.New("Missing access token")
	}

	return auth.membership.GetMembershipByIdentifier("access_token", token)
}

func NewAccessTokenRewriteFunc(acct account.Membership) rewrite.RewriteHTMLFunc {

	var rewrite_func rewrite.RewriteHTMLFunc

	rewrite_func = func(n *html.Node, w io.Writer) {

		if n.Type == html.ElementNode && n.Data == "body" {

			token_ns := ""
			token_key := "data-oauth2-access-token"
			token_value := "fixme" // acct.Get("access_token")

			token_attr := html.Attribute{token_ns, token_key, token_value}
			n.Attr = append(n.Attr, token_attr)
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			rewrite_func(c, w)
		}
	}

	return rewrite_func
}
