package http

import (
	"context"
	"github.com/aaronland/go-auth/account"
	"html/template"
	go_http "net/http"
)

type HTTPAuthenticator interface {
	AuthHandler(go_http.Handler) go_http.Handler
	AppendCredentialsHandler(go_http.Handler) go_http.Handler
	SigninHandler(*template.Template, string) go_http.Handler
	SignupHandler(*template.Template, string) go_http.Handler
	SignoutHandler(*template.Template, string) go_http.Handler
	GetMembershipForRequest(*go_http.Request) (account.Membership, error)
}

func NotImplementedHandler() go_http.Handler {

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		go_http.Error(rsp, "Not Implemented", go_http.StatusNotImplemented)
		return
	}

	return go_http.HandlerFunc(fn)
}

func SetMembershipContext(req *go_http.Request, acct account.Membership) *go_http.Request {

	ctx := req.Context()
	ctx = context.WithValue(ctx, "account", acct) // please make "account" a constant

	return req.WithContext(ctx)
}

func GetMembershipContext(req *go_http.Request) (account.Membership, error) {

	ctx := req.Context()
	v := ctx.Value("account") // please make "account" a constant

	if v == nil {
		return nil, nil
	}

	acct := v.(account.Membership)
	return acct, nil
}

func IsAuthenticated(auth HTTPAuthenticator, req *go_http.Request) (bool, error) {

	m, err := auth.GetMembershipForRequest(req)

	if err != nil {
		return false, err
	}

	if m == nil {
		return false, nil
	}

	return true, nil
}
