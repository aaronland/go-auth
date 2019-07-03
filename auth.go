package auth

import (
	"context"
	"github.com/aaronland/go-http-auth/account"
	"html/template"
	go_http "net/http"
)

const CONTEXT_ACCOUNT_KEY string = "account"

type HTTPAuthenticator interface {
	AuthHandler(go_http.Handler) go_http.Handler
	AppendCredentialsHandler(go_http.Handler) go_http.Handler
	SigninHandler(*template.Template, string) go_http.Handler
	SignupHandler(*template.Template, string) go_http.Handler
	SignoutHandler(*template.Template, string) go_http.Handler
	GetMembershipForRequest(*go_http.Request) (*account.Account, error)
}

func NotImplementedHandler() go_http.Handler {

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		go_http.Error(rsp, "Not Implemented", go_http.StatusNotImplemented)
		return
	}

	return go_http.HandlerFunc(fn)
}

func SetMembershipContext(req *go_http.Request, acct *account.Account) *go_http.Request {

	ctx := req.Context()
	ctx = context.WithValue(ctx, CONTEXT_ACCOUNT_KEY, acct)

	return req.WithContext(ctx)
}

func GetMembershipContext(req *go_http.Request) (*account.Account, error) {

	ctx := req.Context()
	v := ctx.Value(CONTEXT_ACCOUNT_KEY)

	if v == nil {
		return nil, nil
	}

	acct := v.(*account.Account)
	return acct, nil
}

func IsAuthenticated(auth HTTPAuthenticator, req *go_http.Request) (bool, error) {

	acct, err := auth.GetAccountForRequest(req)

	if err != nil {
		return false, err
	}

	if m == nil {
		return false, nil
	}

	return true, nil
}
