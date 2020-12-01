package auth

import (
	"context"
	"github.com/aaronland/go-auth/account"
	"html/template"
	_ "log"
	"net/http"
)

const CONTEXT_ACCOUNT_KEY string = "account"

type Credentials interface {
	AuthHandler(http.Handler) http.Handler
	AppendCredentialsHandler(http.Handler) http.Handler
	SigninHandler(*template.Template, string, http.Handler) http.Handler
	SignupHandler(*template.Template, string, http.Handler) http.Handler
	SignoutHandler(*template.Template, string, http.Handler) http.Handler
	GetAccountForRequest(*http.Request) (*account.Account, error)
	SetAccountForResponse(http.ResponseWriter, *account.Account) error
}

func NotImplementedHandler() http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		http.Error(rsp, "Not Implemented", http.StatusNotImplemented)
		return
	}

	return http.HandlerFunc(fn)
}

// please put these http-related things somewhere else

func SetAccountContext(req *http.Request, acct *account.Account) *http.Request {

	ctx := req.Context()
	ctx = context.WithValue(ctx, CONTEXT_ACCOUNT_KEY, acct)

	return req.WithContext(ctx)
}

func GetAccountContext(req *http.Request) (*account.Account, error) {

	ctx := req.Context()
	v := ctx.Value(CONTEXT_ACCOUNT_KEY)

	if v == nil {
		return nil, nil
	}

	acct := v.(*account.Account)
	return acct, nil
}

func IsAuthenticated(creds Credentials, req *http.Request) (bool, error) {

	acct, err := creds.GetAccountForRequest(req)

	if err != nil {
		return false, err
	}

	if acct == nil {
		return false, nil
	}

	return true, nil
}
