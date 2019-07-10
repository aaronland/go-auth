package www

import (
	"github.com/aaronland/go-http-sanitize"
	go_http "net/http"
	"strings"
)

type QueryRedirectHandlerOptions struct {
	RootURL           string
	RedirectParameter string
}

func DefaultQueryRedirectHandlerOptions() *QueryRedirectHandlerOptions {

	opts := QueryRedirectHandlerOptions{
		RootURL:           "/",
		RedirectParameter: "redir",
	}

	return &opts
}

func NewRedirectHandler(uri string) go_http.Handler {

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {
		go_http.Redirect(rsp, req, uri, 303)
		return
	}

	return go_http.HandlerFunc(fn)
}

func NewQueryRedirectHandler(opts *QueryRedirectHandlerOptions) go_http.Handler {

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		redir, err := sanitize.RequestString(req, opts.RedirectParameter)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusBadRequest)
			return
		}

		if redir == "" {
			redir = opts.RootURL
		}

		if !strings.HasPrefix(redir, "/") {
			go_http.Error(rsp, "Unsupported redirect", go_http.StatusBadRequest)
			return
		}

		go_http.Redirect(rsp, req, redir, 303)
		return
	}

	return go_http.HandlerFunc(fn)
}
