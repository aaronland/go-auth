package www

import (
	"github.com/aaronland/go-http-sanitize"
	"log"
	go_http "net/http"
)

type RedirectHandlerOptions struct {
	RootURL           string
	RedirectParameter string
}

func DefaultRedirectHandlerOptions() *RedirectHandlerOptions {

	opts := RedirectHandlerOptions{
		RootURL:           "/",
		RedirectParameter: "redir",
	}

	return &opts
}

func NewRedirectHandler(opts *RedirectHandlerOptions) go_http.Handler {

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		redir, err := sanitize.RequestString(req, opts.RedirectParameter)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
			return
		}

		log.Println("REDIRECT", req.URL.Path, redir, err)

		if redir == "" {
			redir = opts.RootURL
		}

		go_http.Redirect(rsp, req, redir, 303)
		return
	}

	return go_http.HandlerFunc(fn)
}
