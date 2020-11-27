package www

import (
	"github.com/aaronland/go-http-sanitize"
	"log"
	go_http "net/http"
	"strings"
	"github.com/sfomuseum/logger"	
)

type QueryRedirectHandlerOptions struct {
	RootURL           string
	RedirectParameter string
	Logger *logger.Logger
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

		log.Printf("Redirect to %s (%s)", uri, req.Method)
		
		go_http.Redirect(rsp, req, uri, 303)
		return
	}

	return go_http.HandlerFunc(fn)
}

func NewQueryRedirectHandler(opts *QueryRedirectHandlerOptions) go_http.Handler {

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		log.Printf("Query redirect handler %s (%s)", req.URL.Path, req.Method)

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

		log.Printf("Query redirect to %s (%s)", redir, req.Method)
		
		go_http.Redirect(rsp, req, redir, 303)
		return
	}

	return go_http.HandlerFunc(fn)
}
