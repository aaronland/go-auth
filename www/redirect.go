package www

import (
	"github.com/aaronland/go-http-sanitize"
	"github.com/sfomuseum/logger"
	"log"
	go_http "net/http"
	_ "os"
	"strings"
)

type QueryRedirectHandlerOptions struct {
	RootURL           string
	RedirectParameter string
	Logger            *logger.Logger
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

		opts.Logger.Printf("Query redirect handler %s (%s)", req.URL.Path, req.Method)
		opts.Logger.Printf("QUERY REDIRECT HEADER %s", rsp.Header())

		// rsp.Header().Write(os.Stderr)

		h := rsp.Header()
		opts.Logger.Printf("OMGWTF %s", h["Set-Cookie"])
		
		redir, err := sanitize.RequestString(req, opts.RedirectParameter)

		if err != nil {
			opts.Logger.Printf("WTF 1")
			go_http.Error(rsp, err.Error(), go_http.StatusBadRequest)
			return
		}

		if redir == "" {
			opts.Logger.Printf("WTF 2")
			redir = opts.RootURL
		}

		if !strings.HasPrefix(redir, "/") {
			opts.Logger.Printf("WTF 3")
			go_http.Error(rsp, "Unsupported redirect", go_http.StatusBadRequest)
			return
		}
		
		opts.Logger.Printf("Query redirect to %s (%s)", redir, req.Method)

		go_http.Redirect(rsp, req, redir, 303)
		return
	}

	return go_http.HandlerFunc(fn)
}
