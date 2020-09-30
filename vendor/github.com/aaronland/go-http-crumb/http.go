package crumb

import (
	"context"
	"errors"
	"github.com/aaronland/go-http-rewrite"
	"github.com/aaronland/go-http-sanitize"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
	"io"
	_ "log"
	go_http "net/http"
)

func SetErrorContextWithRequest(req *go_http.Request, err error, status_code int) *go_http.Request {

	ctx := req.Context()
	ctx = SetErrorContextWithContext(ctx, err, status_code)
	return req.WithContext(ctx)
}

func SetErrorContextWithContext(ctx context.Context, err error, status_code int) context.Context {

	ctx = context.WithValue(ctx, "Status", status_code)
	ctx = context.WithValue(ctx, "Error", err)
	return ctx
}

func GetErrorContextValuesWithContext(ctx context.Context) (error, int, error) {

	crumb_err := ctx.Value("Error")

	if crumb_err == nil {
		return nil, 0, errors.New("Invalid crumb handler")
	}

	status_code := ctx.Value("Status")

	if status_code == nil {
		return nil, 0, errors.New("Invalid crumb handler")
	}

	return crumb_err.(error), status_code.(int), nil
}

func GetErrorContextValuesWithRequest(req *go_http.Request) (error, int, error) {
	return GetErrorContextValuesWithContext(req.Context())
}

func DefaultErrorHandler() go_http.Handler {

	handler_fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		crumb_err, status_code, err := GetErrorContextValuesWithRequest(req)

		if err != nil {
			go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
		}

		go_http.Error(rsp, crumb_err.Error(), status_code)
		return
	}

	return go_http.HandlerFunc(handler_fn)
}

func EnsureCrumbHandler(cfg *CrumbConfig, next_handler go_http.Handler) go_http.Handler {

	err_handler := DefaultErrorHandler()
	return EnsureCrumbHandlerWithErrorHandler(cfg, next_handler, err_handler)
}

func EnsureCrumbHandlerWithErrorHandler(cfg *CrumbConfig, next_handler go_http.Handler, error_handler go_http.Handler) go_http.Handler {

	fn := func(rsp go_http.ResponseWriter, req *go_http.Request) {

		switch req.Method {

		case "POST", "PUT":

			var crumb_var string
			var crumb_err error

			if req.Method == "POST" {
				crumb_var, crumb_err = sanitize.PostString(req, "crumb")
			} else {
				crumb_var, crumb_err = sanitize.GetString(req, "crumb")
			}

			if crumb_err != nil {
				req = SetErrorContextWithRequest(req, crumb_err, go_http.StatusBadRequest)
				error_handler.ServeHTTP(rsp, req)
				return
			}

			if crumb_var == "" {
				req = SetErrorContextWithRequest(req, errors.New("Missing crumb"), go_http.StatusBadRequest)
				error_handler.ServeHTTP(rsp, req)
				return
			}

			ok, err := ValidateCrumb(cfg, req, crumb_var)

			if err != nil {
				req = SetErrorContextWithRequest(req, err, go_http.StatusInternalServerError)
				error_handler.ServeHTTP(rsp, req)
				return
			}

			if !ok {
				req = SetErrorContextWithRequest(req, errors.New("Forbidden"), go_http.StatusForbidden)
				error_handler.ServeHTTP(rsp, req)
				return
			}

		default:
			// pass
		}

		crumb_var, err := GenerateCrumb(cfg, req)

		if err != nil {
			req = SetErrorContextWithRequest(req, err, go_http.StatusInternalServerError)
			error_handler.ServeHTTP(rsp, req)
			return
		}

		rewrite_func := NewCrumbRewriteFunc(crumb_var)
		rewrite_handler := rewrite.RewriteHTMLHandler(next_handler, rewrite_func)

		rewrite_handler.ServeHTTP(rsp, req)

	}

	return go_http.HandlerFunc(fn)
}

func NewCrumbRewriteFunc(crumb_var string) rewrite.RewriteHTMLFunc {

	var rewrite_func rewrite.RewriteHTMLFunc

	rewrite_func = func(n *html.Node, w io.Writer) {

		if n.Type == html.ElementNode && n.Data == "body" {

			crumb_ns := ""
			crumb_key := "data-crumb"
			crumb_value := crumb_var

			crumb_attr := html.Attribute{crumb_ns, crumb_key, crumb_value}
			n.Attr = append(n.Attr, crumb_attr)
		}

		if n.Type == html.ElementNode && n.Data == "form" {

			ns := ""

			attrs := []html.Attribute{
				html.Attribute{ns, "type", "hidden"},
				html.Attribute{ns, "id", "crumb"},
				html.Attribute{ns, "name", "crumb"},
				html.Attribute{ns, "value", crumb_var},
			}

			i := &html.Node{
				Type:      html.ElementNode,
				DataAtom:  atom.Input,
				Data:      "input",
				Namespace: ns,
				Attr:      attrs,
			}

			n.AppendChild(i)
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			rewrite_func(c, w)
		}
	}

	return rewrite_func
}
