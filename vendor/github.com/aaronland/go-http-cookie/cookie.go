package cookie

import (
	go_http "net/http"
)

type Cookie interface {
	Get(*go_http.Request) (string, error)
	Set(go_http.ResponseWriter, string) error
	SetCookie(go_http.ResponseWriter, *go_http.Cookie) error
	Delete(go_http.ResponseWriter) error
}
