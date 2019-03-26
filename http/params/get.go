package params

import (
	"github.com/whosonfirst/go-sanitize"
	go_http "net/http"
	_ "strconv"
)

func GetString(req *go_http.Request, param string) (string, error) {

	q := req.URL.Query()
	raw_value := q.Get(param)
	return sanitize.SanitizeString(raw_value, sn_opts)
}
