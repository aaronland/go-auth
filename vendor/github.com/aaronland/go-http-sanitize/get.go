package sanitize

import (
	wof_sanitize "github.com/whosonfirst/go-sanitize"
	go_http "net/http"
	"strconv"
)

func GetString(req *go_http.Request, param string) (string, error) {

	q := req.URL.Query()
	raw_value := q.Get(param)
	return wof_sanitize.SanitizeString(raw_value, sn_opts)
}

func GetInt64(req *go_http.Request, param string) (int64, error) {

	str_value, err := GetString(req, param)

	if err != nil {
		return -1, err
	}

	return strconv.ParseInt(str_value, 10, 64)
}
