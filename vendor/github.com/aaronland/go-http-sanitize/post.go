package sanitize

import (
	wof_sanitize "github.com/whosonfirst/go-sanitize"
	go_http "net/http"
	"strconv"
)

func PostString(req *go_http.Request, param string) (string, error) {

	raw_value := req.PostFormValue(param)
	return wof_sanitize.SanitizeString(raw_value, sn_opts)
}

func PostInt64(req *go_http.Request, param string) (int64, error) {

	str_value, err := PostString(req, param)

	if err != nil {
		return -1, err
	}

	return strconv.ParseInt(str_value, 10, 64)
}
