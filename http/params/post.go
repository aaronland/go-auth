package params

import (
	"github.com/whosonfirst/go-sanitize"
	go_http "net/http"
	"strconv"
)

func PostString(req *go_http.Request, param string) (string, error) {

	raw_value := req.PostFormValue(param)
	return sanitize.SanitizeString(raw_value, sn_opts)
}

func GetInt64(req *go_http.Request, param string) (int64, error) {

	str_value, err := GetString(req, param)

	if err != nil {
		return -1, err
	}

	return strconv.ParseInt(str_value, 10, 64)
}

func PostInt64(req *go_http.Request, param string) (int64, error) {

	str_value, err := PostString(req, param)

	if err != nil {
		return -1, err
	}

	return strconv.ParseInt(str_value, 10, 64)
}
