package params

import (
	"github.com/whosonfirst/go-sanitize"
)

var sn_opts *sanitize.Options

func init() {
	sn_opts = sanitize.DefaultOptions()
}
