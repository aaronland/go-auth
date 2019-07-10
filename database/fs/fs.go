package fs

import (
	"context"
	"encoding/json"
	"errors"
	_ "fmt"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/token"
	"github.com/whosonfirst/walk"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

func ensureRoot(root string) (string, error) {

	abs_root, err := filepath.Abs(root)

	if err != nil {
		return "", err
	}

	info, err := os.Stat(abs_root)

	if err != nil {
		return "", err
	}

	if !info.IsDir() {
		return "", errors.New("Root is not a directory")
	}

	/*
		if info.Mode() != 0700 {
			return "", errors.New("Root permissions must be 0700")
		}
	*/

	return abs_root, nil
}

func ensurePath(path string) error {

	// validate this path please...

	root := filepath.Dir(path)

	_, err := os.Stat(root)

	if err != nil {

		err = os.MkdirAll(root, 0700)
	}

	return err
}

func marshalData(data interface{}, path string) error {

	err := ensurePath(path)

	if err != nil {
		return err
	}

	enc, err := json.Marshal(data)

	if err != nil {
		return err
	}

	fh, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)

	if err != nil {
		return err
	}

	fh.Write(enc)
	return fh.Close()
}

func unmarshalData(path string, data_type string) (interface{}, error) {

	switch data_type {
	case "account", "token":
		// pass
	default:
		return nil, errors.New("Unsupported interface")
	}

	fh, err := os.Open(path)

	if err != nil {
		return nil, err
	}

	defer fh.Close()

	body, err := ioutil.ReadAll(fh)

	if err != nil {
		return nil, err
	}

	var data interface{}

	switch data_type {

	case "account":

		var acct *account.Account
		err = json.Unmarshal(body, &acct)

		if err == nil {
			data = acct
		}

	case "token":

		var tkn *token.Token
		err = json.Unmarshal(body, &tkn)

		if err == nil {
			data = tkn
		}

	default:
		err = errors.New("Unsupported data type")
	}

	return data, err
}

func crawlDatabase(ctx context.Context, root string, cb func(context.Context, string) error) error {

	walker := func(path string, info os.FileInfo, err error) error {

		select {
		case <-ctx.Done():
			return nil
		default:
			// pass
		}

		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if !strings.HasSuffix(path, ".json") {
			return nil
		}

		return cb(ctx, path)
	}

	return walk.Walk(root, walker)
}
