package api

import (
	"context"
	"errors"
	"github.com/aaronland/go-artisanal-integers"
	"github.com/tidwall/gjson"
	"io/ioutil"
	_ "log"
	"net/http"
	"net/url"
)

func init() {
	ctx := context.Background()
	cl := NewAPIClient()
	artisanalinteger.RegisterClient(ctx, "londonintegers", cl)
}

type LondonIntegersClient interface {
	ExecuteMethod(string, *url.Values) (*APIResponse, error)
}

type APIClient struct {
	artisanalinteger.Client
	LondonIntegersClient // see above
	isa                    string
	http_client            *http.Client
	Scheme                 string
	Host                   string
	Endpoint               string
}

type APIResponse struct {
	raw []byte
}

func (rsp *APIResponse) Int() (int64, error) {

	r := gjson.GetBytes(rsp.raw, "integer")

	if !r.Exists() {
		return -1, errors.New("Failed to generate any integers")
	}

	i := r.Int()
	return i, nil
}

func (rsp *APIResponse) Ok() (bool, error) {

	r := gjson.GetBytes(rsp.raw, "stat")

	if !r.Exists() {
		return false, errors.New("Not ok")
	}

	stat := r.String()

	if stat != "ok" {
		return false, errors.New("Not ok")
	}

	return true, nil
}

func NewAPIClient() artisanalinteger.Client {

	http_client := &http.Client{}

	return &APIClient{
		Scheme:      "http",
		Host:        "api.londonintegers.com",
		Endpoint:    "",
		http_client: http_client,
	}
}

func (client *APIClient) NextInt() (int64, error) {

	params := url.Values{}
	method := "london.integers.create"

	rsp, err := client.ExecuteMethod(method, &params)

	if err != nil {
		return -1, err
	}

	return rsp.Int()
}

func (client *APIClient) ExecuteMethod(method string, params *url.Values) (*APIResponse, error) {

	url := client.Scheme + "://" + client.Host + "/" + client.Endpoint + "/" + method

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, err
	}

	req.URL.RawQuery = (*params).Encode()

	req.Header.Add("Accept-Encoding", "gzip")

	rsp, err := client.http_client.Do(req)

	if err != nil {
		return nil, err
	}

	defer rsp.Body.Close()

	body, err := ioutil.ReadAll(rsp.Body)

	if err != nil {
		return nil, err
	}

	r := APIResponse{
		raw: body,
	}

	return &r, nil
}
