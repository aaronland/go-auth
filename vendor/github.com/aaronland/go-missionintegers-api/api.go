package api

import (
	"context"
	"encoding/json"
	"github.com/aaronland/go-artisanal-integers"
	"io/ioutil"
	_ "log"
	"net/http"
	"net/url"
	"strconv"
)

func init() {
	ctx := context.Background()
	cl := NewAPIClient()
	artisanalinteger.RegisterClient(ctx, "missionintegers", cl)
}

type MissionIntegersClient interface {
	ExecuteMethod(string, *url.Values) (*APIResponse, error)
}

type APIResponse struct {
	raw []byte
}

func (rsp *APIResponse) String() string {
	return string(rsp.raw)
}

type APIError struct {
	error
	Message string `json:"message"`
}

func (e APIError) Error() string {
	return e.Message
}

type APIClient struct {
	artisanalinteger.Client
	MissionIntegersClient // see above
	isa                   string
	http_client           *http.Client
	Scheme                string
	Host                  string
	Endpoint              string
}

func NewAPIClient() artisanalinteger.Client {

	http_client := &http.Client{}

	return &APIClient{
		Scheme:      "https",
		Host:        "missionintegers.com",
		Endpoint:    "api",
		http_client: http_client,
	}
}

func (client *APIClient) NextInt() (int64, error) {

	params := url.Values{}
	method := "integer"

	rsp, err := client.ExecuteMethod(method, &params)

	if err != nil {
		return -1, err
	}

	str_int := rsp.String()

	int, err := strconv.ParseInt(str_int, 10, 64)

	if err != nil {
		return -1, err
	}

	return int, nil
}

func (client *APIClient) ExecuteMethod(method string, params *url.Values) (*APIResponse, error) {

	// please make me a proper net/url thingy...

	url := client.Scheme + "://" + client.Host + "/" + client.Endpoint + "/" + method

	req, err := http.NewRequest("POST", url, nil)

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

	var api_err APIError

	err = json.Unmarshal(body, &api_err)

	if err == nil {
		return nil, api_err
	}

	r := APIResponse{
		raw: body,
	}

	return &r, nil
}
