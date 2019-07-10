package www

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/aaronland/go-http-auth"
	"github.com/aaronland/go-http-auth/account"
	"github.com/aaronland/go-http-auth/database"
	"github.com/aaronland/go-http-auth/token"
	"github.com/aaronland/go-http-sanitize"
	"github.com/pquerna/otp/totp"
	_ "log"
	"net/http"
	"sort"
	"sync"
)

type SiteTokenHandlerOptions struct {
	Credentials         auth.Credentials
	AccountDatabase     database.AccountDatabase
	AccessTokenDatabase database.AccessTokenDatabase
}

type SiteTokenReponse struct {
	AccessToken string
	Expires     int64
	Permissions int
}

func GetSiteTokenForAccount(ctx context.Context, token_db database.AccessTokenDatabase, acct *account.Account) (*token.Token, error) {

	possible := make([]*token.Token, 0)
	mu := new(sync.RWMutex)

	cb := func(t *token.Token) error {

		if !t.IsSiteToken() {
			return nil
		}

		if !t.IsActive() {
			return nil
		}

		mu.Lock()
		defer mu.Unlock()

		possible = append(possible, t)
		return nil
	}

	err := token_db.ListAccessTokensForAccount(ctx, acct, cb)

	if err != nil {
		return nil, err
	}

	count_possible := len(possible)

	switch count_possible {

	case 0:

		t, err := token.NewSiteTokenForAccount(acct)

		if err != nil {
			return nil, err
		}

		return token_db.AddToken(t)

	case 1:
		return possible[0], nil

	default:

		sorted := make([]int64, count_possible)
		lookup := make(map[int64]*token.Token)

		for i, t := range possible {
			sorted[i] = t.ID
			lookup[t.ID] = t
		}

		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i] > sorted[j] // most recent first
		})

		current := sorted[0]
		token := lookup[current]

		go func() {
			for _, id := range sorted[1:] {

				t := lookup[id]
				token_db.DeleteToken(t)
			}
		}()

		return token, nil
	}

	return nil, errors.New("How did we get here")
}

func SiteTokenHandler(opts *SiteTokenHandlerOptions) http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		switch req.Method {

		case "POST":

			email, err := sanitize.PostString(req, "email")

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			if email == "" {
				http.Error(rsp, "Missing email", http.StatusInternalServerError)
				return
			}

			password, err := sanitize.PostString(req, "password")

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			if password == "" {
				http.Error(rsp, "Missing password", http.StatusInternalServerError)
				return
			}

			code, err := sanitize.PostString(req, "code")

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			if code == "" {
				http.Error(rsp, "Missing code", http.StatusInternalServerError)
				return
			}

			acct, err := opts.AccountDatabase.GetAccountByEmailAddress(email)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			if !acct.IsEnabled() {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			pswd, err := acct.GetPassword()

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			err = pswd.Compare(password)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			mfa := acct.MFA

			if mfa == nil {
				http.Error(rsp, "MFA not configured", http.StatusInternalServerError)
				return
			}

			secret, err := mfa.GetSecret()

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			valid := totp.Validate(code, secret)

			if !valid {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			site_token, err := GetSiteTokenForAccount(req.Context(), opts.AccessTokenDatabase, acct)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			token_rsp := SiteTokenReponse{
				AccessToken: site_token.AccessToken,
				Expires:     site_token.Expires,
				Permissions: site_token.Permissions,
			}

			enc, err := json.Marshal(token_rsp)

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusInternalServerError)
				return
			}

			rsp.Write(enc)
			return

		default:
			http.Error(rsp, "Unsupported method", http.StatusMethodNotAllowed)
			return

		}
	}

	return http.HandlerFunc(fn)
}
