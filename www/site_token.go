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
	"log"
	"net/http"
	"sort"
	"sync"
)

const CONTEXT_SITE_TOKEN string = "site_token"

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

/*
func GetSiteTokenForAccountWithRequest(req *http.Request, token_db database.AccessTokenDatabase, acct *account.Account) (*token.Token, error) {

	ctx := req.Context()

     	v := ctx.Value(CONTEXT_SITE_TOKEN)

	if v != nil {
		site_token := v.(*token.Token)
		return site_token, nil
	}

	return GetSiteTokenForAccount(ctx, token_db, acct)
}
*/

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

	var site_token *token.Token

	count_possible := len(possible)

	switch count_possible {

	case 0:

		t, err := token.NewSiteTokenForAccount(acct)

		if err != nil {
			return nil, err
		}

		t, err = token_db.AddToken(t)

		if err != nil {
			return nil, err
		}

		site_token = t

	case 1:
		site_token = possible[0]

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
				_, err := token_db.DeleteToken(t)

				if err != nil {
					log.Printf("Failed to delete token (%d) %s\n", t.ID, err)
				}
			}
		}()

		site_token = token
	}

	if site_token == nil {
		return nil, errors.New("How did we get here")
	}

	return site_token, nil
}

func SiteTokenHandler(opts *SiteTokenHandlerOptions) http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		switch req.Method {

		case "POST":

			email, err := sanitize.PostString(req, "email")

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusBadRequest)
				return
			}

			if email == "" {
				http.Error(rsp, "Missing email", http.StatusBadRequest)
				return
			}

			password, err := sanitize.PostString(req, "password")

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusBadRequest)
				return
			}

			if password == "" {
				http.Error(rsp, "Missing password", http.StatusBadRequest)
				return
			}

			code, err := sanitize.PostString(req, "code")

			if err != nil {
				http.Error(rsp, err.Error(), http.StatusBadRequest)
				return
			}

			if code == "" {
				http.Error(rsp, "Missing code", http.StatusBadRequest)
				return
			}

			acct, err := opts.AccountDatabase.GetAccountByEmailAddress(email)

			if err != nil {
				http.Error(rsp, "Forbidden", http.StatusForbidden)
				return
			}

			if !acct.IsEnabled() {
				http.Error(rsp, "Forbidden", http.StatusForbidden)
				return
			}

			pswd, err := acct.GetPassword()

			if err != nil {
				http.Error(rsp, "Forbidden", http.StatusForbidden)
				return
			}

			err = pswd.Compare(password)

			if err != nil {
				http.Error(rsp, "Forbidden", http.StatusForbidden)
				return
			}

			mfa := acct.MFA

			if mfa == nil {
				http.Error(rsp, "Forbidden", http.StatusForbidden)
				return
			}

			secret, err := mfa.GetSecret()

			if err != nil {
				http.Error(rsp, "Forbidden", http.StatusForbidden)
				return
			}

			valid := totp.Validate(code, secret)

			if !valid {
				http.Error(rsp, "Invalid code", http.StatusInternalServerError)
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
