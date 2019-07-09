package www

import (

)

func PasswordHandler(auth auth.HTTPAuthenticator, templates *template.Template, t_name string) http.Handler {

     type PasswordVars struct {
     	Account *account.Account
	Error error
     }

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		acct, err := auth.GetAccountForRequest(req)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		switch req.Method {

		case "GET":

		vars := PasswordVars{
			Account: acct,
		}

		err = templates.ExecuteTemplate(rsp, t_name, vars)

		if err != nil {
			http.Error(rsp, err.Error(), http.StatusInternalServerError)
			return
		}

		case "POST":

			str_old_password, err := sanitize.PostString(req, "old_password")

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusBadRequest)
				return
			}

			str_new_password, err := sanitize.PostString(req, "new_password")

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusBadRequest)
				return
			}

			if str_old_password == str_new_password {
				// 
			}

			p, err := acct.GetPassword()

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			err = p.Compare(str_old_password)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			acct, err = acct.UpdatePassword(str_new_password)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			// FIX ME

			acct, err = account_db.UpdateAccount(acct)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			// FIX ME

			err = ep_auth.setAuthCookie(rsp, acct)

			if err != nil {
				go_http.Error(rsp, err.Error(), go_http.StatusInternalServerError)
				return
			}

			// redir to req.URL.Path...
			
		default:
			go_http.Error(rsp, "Unsupported method", go_http.StatusMethodNotAllowed)
			return
		}

		return
	}

	// FIX ME...CRUMBS

	return http.HandlerFunc(fn)
}

