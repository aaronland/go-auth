package main

import (
       "fmt"
       "flag"
       "log"
	"github.com/aaronland/go-http-auth/database/fs"
	"github.com/aaronland/go-string/dsn"
)

func main() {

	addr := flag.String("email", "", "...")
     accts_dsn := flag.String("accounts-dsn", "", "...")

     flag.Parse()

	accts_cfg, err := dsn.StringToDSNWithKeys(*accts_dsn, "root")

	if err != nil {
		log.Fatal(err)
	}

	account_db, err := fs.NewFSAccountDatabase(accts_cfg["root"])

	if err != nil {
		log.Fatal(err)
	}

	acct, err := account_db.GetAccountByEmailAddress(*addr)

	if err != nil {
		log.Fatal(err)
	}

	mfa := acct.MFA

	if mfa == nil {
		log.Fatal("MFA not configured")
	}

	code, err := mfa.GetCode()

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(code)
}
