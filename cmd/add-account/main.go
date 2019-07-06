package main

import (
	"flag"
	"github.com/aaronland/go-string/dsn"
	"github.com/aaronland/go-http-auth/account"
	"github.com/aaronland/go-http-auth/database/fs"
	"log"
)

func main() {

	email := flag.String("email", "", "...")
	username := flag.String("username", "", "...")
	password := flag.String("password", "", "...")

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

	acct, err := account.NewAccount(*email, *password, *username)

	if err != nil {
		log.Fatal(err)
	}

	acct, err = account_db.AddAccount(acct)

	if err != nil {
		log.Fatal(err)
	}

	log.Println(acct.ID)
}
