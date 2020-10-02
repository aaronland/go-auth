package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/aaronland/go-auth/database"
	_ "github.com/aaronland/go-auth/database/fs"
	"log"
)

func main() {

	addr := flag.String("email", "", "...")
	accts_uri := flag.String("accounts-uri", "", "...")

	flag.Parse()

	ctx := context.Background()

	account_db, err := database.NewAccountsDatabase(ctx, *accts_uri)

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
