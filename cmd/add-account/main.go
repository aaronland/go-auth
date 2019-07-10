package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/database/fs"
	"github.com/aaronland/go-password/cli"
	"github.com/aaronland/go-string/dsn"
	"log"
	"os"
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

	account_db, err := fs.NewFSAccountsDatabase(accts_cfg["root"])

	if err != nil {
		log.Fatal(err)
	}

	reader := bufio.NewReader(os.Stdin)

	if *email == "" {

		fmt.Print("Email address: ")

		addr, err := reader.ReadString('\n')

		if err != nil {
			log.Fatal(err)
		}

		*email = addr
	}

	if *username == "" {

		fmt.Print("Username: ")
		name, err := reader.ReadString('\n')

		if err != nil {
			log.Fatal(err)
		}

		*username = name
	}

	if *password == "" {

		pswd_opts := cli.DefaultGetPasswordOptions()
		pswd, err := cli.GetPassword(pswd_opts)

		if err != nil {
			log.Fatal(err)
		}

		*password = pswd
	}

	// scrub, validate and sanity check email, password, username here...

	acct, err := account.NewAccount(*email, *password, *username)

	if err != nil {
		log.Fatal(err)
	}

	acct, err = account_db.AddAccount(acct)

	if err != nil {
		log.Fatal(err)
	}

	secret, err := acct.GetMFASecret()

	if err != nil {
		log.Fatal(err)
	}

	log.Println(acct.ID, secret)
}
