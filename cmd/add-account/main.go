package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/aaronland/go-http-auth/account"
	"github.com/aaronland/go-http-auth/database/fs"
	"github.com/aaronland/go-string/dsn"
	"golang.org/x/crypto/ssh/terminal"
	"log"
	"os"
	"strings"
	"syscall"
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

		for {

			fmt.Print("Enter Password: ")

			pswd1, err := terminal.ReadPassword(int(syscall.Stdin))

			if err != nil {
				log.Fatal(err)
			}

			fmt.Println("")
			fmt.Print("Enter Password (again): ")

			pswd2, err := terminal.ReadPassword(int(syscall.Stdin))

			if err != nil {
				log.Fatal(err)
			}

			fmt.Println("")

			if strings.Compare(string(pswd1), string(pswd2)) != 0 {
				log.Println("Passwords do not match")
				continue
			}

			*password = string(pswd1)
			break
		}
	}

	// scrub email, password, username here...

	acct, err := account.NewAccount(*email, *password, *username)

	if err != nil {
		log.Fatal(err)
	}

	secret, err := acct.GetMFASecret()

	if err != nil {
		log.Fatal(err)
	}

	log.Println(acct.ID, secret)
	return

	acct, err = account_db.AddAccount(acct)

	if err != nil {
		log.Fatal(err)
	}

	log.Println(acct.ID)
}
