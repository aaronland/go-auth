package cli

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"log"
	"strings"
	"syscall"
)

type GetPasswordOptions struct {
	MinLength int
	Repeat    bool
}

func DefaultGetPasswordOptions() *GetPasswordOptions {

	opts := GetPasswordOptions{
		MinLength: 8,
		Repeat:    true,
	}

	return &opts
}

func GetPassword(opts *GetPasswordOptions) (string, error) {

	if opts.MinLength <= 0 {
		return "", errors.New("You must specify a minimum password length")
	}

	password := ""

	for {

		fmt.Print("Enter Password: ")

		pswd1, err := terminal.ReadPassword(int(syscall.Stdin))

		if err != nil {
			return "", err
		}

		if opts.Repeat {

			fmt.Println("")
			fmt.Print("Enter Password (again): ")

			pswd2, err := terminal.ReadPassword(int(syscall.Stdin))

			if err != nil {
				return "", nil
			}

			fmt.Println("")

			if strings.Compare(string(pswd1), string(pswd2)) != 0 {
				log.Println("Passwords do not match")
				continue
			}
		}

		password = string(pswd1)
		password = strings.TrimSpace(password)

		if len(password) < opts.MinLength {
			log.Println("Password is too short")
			password = ""
			continue
		}

		break
	}

	return password, nil
}
