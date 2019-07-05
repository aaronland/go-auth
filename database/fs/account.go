package fs

import (
	"errors"
	"fmt"
	"github.com/aaronland/go-http-auth/account"
	"github.com/aaronland/go-http-auth/database"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

const FSDATABASE_POINTERS string = "pointers"
const FSDATABASE_ACCOUNTS string = "accounts"

type FSAccountDatabase struct {
	database.AccountDatabase
	root string
	mu *sync.RWMutex
}

func NewFSAccountDatabase(root string) (database.AccountDatabase, error) {

	abs_root, err := ensureRoot(root)

	if err != nil {
		return nil, err
	}

	subdirs := []string{
		FSDATABASE_POINTERS,
		FSDATABASE_ACCOUNTS,
	}

	for _, dir := range subdirs {

		subdir := filepath.Join(abs_root, dir)

		_, err = os.Stat(subdir)

		if err != nil {

			err = os.Mkdir(subdir, 0700)
		}

		if err != nil {
			return nil, err
		}
	}

	mu := new(sync.RWMutex)

	db := &FSAccountDatabase{
		root: abs_root,
		mu:   mu,
	}

	return db, nil
}

func (db *FSAccountDatabase) AddAccount(acct *account.Account) (*account.Account, error) {

	db.mu.Lock()
	defer db.mu.Unlock()

	pointers := map[string]string{
		"address":  acct.Address.URI,
		"username": acct.Username.Safe,
	}

	for key, id := range pointers {

		if db.pointerExists(key, id) {
			msg := fmt.Sprintf("%s already taken", key) // technically this would leak email addresses...
			return nil, errors.New(msg)
		}
	}

	acct_id, err := database.NewID()

	if err != nil {
		return nil, err
	}

	acct.ID = acct_id

	acct_path := db.accountPath(acct_id)

	err = marshalData(acct, acct_path)

	if err != nil {
		return nil, err
	}

	err = db.setPointers(acct_id, pointers)

	if err != nil {
		// remove acct here?
		return nil, err
	}

	return acct, nil
}

func (db *FSAccountDatabase) setPointers(acct_id int64, pointers map[string]string) error {

	for pointer_key, pointer_id := range pointers {

		err := db.setPointer(acct_id, pointer_key, pointer_id)

		if err != nil {
			return err
		}
	}

	return nil
}

func (db *FSAccountDatabase) setPointer(acct_id int64, pointer_key string, pointer_id string) error {

	pointer_path := db.pointerPath(pointer_key, pointer_id)

	fh, err := os.OpenFile(pointer_path, os.O_CREATE|os.O_WRONLY, 0600)

	if err != nil {
		return err
	}
	
	str_id := strconv.FormatInt(acct_id, 10)

	_, err = fh.Write([]byte(str_id))

	if err != nil {
		return err
	}

	return fh.Close()
}

func (db *FSAccountDatabase) pointerExists(key string, id string) bool {

	pointer_path := db.pointerPath(key, id)

	_, err := os.Stat(pointer_path)

	if err != nil {
		return false
	}

	return true
}

func (db *FSAccountDatabase) pointerPath(key string, id string) string {

	pointers_root := filepath.Join(db.root, FSDATABASE_POINTERS)
	key_root := filepath.Join(pointers_root, key)

	return filepath.Join(key_root, id)
}

func (db *FSAccountDatabase) accountPath(id int64) string {

	str_id := strconv.FormatInt(id, 10)
	fname := fmt.Sprintf("%s.json")

	accounts_root := filepath.Join(db.root, FSDATABASE_ACCOUNTS)
	id_root := filepath.Join(accounts_root, str_id)

	return filepath.Join(id_root, fname)
}
