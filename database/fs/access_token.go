package fs

import (
	"context"
	"errors"
	"fmt"
	"github.com/aaronland/go-auth/account"
	"github.com/aaronland/go-auth/database"
	"github.com/aaronland/go-auth/token"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const FSDATABASE_TOKENS string = "tokens"
const FSDATABASE_TOKENS_POINTERS string = "tokens_pointers"

type FSAccessTokenDatabase struct {
	database.AccessTokenDatabase
	root string
	mu   *sync.RWMutex
}

func NewFSAccessTokenDatabase(root string) (database.AccessTokenDatabase, error) {

	abs_root, err := ensureRoot(root)

	if err != nil {
		return nil, err
	}

	subdirs := []string{
		FSDATABASE_TOKENS_POINTERS,
		FSDATABASE_TOKENS,
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

	db := &FSAccessTokenDatabase{
		root: abs_root,
		mu:   mu,
	}

	return db, nil
}

func (db *FSAccessTokenDatabase) pointersMap(tkn *token.Token) map[string]string {

	pointers_map := map[string]string{
		"access_token": tkn.AccessToken,
	}

	return pointers_map
}

func (db *FSAccessTokenDatabase) AddToken(tkn *token.Token) (*token.Token, error) {

	db.mu.Lock()
	defer db.mu.Unlock()

	pointers := db.pointersMap(tkn)

	for key, id := range pointers {

		if db.pointerExists(key, id) {
			msg := fmt.Sprintf("%s already taken", key) // technically this would leak email addresses...
			return nil, errors.New(msg)
		}
	}

	tkn_id, err := database.NewID()

	if err != nil {
		return nil, err
	}

	tkn.ID = tkn_id

	tkn_path := db.tokenPath(tkn_id)

	err = marshalData(tkn, tkn_path)

	if err != nil {
		return nil, err
	}

	err = db.setPointers(tkn_id, pointers)

	if err != nil {
		// remove tkn here?
		return nil, err
	}

	return tkn, nil
}

func (db *FSAccessTokenDatabase) UpdateToken(tkn *token.Token) (*token.Token, error) {

	now := time.Now()
	tkn.LastModified = now.Unix()

	tkn_path := db.tokenPath(tkn.ID)
	err := marshalData(tkn, tkn_path)

	if err != nil {
		return nil, err
	}

	pointers_map := db.pointersMap(tkn)

	err = db.setPointers(tkn.ID, pointers_map)

	if err != nil {
		return nil, err
	}

	return tkn, nil
}

func (db *FSAccessTokenDatabase) DeleteToken(tkn *token.Token) (*token.Token, error) {

	tkn.Status = token.TOKEN_STATUS_DELETED
	tkn, err := db.UpdateToken(tkn)

	if err != nil {
		return nil, err
	}

	pointers_map := db.pointersMap(tkn)

	for pointer_key, pointer_id := range pointers_map {
		pointer_path := db.pointerPath(pointer_key, pointer_id)
		os.Remove(pointer_path)
	}

	return tkn, nil
}

func (db *FSAccessTokenDatabase) GetTokenByID(tkn_id int64) (*token.Token, error) {

	tkn_path := db.tokenPath(tkn_id)

	tkn, err := unmarshalData(tkn_path, "token")

	if err != nil {
		return nil, err
	}

	return tkn.(*token.Token), nil
}

func (db *FSAccessTokenDatabase) GetTokenByAccessToken(access_token string) (*token.Token, error) {
	return db.getTokenByPointer("access_token", access_token)
}

func (db *FSAccessTokenDatabase) ListAccessTokens(ctx context.Context, cb database.ListAccessTokensFunc) error {

	tokens_root := filepath.Join(db.root, FSDATABASE_TOKENS)

	local_cb := func(ctx context.Context, path string) error {

		tkn, err := unmarshalData(path, "token")

		if err != nil {
			return err
		}

		return cb(tkn.(*token.Token))
	}

	return crawlDatabase(ctx, tokens_root, local_cb)
}

func (db *FSAccessTokenDatabase) ListAccessTokensForAccount(ctx context.Context, acct *account.Account, cb database.ListAccessTokensFunc) error {

	local_cb := func(t *token.Token) error {

		if t.AccountID != acct.ID {
			return nil
		}

		return cb(t)
	}

	return db.ListAccessTokens(ctx, local_cb)
}

func (db *FSAccessTokenDatabase) getTokenByPointer(pointer_key string, pointer_id string) (*token.Token, error) {

	tkn_id, err := db.getPointer(pointer_key, pointer_id)

	if err != nil {
		return nil, err
	}

	return db.GetTokenByID(tkn_id)
}

func (db *FSAccessTokenDatabase) getPointer(pointer_key string, pointer_id string) (int64, error) {

	pointer_path := db.pointerPath(pointer_key, pointer_id)

	fh, err := os.Open(pointer_path)

	if err != nil {
		return -1, err
	}

	body, err := ioutil.ReadAll(fh)

	if err != nil {
		return -1, err
	}

	str_id := string(body)
	return strconv.ParseInt(str_id, 10, 64)
}

func (db *FSAccessTokenDatabase) setPointers(tkn_id int64, pointers map[string]string) error {

	for pointer_key, pointer_id := range pointers {

		err := db.setPointer(tkn_id, pointer_key, pointer_id)

		if err != nil {
			return err
		}
	}

	return nil
}

func (db *FSAccessTokenDatabase) setPointer(tkn_id int64, pointer_key string, pointer_id string) error {

	pointer_path := db.pointerPath(pointer_key, pointer_id)

	err := ensurePath(pointer_path)

	if err != nil {
		return err
	}

	fh, err := os.OpenFile(pointer_path, os.O_CREATE|os.O_WRONLY, 0600)

	if err != nil {
		return err
	}

	str_id := strconv.FormatInt(tkn_id, 10)

	_, err = fh.Write([]byte(str_id))

	if err != nil {
		return err
	}

	return fh.Close()
}

func (db *FSAccessTokenDatabase) pointerExists(key string, id string) bool {

	pointer_path := db.pointerPath(key, id)

	_, err := os.Stat(pointer_path)

	if err != nil {
		return false
	}

	return true
}

func (db *FSAccessTokenDatabase) pointerPath(key string, id string) string {

	pointers_root := filepath.Join(db.root, FSDATABASE_TOKENS_POINTERS)
	key_root := filepath.Join(pointers_root, key)

	return filepath.Join(key_root, id)
}

func (db *FSAccessTokenDatabase) tokenPath(id int64) string {

	str_id := strconv.FormatInt(id, 10)
	fname := fmt.Sprintf("%s.json", str_id)

	tokens_root := filepath.Join(db.root, FSDATABASE_TOKENS)
	id_root := filepath.Join(tokens_root, str_id)

	return filepath.Join(id_root, fname)
}
