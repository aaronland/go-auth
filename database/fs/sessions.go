package fs

import (
	"context"
	"errors"
	"fmt"
	"github.com/aaronland/go-auth/session"
	"github.com/aaronland/go-auth/database"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const FSDATABASE_SESSIONS string = "sessions"
const FSDATABASE_SESSIONS_POINTERS string = "sessions_pointers"

type FSSessionsDatabase struct {
	database.SessionsDatabase
	root string
	mu   *sync.RWMutex
}

func init() {

	ctx := context.Background()
	err := database.RegisterSessionsDatabase(ctx, "fs", NewFSSessionsDatabase)

	if err != nil {
		panic(err)
	}
}

func NewFSSessionsDatabase(ctx context.Context, uri string) (database.SessionsDatabase, error) {

	u, err := url.Parse(uri)

	if err != nil {
		return nil, err
	}

	root := u.Path

	abs_root, err := ensureRoot(root)

	if err != nil {
		return nil, err
	}

	subdirs := []string{
		FSDATABASE_SESSIONS_POINTERS,
		FSDATABASE_SESSIONS,
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

	db := &FSSessionsDatabase{
		root: abs_root,
		mu:   mu,
	}

	return db, nil
}

func (db *FSSessionsDatabase) AddSession(acct *session.SessionRecord) (*session.Session, error) {

	db.mu.Lock()
	defer db.mu.Unlock()

	pointers := db.pointersMap(acct)

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

	acct_path := db.sessionPath(acct_id)

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

func (db *FSSessionsDatabase) UpdateSession(acct *session.Session) (*session.Session, error) {

	now := time.Now()
	acct.LastModified = now.Unix()

	acct_path := db.sessionPath(acct.ID)
	err := marshalData(acct, acct_path)

	if err != nil {
		return nil, err
	}

	pointers_map := db.pointersMap(acct)

	err = db.setPointers(acct.ID, pointers_map)

	if err != nil {
		return nil, err
	}

	return acct, nil
}

func (db *FSSessionsDatabase) RemoveSession(acct *session.Session) (*session.Session, error) {

	acct.Status = session.SESSION_STATUS_DELETED
	acct, err := db.UpdateSession(acct)

	if err != nil {
		return nil, err
	}

	pointers_map := db.pointersMap(acct)

	for pointer_key, pointer_id := range pointers_map {
		pointer_path := db.pointerPath(pointer_key, pointer_id)
		os.Remove(pointer_path)
	}

	return acct, nil
}

func (db *FSSessionsDatabase) GetSessionByID(acct_id int64) (*session.Session, error) {

	acct_path := db.sessionPath(acct_id)

	acct, err := unmarshalData(acct_path, "session")

	if err != nil {
		return nil, err
	}

	return acct.(*session.Session), nil
}

func (db *FSSessionsDatabase) GetSessionByEmailAddress(addr string) (*session.Session, error) {
	return db.getSessionByPointer("address", addr)
}

func (db *FSSessionsDatabase) GetSessionByURL(addr string) (*session.Session, error) {
	return db.getSessionByPointer("url", addr)
}

func (db *FSSessionsDatabase) getSessionByPointer(pointer_key string, pointer_id string) (*session.Session, error) {

	acct_id, err := db.getPointer(pointer_key, pointer_id)

	if err != nil {
		return nil, err
	}

	return db.GetSessionByID(acct_id)
}

func (db *FSSessionsDatabase) getPointer(pointer_key string, pointer_id string) (int64, error) {

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

func (db *FSSessionsDatabase) setPointers(acct_id int64, pointers map[string]string) error {

	for pointer_key, pointer_id := range pointers {

		err := db.setPointer(acct_id, pointer_key, pointer_id)

		if err != nil {
			return err
		}
	}

	return nil
}

func (db *FSSessionsDatabase) setPointer(acct_id int64, pointer_key string, pointer_id string) error {

	pointer_path := db.pointerPath(pointer_key, pointer_id)

	err := ensurePath(pointer_path)

	if err != nil {
		return err
	}

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

func (db *FSSessionsDatabase) pointerExists(key string, id string) bool {

	pointer_path := db.pointerPath(key, id)

	_, err := os.Stat(pointer_path)

	if err != nil {
		return false
	}

	return true
}

func (db *FSSessionsDatabase) pointerPath(key string, id string) string {

	pointers_root := filepath.Join(db.root, FSDATABASE_SESSIONS_POINTERS)
	key_root := filepath.Join(pointers_root, key)

	return filepath.Join(key_root, id)
}

func (db *FSSessionsDatabase) sessionPath(id int64) string {

	str_id := strconv.FormatInt(id, 10)
	fname := fmt.Sprintf("%s.json", str_id)

	sessions_root := filepath.Join(db.root, FSDATABASE_SESSIONS)
	id_root := filepath.Join(sessions_root, str_id)

	return filepath.Join(id_root, fname)
}
