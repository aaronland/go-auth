package fs

import (
	"context"
	"fmt"
	"github.com/aaronland/go-auth/database"
	"github.com/aaronland/go-auth/session"
	"net/url"
	"os"
	"path/filepath"
	"sync"
)

const FSDATABASE_SESSIONS string = "sessions"

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

func (db *FSSessionsDatabase) AddSession(ctx context.Context, sess *session.SessionRecord) error {

	db.mu.Lock()
	defer db.mu.Unlock()

	sess_path := db.sessionPath(sess.SessionId)

	err := marshalData(sess, sess_path)

	if err != nil {
		return err
	}

	return nil
}

func (db *FSSessionsDatabase) UpdateSession(ctx context.Context, sess *session.SessionRecord) error {

	sess_path := db.sessionPath(sess.SessionId)
	err := marshalData(sess, sess_path)

	if err != nil {
		return err
	}

	return nil
}

func (db *FSSessionsDatabase) RemoveSession(ctx context.Context, sess *session.SessionRecord) error {

	sess_path := db.sessionPath(sess.SessionId)
	return os.Remove(sess_path)
}

func (db *FSSessionsDatabase) GetSessionWithId(ctx context.Context, sess_id string) (*session.SessionRecord, error) {

	sess_path := db.sessionPath(sess_id)

	sess, err := unmarshalData(sess_path, "session")

	if err != nil {
		return nil, err
	}

	return sess.(*session.SessionRecord), nil
}

func (db *FSSessionsDatabase) sessionPath(str_id string) string {

	fname := fmt.Sprintf("%s.json", str_id)

	sessions_root := filepath.Join(db.root, FSDATABASE_SESSIONS)
	id_root := filepath.Join(sessions_root, str_id)

	return filepath.Join(id_root, fname)
}
