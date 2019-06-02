package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/boltdb/bolt"
	"github.com/aaronland/go-auth/account"
	"reflect"
	"regexp"
	"strings"
)

// key prefixes
// membership:{KEY}:{ID}	= JSON | POINTER
// pointer:{KEY}:{ID}		= ID
// lookup:alt_keys:{ID}		= ";" SEPARATED LIST

type BoltDBMembershipDatabase struct {
	account.MembershipDatabase
	bolt_db *bolt.DB
	bucket  string
}

var re_pointer *regexp.Regexp

func init() {
	re_pointer = regexp.MustCompile(`^pointer\:(id)\:(\d+)$`)
}

func NewBoltDBMembershipDatabase(dsn string, bucket string) (account.MembershipDatabase, error) {

	bolt_db, err := bolt.Open(dsn, 0600, nil)

	if err != nil {
		return nil, err
	}

	tx, err := bolt_db.Begin(true)

	if err != nil {
		return nil, err
	}

	defer tx.Rollback()

	_, err = tx.CreateBucketIfNotExists([]byte(bucket))

	if err != nil {
		return nil, err
	}

	err = tx.Commit()

	if err != nil {
		return nil, err
	}

	db := BoltDBMembershipDatabase{
		bolt_db: bolt_db,
		bucket:  bucket,
	}

	return &db, nil
}

// func (db *BoltDBMembershipDatabase) GetMembershipByIdentifier(key string, id string, m account.Membership) error {

func (db *BoltDBMembershipDatabase) GetMembershipByIdentifier(key string, id string) (account.Membership, error) {

	var m account.Membership

	test_m := reflect.TypeOf(m)
	fmt.Println("DEBUG", test_m)

	err := db.bolt_db.View(func(tx *bolt.Tx) error {

		b := tx.Bucket([]byte(db.bucket))

		k := MembershipKey(key, id)
		v := b.Get([]byte(k))

		if v == nil {
			return account.ErrNoMembership{}
		}

		if re_pointer.Match(v) {

			match := re_pointer.FindSubmatch(v)
			other_key := string(match[1])
			other_id := string(match[0])

			if other_key == key && other_id == id {
				return errors.New("Infinite pointer")
			}

			other_m, err := db.GetMembershipByIdentifier(other_key, other_id)

			if err != nil {
				return err
			}

			m = other_m
			return nil
		}

		// WILL THIS EVEN WORK? HOW WILL IT KNOW _WHICH_ IMPLEMENTATION
		// OF THE INTERFACE TO UNMARSHAL (20190125/thisisaaronland)

		err := json.Unmarshal(v, &m)

		if err != nil {
			return err
		}

		return nil
	})

	return m, err
}

func (db *BoltDBMembershipDatabase) AddMembership(m account.Membership, alt_keys ...string) error {

	id := m.Id()

	enc_m, err := json.Marshal(m)

	if err != nil {
		return err
	}

	tx, err := db.bolt_db.Begin(true)

	if err != nil {
		return err
	}

	defer tx.Rollback()

	err = db.bolt_db.Update(func(tx *bolt.Tx) error {

		b := tx.Bucket([]byte(db.bucket))
		k := MembershipKey("id", id)

		err := b.Put([]byte(k), enc_m)

		if err != nil {
			return err
		}

		// store pointers for alt_keys

		for _, other_key := range alt_keys {

			other, ok := m.GetProperty(other_key)

			if !ok {
				msg := fmt.Sprintf("Membership is missing '%s' alt key", other_key)
				return errors.New(msg)
			}

			// HEY WAIT... HOW DO WE KNOW THAT THIS IS A STRING???
			// (20190125/thisisaaronland)

			other_v := other.(string)

			k := MembershipKey(other_key, other_v)
			v := fmt.Sprintf("pointer:id:%s", id)

			// CHECK TO SEE IF k ALREADY EXISTS (AND
			// DOESN'T ALREADY POINT TO THIS RECORD)

			test_v := b.Get([]byte(k))

			// AGAIN... R U A STRING 4 REAL???
			// (20190125/thisisaaronland)

			if test_v != nil && string(test_v) != v {
				msg := fmt.Sprintf("Alt key '%s' already exists", k)
				return errors.New(msg)
			}

			err := b.Put([]byte(k), []byte(v))

			if err != nil {
				return err
			}
		}

		// store a pointer (lookup) to all the (alt_key) pointers
		// we'll need this for deleting records

		lookup_k := fmt.Sprintf("internal:alt_keys:%s", id)
		lookup_v := strings.Join(alt_keys, ":")

		err = b.Put([]byte(lookup_k), []byte(lookup_v))

		if err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return err
	}

	return tx.Commit()
}

func (db *BoltDBMembershipDatabase) DeleteMembership(m account.Membership) error {
	return errors.New("Please write me")
}

func MembershipKey(key string, id string) string {
	return fmt.Sprintf("membership:%s:%s", key, id)
}

/*
func (db *BoltDBMembershipDatabase) nextID() (int64, error) {

	var id int64
	var err error

	db.bolt_db.Update(func(tx *bolt.Tx) error {

		b := tx.Bucket([]byte(db.bucket))
		id, err = b.NextSequence()

		return err
	})

	return id, err
}
*/
