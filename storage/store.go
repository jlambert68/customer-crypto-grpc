package storage

import (
	"database/sql"
	"errors"
	"fmt"
	_ "modernc.org/sqlite"
)

type Store struct{ DB *sql.DB }

type WriteMode uint8

const (
	WriteInitial WriteMode = iota
	WriteOwnerUpdate
	WriteRotation
)

func Open(path string) (*Store, error) {
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	_, e = db.Exec(`PRAGMA foreign_keys=ON;
 CREATE TABLE IF NOT EXISTS principals(id TEXT PRIMARY KEY, role TEXT NOT NULL, token TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, server_secret BLOB NOT NULL, server_public BLOB NOT NULL, client_public BLOB NOT NULL);
 CREATE TABLE IF NOT EXISTS grants(principal_id TEXT NOT NULL, object_id TEXT NOT NULL, PRIMARY KEY(principal_id,object_id));
 CREATE TABLE IF NOT EXISTS object_owners(object_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS objects(id TEXT NOT NULL, version INTEGER NOT NULL, ciphertext BLOB NOT NULL, PRIMARY KEY(id,version));
 CREATE TABLE IF NOT EXISTS rotation_jobs(object_id TEXT PRIMARY KEY, state TEXT NOT NULL, next_version INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, principal_id TEXT NOT NULL, action TEXT NOT NULL, object_id TEXT NOT NULL DEFAULT '', at TEXT DEFAULT CURRENT_TIMESTAMP);`)
	if e != nil {
		db.Close()
		return nil, e
	}
	return &Store{db}, nil
}
func (s *Store) Exec(q string, args ...any) error { _, e := s.DB.Exec(q, args...); return e }
func (s *Store) Authorized(id, object string) bool {
	var n int
	e := s.DB.QueryRow(`SELECT COUNT(*) FROM principals p JOIN grants g ON p.id=g.principal_id WHERE p.id=? AND g.object_id=? AND p.revoked=0`, id, object).Scan(&n)
	return e == nil && n == 1
}
func (s *Store) Owner(id, object string) bool {
	var n int
	e := s.DB.QueryRow(`SELECT COUNT(*) FROM object_owners WHERE principal_id=? AND object_id=?`, id, object).Scan(&n)
	return e == nil && n == 1
}
func (s *Store) Principal(id string) (role string, secret, serverPub, clientPub []byte, revoked bool, err error) {
	var r int
	err = s.DB.QueryRow(`SELECT role,server_secret,server_public,client_public,revoked FROM principals WHERE id=?`, id).Scan(&role, &secret, &serverPub, &clientPub, &r)
	return role, secret, serverPub, clientPub, r != 0, err
}
func (s *Store) Current(id string) (uint64, error) {
	var v uint64
	e := s.DB.QueryRow(`SELECT COALESCE(MAX(version),0) FROM objects WHERE id=?`, id).Scan(&v)
	if e != nil {
		return 0, e
	}
	return v, nil
}
func (s *Store) Object(id string, v uint64) ([]byte, error) {
	var b []byte
	e := s.DB.QueryRow(`SELECT ciphertext FROM objects WHERE id=? AND version=?`, id, v).Scan(&b)
	return b, e
}
func (s *Store) CheckToken(id, token string) error {
	var n int
	e := s.DB.QueryRow(`SELECT COUNT(*) FROM principals WHERE id=? AND token=?`, id, token).Scan(&n)
	if e != nil || n != 1 {
		return errors.New("invalid identity token")
	}
	return nil
}
func (s *Store) GrantIDs(object string) ([]string, error) {
	rows, e := s.DB.Query(`SELECT p.id FROM principals p JOIN grants g ON p.id=g.principal_id WHERE g.object_id=? AND p.revoked=0 ORDER BY p.id`, object)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var x string
		if e = rows.Scan(&x); e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}
func (s *Store) RotationJob(id string) (uint64, string, error) {
	var v uint64
	var state string
	e := s.DB.QueryRow(`SELECT next_version,state FROM rotation_jobs WHERE object_id=?`, id).Scan(&v, &state)
	return v, state, e
}
func (s *Store) Pending() ([]string, error) {
	rows, e := s.DB.Query(`SELECT object_id FROM rotation_jobs WHERE state='pending' ORDER BY object_id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func (s *Store) Revoke(id string) error {
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var role string
	var rev int
	if e = tx.QueryRow(`SELECT role,revoked FROM principals WHERE id=?`, id).Scan(&role, &rev); e != nil {
		return e
	}
	if role == "rotation" {
		return errors.New("rotation principal cannot be revoked in demo")
	}
	if rev != 0 {
		return nil
	}
	if _, e = tx.Exec(`UPDATE principals SET revoked=1 WHERE id=?`, id); e != nil {
		return e
	}
	rows, e := tx.Query(`SELECT object_id FROM grants WHERE principal_id=?`, id)
	if e != nil {
		return e
	}
	var ids []string
	for rows.Next() {
		var x string
		if e = rows.Scan(&x); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, x)
	}
	rows.Close()
	for _, obj := range ids {
		var v uint64
		if e = tx.QueryRow(`SELECT COALESCE(MAX(version),0) FROM objects WHERE id=?`, obj).Scan(&v); e != nil {
			return e
		}
		if _, e = tx.Exec(`INSERT INTO rotation_jobs(object_id,state,next_version) VALUES(?,'pending',?) ON CONFLICT(object_id) DO UPDATE SET state='pending',next_version=excluded.next_version`, obj, v+1); e != nil {
			return e
		}
	}
	return tx.Commit()
}
func (s *Store) Put(id string, v uint64, b []byte, mode WriteMode) error {
	tx, e := s.DB.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var current uint64
	if e = tx.QueryRow(`SELECT COALESCE(MAX(version),0) FROM objects WHERE id=?`, id).Scan(&current); e != nil {
		return e
	}
	if v != current+1 {
		return fmt.Errorf("version conflict current=%d proposed=%d", current, v)
	}
	switch mode {
	case WriteInitial:
		if current != 0 {
			return errors.New("initial write requires an empty object")
		}
	case WriteOwnerUpdate:
		if current == 0 {
			return errors.New("cannot update an empty object")
		}
		var pending int
		if e = tx.QueryRow(`SELECT COUNT(*) FROM rotation_jobs WHERE object_id=? AND state='pending'`, id).Scan(&pending); e != nil {
			return e
		}
		if pending != 0 {
			return errors.New("cannot update while rotation is pending")
		}
	case WriteRotation:
		var pending uint64
		var state string
		if e = tx.QueryRow(`SELECT next_version,state FROM rotation_jobs WHERE object_id=?`, id).Scan(&pending, &state); e != nil {
			return e
		}
		if state != "pending" || pending != v {
			return errors.New("no matching rotation job")
		}
	default:
		return errors.New("invalid write mode")
	}
	if _, e = tx.Exec(`INSERT INTO objects(id,version,ciphertext) VALUES(?,?,?)`, id, v, b); e != nil {
		return e
	}
	if mode == WriteRotation {
		if _, e = tx.Exec(`DELETE FROM rotation_jobs WHERE object_id=?`, id); e != nil {
			return e
		}
	}
	return tx.Commit()
}
