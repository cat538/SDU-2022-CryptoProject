package user

import (
	"crypto/rand"
	"errors"

	"github.com/tjfoc/gmsm/sm2"
)

type Entity struct {
	UserId *UserId
	Pub    sm2.PublicKey
	Priv   sm2.PrivateKey
}

func NewEntity(name, comment, email string) (*Entity, error) {
	uid := NewUserId(name, comment, email)
	if uid == nil {
		return nil, errors.New("Invaild name/comment/email")
	}
	sigPriv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, errors.New("Sig priv generate error")
	}
	e := &Entity{
		UserId: uid,
		Priv:   *sigPriv,
		Pub:    sigPriv.PublicKey,
	}
	return e, nil
}

type UserId struct {
	Id string // By convention, this takes the form "Full Name (Comment) <email@example.com>" which is split out in the fields below.

	Name, Comment, Email string
}

func hasInvalidCharacters(s string) bool {
	for _, c := range s {
		switch c {
		case '(', ')', '<', '>', 0:
			return true
		}
	}
	return false
}

func NewUserId(name, comment, email string) *UserId {
	if hasInvalidCharacters(name) || hasInvalidCharacters(comment) || hasInvalidCharacters(email) {
		return nil
	}

	uid := new(UserId)
	uid.Name, uid.Comment, uid.Email = name, comment, email
	uid.Id = name
	if len(comment) > 0 {
		if len(uid.Id) > 0 {
			uid.Id += " "
		}
		uid.Id += "("
		uid.Id += comment
		uid.Id += ")"
	}
	if len(email) > 0 {
		if len(uid.Id) > 0 {
			uid.Id += " "
		}
		uid.Id += "<"
		uid.Id += email
		uid.Id += ">"
	}
	return uid
}
