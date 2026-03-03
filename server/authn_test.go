package server

import (
	"testing"

	"github.com/zjyl1994/arkauthn/infra/vars"
	"golang.org/x/crypto/bcrypt"
)

func TestCheckUser(t *testing.T) {
	oldUsers := vars.Users
	t.Cleanup(func() {
		vars.Users = oldUsers
	})
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	vars.Users = []vars.UserItem{
		{Username: "plain", Password: "pass"},
		{Username: "bcrypt", Password: string(hash)},
	}

	user, ok := checkUser("plain", "pass")
	if !ok || user != "plain" {
		t.Fatalf("expected plain user match")
	}

	_, ok = checkUser("plain", "wrong")
	if ok {
		t.Fatalf("expected plain wrong password")
	}

	user, ok = checkUser("bcrypt", "secret")
	if !ok || user != "bcrypt" {
		t.Fatalf("bcrypt user mismatch")
	}

	_, ok = checkUser("bcrypt", "wrong")
	if ok {
		t.Fatalf("expected wrong password")
	}

	_, ok = checkUser("missing", "anything")
	if ok {
		t.Fatalf("expected missing user")
	}
}
