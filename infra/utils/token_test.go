package utils

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zjyl1994/arkauthn/infra/vars"
)

func setTestKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	oldPub := vars.Ed25519PublicKey
	oldPriv := vars.Ed25519PrivateKey
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	vars.Ed25519PublicKey = pub
	vars.Ed25519PrivateKey = priv
	t.Cleanup(func() {
		vars.Ed25519PublicKey = oldPub
		vars.Ed25519PrivateKey = oldPriv
	})
	return pub, priv
}

func TestGenerateAndParseToken(t *testing.T) {
	setTestKeys(t)
	token, err := GenerateToken("alice", time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	username, expireAt, err := ParseToken(token)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if username != "alice" {
		t.Fatalf("username mismatch: %s", username)
	}
	if time.Until(expireAt) <= 0 {
		t.Fatalf("expire time not in future")
	}
}

func TestGenerateTokenMissingKey(t *testing.T) {
	oldPriv := vars.Ed25519PrivateKey
	vars.Ed25519PrivateKey = nil
	t.Cleanup(func() {
		vars.Ed25519PrivateKey = oldPriv
	})
	_, err := GenerateToken("alice", time.Hour)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseTokenExpired(t *testing.T) {
	_, priv := setTestKeys(t)
	claims := Claims{
		Username: "alice",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	_, _, err = ParseToken(signed)
	if !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("expected expired token error")
	}
}

func TestParseTokenMissingPublicKey(t *testing.T) {
	setTestKeys(t)
	token, err := GenerateToken("alice", time.Hour)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	oldPub := vars.Ed25519PublicKey
	vars.Ed25519PublicKey = nil
	t.Cleanup(func() {
		vars.Ed25519PublicKey = oldPub
	})
	_, _, err = ParseToken(token)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected invalid token error")
	}
}
