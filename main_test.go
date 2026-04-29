package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHashBlake3Deterministic(t *testing.T) {
	a := hashBlake3("test")
	b := hashBlake3("test")

	if a != b {
		t.Fatalf("expected deterministic hash, got %s vs %s", a, b)
	}

	if len(a) == 0 {
		t.Fatalf("expected non-empty hash")
	}
}

func TestInvalidStoreSetGetDelete(t *testing.T) {
	store := &InvalidStore{}

	key := "127.0.0.1"
	val := InvalidAttempts{
		Count:      1,
		Expiration: time.Now().Add(time.Minute),
	}

	store.Set(key, val)

	got, ok := store.Get(key)
	if !ok {
		t.Fatalf("expected key to exist")
	}

	if got.Count != 1 {
		t.Fatalf("expected count 1, got %d", got.Count)
	}

	store.Delete(key)

	_, ok = store.Get(key)
	if ok {
		t.Fatalf("expected key to be deleted")
	}
}

func TestInvalidStoreExpire(t *testing.T) {
	store := &InvalidStore{}

	store.Set("expired", InvalidAttempts{
		Count:      1,
		Expiration: time.Now().Add(-time.Minute),
	})

	store.Set("valid", InvalidAttempts{
		Count:      1,
		Expiration: time.Now().Add(time.Minute),
	})

	removed := store.Expire()

	if removed == 0 {
		t.Fatalf("expected expired entries to be cleaned")
	}
}

func TestAuthHandlerMissingMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(AuthUserHeader, "user")
	req.Header.Set(AuthPassHeader, "pass")
	req.Header.Set(AuthProtocolHeader, "imap")

	w := httptest.NewRecorder()

	authHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing Auth-Method, got %d", w.Code)
	}
}

func TestAuthHandlerInvalidMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(AuthMethodHeader, "invalid")
	req.Header.Set(AuthUserHeader, "user")
	req.Header.Set(AuthPassHeader, "pass")
	req.Header.Set(AuthProtocolHeader, "imap")

	w := httptest.NewRecorder()

	authHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid Auth-Method, got %d", w.Code)
	}
}

func TestAuthHandlerTooManyLoginAttempts(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(AuthMethodHeader, "plain")
	req.Header.Set(AuthUserHeader, "user")
	req.Header.Set(AuthPassHeader, "pass")
	req.Header.Set(AuthProtocolHeader, "imap")
	req.Header.Set(AuthLoginAttempt, "999") // exceed default maxLoginAttempts

	w := httptest.NewRecorder()

	authHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for too many login attempts, got %d", w.Code)
	}
}

func TestAuthHandlerUnsupportedProtocol(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(AuthMethodHeader, "plain")
	req.Header.Set(AuthUserHeader, "user")
	req.Header.Set(AuthPassHeader, "pass")
	req.Header.Set(AuthProtocolHeader, "ftp")

	w := httptest.NewRecorder()

	authHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unsupported protocol, got %d", w.Code)
	}
}
