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
	store := NewLimiter(1, time.Hour)

	key := "127.0.0.1"

	store.Register(key)

	if !store.Blocked(key) {
		t.Fatalf("must be blocked after registration")
	}

	store.Reset(key)

	if store.Blocked(key) {
		t.Fatalf("expected key to be deleted")
	}
}

func TestInvalidStoreExpire(t *testing.T) {
	store := NewLimiter(1, time.Second)

	// Simulate an expired entry
	store.Register("expired")

	removed := store.Expire()
	if removed != 0 {
		t.Fatalf("expected no expired entries to be cleaned")
	}

	time.Sleep(2 * time.Second)
	removed = store.Expire()

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
	req.Header.Set(AuthProtocolHeader, "sftp") // unsupported protocol

	w := httptest.NewRecorder()

	authHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unsupported protocol, got %d", w.Code)
	}
}
