package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthEndpointReturns200(t *testing.T) {
	handler := newHandler()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var payload healthResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}

	if payload.Status != "ok" {
		t.Fatalf("expected status field 'ok', got %q", payload.Status)
	}

	if payload.Service != "user-identity-service" {
		t.Fatalf("unexpected service name: %q", payload.Service)
	}
}

func TestHealthEndpointRejectsPost(t *testing.T) {
	handler := newHandler()
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}
