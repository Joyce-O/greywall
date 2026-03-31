package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsOlderVersion(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		// Strictly older
		{"1.0.0", "1.0.1", true},
		{"1.0.0", "1.1.0", true},
		{"1.0.0", "2.0.0", true},
		{"0.9.9", "1.0.0", true},
		// Same version
		{"1.0.0", "1.0.0", false},
		{"2.3.4", "2.3.4", false},
		// Strictly newer
		{"1.0.1", "1.0.0", false},
		{"2.0.0", "1.9.9", false},
		// Invalid current → treated as outdated
		{"dev", "1.0.0", true},
		{"", "1.0.0", true},
		{"1.0", "1.0.0", true},
		// Invalid latest → not older
		{"1.0.0", "dev", false},
		{"1.0.0", "", false},
		{"1.0.0", "1.0", false},
		// Non-numeric components in current → treated as outdated
		{"a.b.c", "1.0.0", true},
		// Non-numeric components in latest → not older
		{"1.0.0", "a.b.c", false},
	}

	for _, tc := range tests {
		got := IsOlderVersion(tc.current, tc.latest)
		if got != tc.want {
			t.Errorf("IsOlderVersion(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
		}
	}
}

func TestCheckLatestTag_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/greyhavenhq/greyproxy/releases/latest" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(release{TagName: "v1.2.3"})
	}))
	defer srv.Close()

	tag, err := checkLatestTag(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tag != "v1.2.3" {
		t.Errorf("got tag %q, want %q", tag, "v1.2.3")
	}
}

func TestCheckLatestTag_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	_, err := checkLatestTag(srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("expected error on non-200 response, got nil")
	}
}
