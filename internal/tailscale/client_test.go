package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, creds Credentials, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Config{
		BaseURL:     srv.URL,
		Tailnet:     "example.com",
		Credentials: creds,
		MaxRetries:  3,
		RetryWait:   time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func TestDevicesUsesAPIKeyAndTailnetPath(t *testing.T) {
	c := newTestClient(t, APIKey("tskey-api-test"), func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "tskey-api-test" || pass != "" {
			t.Errorf("basic auth = %q, %q, %v", user, pass, ok)
		}
		if r.URL.Path != "/api/v2/tailnet/example.com/devices" {
			t.Errorf("path = %s", r.URL.Path)
		}
		writeJSON(w, 200, map[string]any{"devices": []map[string]any{
			{"nodeId": "n1", "name": "web.example.ts.net", "connectedToControl": true, "lastSeen": nil, "tags": []string{"tag:prod"}},
		}})
	})

	devices, err := c.Devices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].NodeID != "n1" || !devices[0].ConnectedToControl || devices[0].Tags[0] != "tag:prod" {
		t.Fatalf("devices = %+v", devices)
	}
}

func TestDeviceRequestsAllFieldsAndEscapesID(t *testing.T) {
	c := newTestClient(t, APIKey("k"), func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/api/v2/device/a%2Fb" {
			t.Errorf("escaped path = %s", r.URL.EscapedPath())
		}
		if r.URL.Query().Get("fields") != "all" {
			t.Errorf("fields = %q", r.URL.Query().Get("fields"))
		}
		writeJSON(w, 200, map[string]any{"nodeId": "a/b", "AdvertisedRoutes": []string{"10.0.0.0/24"}})
	})

	d, err := c.Device(context.Background(), "a/b")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.AdvertisedRoutes) != 1 {
		t.Fatalf("advertised routes not decoded: %+v", d)
	}
}

func TestRetriesTransientErrorsThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, APIKey("k"), func(w http.ResponseWriter, r *http.Request) {
		switch calls.Add(1) {
		case 1:
			w.Header().Set("Retry-After", "0")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"message": "too many requests"})
		case 2:
			writeJSON(w, http.StatusBadGateway, map[string]string{"message": "bad gateway"})
		default:
			writeJSON(w, 200, map[string]any{"devices": []any{}})
		}
	})

	if _, err := c.Devices(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3", calls.Load())
	}
}

func TestDoesNotRetryClientErrors(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, APIKey("k"), func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "device not found"})
	})

	_, err := c.Device(context.Background(), "missing")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 404 || apiErr.Message != "device not found" {
		t.Fatalf("err = %v", err)
	}
	if !IsNotFound(err) {
		t.Fatal("IsNotFound = false")
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", calls.Load())
	}
}

func TestGivesUpAfterMaxRetries(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, APIKey("k"), func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "unavailable"})
	})

	if _, err := c.Devices(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if calls.Load() != 4 {
		t.Fatalf("calls = %d, want 4", calls.Load())
	}
}

func TestStopsRetryingWhenContextIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := newTestClient(t, APIKey("k"), func(w http.ResponseWriter, r *http.Request) {
		cancel()
		w.Header().Set("Retry-After", "30")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{})
	})

	start := time.Now()
	_, err := c.Devices(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("waited out Retry-After despite cancellation")
	}
}

func TestOAuthFetchesCachesAndRefreshesOnUnauthorized(t *testing.T) {
	var tokens, apiCalls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "id" ||
			r.Form.Get("client_secret") != "secret" || r.Form.Get("scope") != "devices:core:read policy_file:read" {
			t.Errorf("token form = %v", r.Form)
		}
		n := tokens.Add(1)
		writeJSON(w, 200, map[string]any{"access_token": "tok" + string(rune('0'+n)), "token_type": "Bearer", "expires_in": 3600})
	})
	mux.HandleFunc("/api/v2/tailnet/-/devices", func(w http.ResponseWriter, r *http.Request) {
		n := apiCalls.Add(1)
		auth := r.Header.Get("Authorization")
		if n == 3 && auth == "Bearer tok1" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "token revoked"})
			return
		}
		writeJSON(w, 200, map[string]any{"devices": []any{}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	oauth, err := NewOAuth(OAuthConfig{
		ClientID: "id", ClientSecret: "secret",
		Scopes:   []string{"devices:core:read", "policy_file:read"},
		TokenURL: srv.URL + "/api/v2/oauth/token",
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{BaseURL: srv.URL, Credentials: oauth, RetryWait: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 2; i++ {
		if _, err := c.Devices(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if tokens.Load() != 1 {
		t.Fatalf("token fetched %d times for two calls, want 1", tokens.Load())
	}

	if _, err := c.Devices(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tokens.Load() != 2 {
		t.Fatalf("token not refreshed after 401: fetched %d times", tokens.Load())
	}
}

func TestOAuthRefreshesBeforeExpiry(t *testing.T) {
	var tokens atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokens.Add(1)
		writeJSON(w, 200, map[string]any{"access_token": "tok", "expires_in": 3600})
	}))
	t.Cleanup(srv.Close)

	oauth, _ := NewOAuth(OAuthConfig{ClientID: "id", ClientSecret: "s", TokenURL: srv.URL})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	oauth.now = func() time.Time { return now }

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	_ = oauth.Authorize(context.Background(), req)
	now = now.Add(58 * time.Minute)
	_ = oauth.Authorize(context.Background(), req)
	if tokens.Load() != 1 {
		t.Fatalf("refreshed too early: %d fetches", tokens.Load())
	}
	now = now.Add(90 * time.Second)
	_ = oauth.Authorize(context.Background(), req)
	if tokens.Load() != 2 {
		t.Fatalf("did not refresh inside the margin: %d fetches", tokens.Load())
	}
}

func TestOAuthSurfacesTokenErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "invalid client"})
	}))
	t.Cleanup(srv.Close)

	oauth, _ := NewOAuth(OAuthConfig{ClientID: "id", ClientSecret: "s", TokenURL: srv.URL})
	err := oauth.Authorize(context.Background(), httptest.NewRequest(http.MethodGet, "/", nil))
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Message != "invalid client" {
		t.Fatalf("err = %v", err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := map[string]time.Duration{
		"":                              0,
		"5":                             5 * time.Second,
		"600":                           maxRetryAfter,
		"-1":                            0,
		"garbage":                       0,
		"Thu, 01 Jan 2026 00:00:10 GMT": 10 * time.Second,
	}
	for in, want := range cases {
		if got := parseRetryAfter(in, now); got != want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSetTagsSendsFullList(t *testing.T) {
	c := newTestClient(t, APIKey("k"), func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v2/device/n1/tags" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"tags":[]}` {
			t.Errorf("body = %s", body)
		}
		w.WriteHeader(200)
	})
	if err := c.SetTags(context.Background(), "n1", nil); err != nil {
		t.Fatal(err)
	}
}

func TestSetAuthorized(t *testing.T) {
	c := newTestClient(t, APIKey("k"), func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path != "/api/v2/device/n1/authorized" || string(body) != `{"authorized":false}` {
			t.Errorf("%s %s", r.URL.Path, body)
		}
		w.WriteHeader(200)
	})
	if err := c.SetAuthorized(context.Background(), "n1", false); err != nil {
		t.Fatal(err)
	}
}
