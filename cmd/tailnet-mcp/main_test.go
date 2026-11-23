package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func env(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func TestEndToEndOverStdio(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, _, _ := r.BasicAuth(); u != "tskey-api-test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/api/v2/tailnet/-/devices" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"devices": []map[string]any{
			{"nodeId": "n1", "name": "web-1", "authorized": true, "connectedToControl": true},
		}})
	}))
	defer api.Close()

	stdin := strings.NewReader(strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_devices","arguments":{}}}`,
	}, "\n") + "\n")
	var stdout, stderr bytes.Buffer

	err := run(nil, env(map[string]string{
		"TAILSCALE_API_KEY":  "tskey-api-test",
		"TAILSCALE_BASE_URL": api.URL,
	}), stdin, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, stderr.String())
	}

	replies := map[float64]map[string]any{}
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("non-JSON on stdout: %q", line)
		}
		replies[m["id"].(float64)] = m
	}
	if len(replies) != 3 {
		t.Fatalf("got %d replies, want 3:\n%s", len(replies), stdout.String())
	}

	tools := replies[2]["result"].(map[string]any)["tools"].([]any)
	for _, tool := range tools {
		if strings.HasPrefix(tool.(map[string]any)["name"].(string), "set_") {
			t.Error("write tool listed without -allow-writes")
		}
	}

	text := replies[3]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, `"name": "web-1"`) {
		t.Fatalf("list_devices result = %s", text)
	}
	if strings.Contains(stderr.String(), "tskey-api-test") {
		t.Fatal("credential written to logs")
	}
}

func TestCredentials(t *testing.T) {
	cases := []struct {
		name    string
		vars    map[string]string
		wantErr string
	}{
		{"none", map[string]string{}, "no credentials"},
		{"both", map[string]string{"TAILSCALE_API_KEY": "k", "TAILSCALE_OAUTH_CLIENT_ID": "id"}, "not both"},
		{"oauth missing secret", map[string]string{"TAILSCALE_OAUTH_CLIENT_ID": "id"}, "required"},
		{"api key", map[string]string{"TAILSCALE_API_KEY": "k"}, ""},
		{"oauth", map[string]string{"TAILSCALE_OAUTH_CLIENT_ID": "id", "TAILSCALE_OAUTH_CLIENT_SECRET": "s"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := credentials(env(tc.vars))
			if tc.wantErr == "" && err != nil {
				t.Fatal(err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestRejectsBadLogLevel(t *testing.T) {
	err := run([]string{"-log-level", "loud"}, env(map[string]string{"TAILSCALE_API_KEY": "k"}), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error")
	}
}
