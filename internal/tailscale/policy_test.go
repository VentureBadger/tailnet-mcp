package tailscale

import (
	"context"
	"io"
	"net/http"
	"testing"
)

const samplePolicy = `{
  // comment
  "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
}`

func TestPolicyReturnsHuJSONAndETag(t *testing.T) {
	c := newTestClient(t, APIKey("k"), func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/tailnet/example.com/acl" || r.Header.Get("Accept") != "application/hujson" {
			t.Errorf("%s accept=%s", r.URL.Path, r.Header.Get("Accept"))
		}
		w.Header().Set("ETag", `"abc123"`)
		_, _ = io.WriteString(w, samplePolicy)
	})

	p, err := c.Policy(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.HuJSON != samplePolicy || p.ETag != "abc123" {
		t.Fatalf("policy = %+v", p)
	}
}

func TestValidatePolicy(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		valid   bool
		message string
	}{
		{"empty body passes", 200, "", true, ""},
		{"empty object passes", 200, "{}", true, ""},
		{"failing tests", 200, `{"message":"test(s) failed","data":[{"user":"a@example.com","errors":["denied"]}]}`, false, "test(s) failed"},
		{"unparseable policy", 400, `{"message":"line 3: unexpected token"}`, false, "line 3: unexpected token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestClient(t, APIKey("k"), func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v2/tailnet/example.com/acl/validate" || r.Header.Get("Content-Type") != "application/hujson" {
					t.Errorf("%s content-type=%s", r.URL.Path, r.Header.Get("Content-Type"))
				}
				body, _ := io.ReadAll(r.Body)
				if string(body) != samplePolicy {
					t.Errorf("body = %s", body)
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})

			v, err := c.ValidatePolicy(context.Background(), samplePolicy)
			if err != nil {
				t.Fatal(err)
			}
			if v.Valid != tc.valid || v.Message != tc.message {
				t.Fatalf("validation = %+v", v)
			}
		})
	}
}

func TestValidatePolicyServerErrorIsAnError(t *testing.T) {
	c := newTestClient(t, APIKey("k"), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message":"missing scope"}`)
	})
	if _, err := c.ValidatePolicy(context.Background(), samplePolicy); err == nil {
		t.Fatal("expected error for 403")
	}
}

func TestPreviewRuleMatches(t *testing.T) {
	c := newTestClient(t, APIKey("k"), func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/api/v2/tailnet/example.com/acl/preview" || q.Get("type") != "ipport" || q.Get("previewFor") != "100.64.0.1:22" {
			t.Errorf("%s %v", r.URL.Path, q)
		}
		writeJSON(w, 200, map[string]any{
			"type": "ipport", "previewFor": "100.64.0.1:22",
			"matches": []map[string]any{{"users": []string{"group:eng"}, "ports": []string{"100.64.0.1:22"}, "lineNumber": 12}},
		})
	})

	p, err := c.PreviewRuleMatches(context.Background(), PreviewIPPort, "100.64.0.1:22", samplePolicy)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Matches) != 1 || p.Matches[0].LineNumber != 12 || p.Matches[0].Users[0] != "group:eng" {
		t.Fatalf("preview = %+v", p)
	}
}

func TestPreviewRejectsBadInput(t *testing.T) {
	c := newTestClient(t, APIKey("k"), func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request expected")
	})
	if _, err := c.PreviewRuleMatches(context.Background(), "dst", "x", samplePolicy); err == nil {
		t.Error("expected error for unknown type")
	}
	if _, err := c.PreviewRuleMatches(context.Background(), PreviewUser, "", samplePolicy); err == nil {
		t.Error("expected error for empty target")
	}
}
