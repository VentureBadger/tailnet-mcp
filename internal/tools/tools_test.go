package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/VentureBadger/tailnet-mcp/internal/mcp"
	"github.com/VentureBadger/tailnet-mcp/internal/tailscale"
)

type fakeAPI struct {
	devices    []tailscale.Device
	policy     string
	previewed  string
	tagsSet    []string
	authorized *bool
}

func (f *fakeAPI) Devices(context.Context) ([]tailscale.Device, error) { return f.devices, nil }

func (f *fakeAPI) Device(_ context.Context, id string) (*tailscale.Device, error) {
	for _, d := range f.devices {
		if d.NodeID == id {
			return &d, nil
		}
	}
	return nil, &tailscale.APIError{Status: 404, Message: "not found"}
}

func (f *fakeAPI) SetAuthorized(_ context.Context, _ string, a bool) error {
	f.authorized = &a
	return nil
}

func (f *fakeAPI) SetTags(_ context.Context, _ string, tags []string) error {
	f.tagsSet = tags
	return nil
}

func (f *fakeAPI) Policy(context.Context) (*tailscale.PolicyFile, error) {
	return &tailscale.PolicyFile{HuJSON: f.policy, ETag: "e1"}, nil
}

func (f *fakeAPI) ValidatePolicy(_ context.Context, p string) (*tailscale.Validation, error) {
	return &tailscale.Validation{Valid: !strings.Contains(p, "bad")}, nil
}

func (f *fakeAPI) PreviewRuleMatches(_ context.Context, typ tailscale.PreviewType, target, policy string) (*tailscale.Preview, error) {
	f.previewed = policy
	return &tailscale.Preview{Type: typ, PreviewFor: target, Matches: []tailscale.RuleMatch{{Users: []string{"*"}, Ports: []string{"*:*"}, LineNumber: 3}}}, nil
}

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func fixture() *fakeAPI {
	return &fakeAPI{
		policy: `{"acls":[]}`,
		devices: []tailscale.Device{
			{NodeID: "n1", Name: "web-1", OS: "linux", User: "ops@example.com", Tags: []string{"tag:prod"}, Authorized: true, ConnectedToControl: true, Expires: now.AddDate(1, 0, 0).Format(time.RFC3339)},
			{NodeID: "n2", Name: "laptop", OS: "macOS", User: "dev@example.com", Authorized: true, LastSeen: now.AddDate(0, 0, -45).Format(time.RFC3339), Expires: now.AddDate(0, 0, 5).Format(time.RFC3339), UpdateAvailable: true},
			{NodeID: "n3", Name: "new-box", OS: "linux", Authorized: false, ConnectedToControl: true, KeyExpiryDisabled: true, Expires: now.AddDate(0, 0, -1).Format(time.RFC3339)},
		},
	}
}

func find(t *testing.T, tools []mcp.Tool, name string) mcp.Tool {
	t.Helper()
	for _, tool := range tools {
		if tool.Name == name {
			return tool
		}
	}
	t.Fatalf("tool %q not registered", name)
	return mcp.Tool{}
}

func call(t *testing.T, api API, name, args string) (map[string]any, error) {
	t.Helper()
	tool := find(t, New(api, Options{AllowWrites: true, Now: func() time.Time { return now }}), name)
	out, err := tool.Handler(context.Background(), json.RawMessage(args))
	if err != nil {
		return nil, err
	}
	data, _ := json.Marshal(out)
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	return m, nil
}

func TestWriteToolsAreOptIn(t *testing.T) {
	readOnly := New(fixture(), Options{})
	for _, tool := range readOnly {
		if !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s exposed without AllowWrites", tool.Name)
		}
	}
	withWrites := New(fixture(), Options{AllowWrites: true})
	if len(withWrites) != len(readOnly)+2 {
		t.Fatalf("got %d tools with writes, want %d", len(withWrites), len(readOnly)+2)
	}
	if !find(t, withWrites, "set_device_tags").Annotations.DestructiveHint {
		t.Error("write tool not marked destructive")
	}
}

func TestSchemasAreValidJSON(t *testing.T) {
	for _, tool := range New(fixture(), Options{AllowWrites: true}) {
		var schema map[string]any
		if err := json.Unmarshal(tool.InputSchema, &schema); err != nil || schema["type"] != "object" {
			t.Errorf("%s: bad schema: %v", tool.Name, err)
		}
	}
}

func TestListDevicesFilters(t *testing.T) {
	cases := map[string][]string{
		`{}`:                               {"laptop", "new-box", "web-1"},
		`{"tag":"tag:prod"}`:               {"web-1"},
		`{"os":"LINUX"}`:                   {"new-box", "web-1"},
		`{"connected":false}`:              {"laptop"},
		`{"authorized":false}`:             {"new-box"},
		`{"query":"DEV@"}`:                 {"laptop"},
		`{"os":"linux","authorized":true}`: {"web-1"},
	}
	for args, want := range cases {
		out, err := call(t, fixture(), "list_devices", args)
		if err != nil {
			t.Fatalf("%s: %v", args, err)
		}
		var got []string
		for _, d := range out["devices"].([]any) {
			got = append(got, d.(map[string]any)["name"].(string))
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: got %v, want %v", args, got, want)
		}
	}
}

func TestUnknownArgumentsAreRejected(t *testing.T) {
	if _, err := call(t, fixture(), "list_devices", `{"tags":"tag:prod"}`); err == nil || !strings.Contains(err.Error(), "invalid arguments") {
		t.Fatalf("err = %v", err)
	}
}

func TestGetDeviceNotFoundIsActionable(t *testing.T) {
	_, err := call(t, fixture(), "get_device", `{"device_id":"zzz"}`)
	if err == nil || !strings.Contains(err.Error(), "list_devices") {
		t.Fatalf("err = %v", err)
	}
}

func TestAuditDevices(t *testing.T) {
	out, err := call(t, fixture(), "audit_devices", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	names := func(key string) string {
		var n []string
		for _, f := range out[key].([]any) {
			n = append(n, f.(map[string]any)["name"].(string)+": "+stringOr(f.(map[string]any)["detail"]))
		}
		return strings.Join(n, "; ")
	}
	if got := names("unauthorized"); got != "new-box: " {
		t.Errorf("unauthorized = %q", got)
	}
	if got := names("keyExpiringOrExpired"); got != "laptop: key expires in 5 days" {
		t.Errorf("expiring = %q (new-box has key expiry disabled)", got)
	}
	if got := names("notSeenRecently"); got != "laptop: last seen 45 days ago" {
		t.Errorf("stale = %q", got)
	}
	if got := names("updateAvailable"); got != "laptop: " {
		t.Errorf("updates = %q", got)
	}
}

func stringOr(v any) string {
	s, _ := v.(string)
	return s
}

func TestAuditRejectsOutOfRangeDays(t *testing.T) {
	if _, err := call(t, fixture(), "audit_devices", `{"stale_after_days":0}`); err == nil {
		t.Fatal("expected error")
	}
}

func TestPreviewAccessUsesCurrentPolicyByDefault(t *testing.T) {
	api := fixture()
	out, err := call(t, api, "preview_access", `{"user":"dev@example.com"}`)
	if err != nil {
		t.Fatal(err)
	}
	if out["policy"] != "current" || api.previewed != api.policy || out["type"] != "user" {
		t.Fatalf("out = %v, previewed %q", out, api.previewed)
	}

	out, err = call(t, api, "preview_access", `{"ip_port":"100.64.0.1:22","policy":"{\"acls\":[1]}"}`)
	if err != nil {
		t.Fatal(err)
	}
	if out["policy"] != "proposed" || api.previewed != `{"acls":[1]}` {
		t.Fatalf("out = %v, previewed %q", out, api.previewed)
	}
}

func TestPreviewAccessNeedsExactlyOneTarget(t *testing.T) {
	for _, args := range []string{`{}`, `{"user":"a@example.com","ip_port":"1.2.3.4:5"}`} {
		if _, err := call(t, fixture(), "preview_access", args); err == nil {
			t.Errorf("%s: expected error", args)
		}
	}
}

func TestSetTagsValidatesTags(t *testing.T) {
	api := fixture()
	if _, err := call(t, api, "set_device_tags", `{"device_id":"n1","tags":["prod"]}`); err == nil {
		t.Fatal("accepted tag without tag: prefix")
	}
	if api.tagsSet != nil {
		t.Fatal("API called despite invalid tag")
	}
	if _, err := call(t, api, "set_device_tags", `{"device_id":"n1","tags":["tag:prod","tag:web-1"]}`); err != nil {
		t.Fatal(err)
	}
	if strings.Join(api.tagsSet, ",") != "tag:prod,tag:web-1" {
		t.Fatalf("tags set = %v", api.tagsSet)
	}
}

func TestSetAuthorizedRequiresExplicitValue(t *testing.T) {
	api := fixture()
	if _, err := call(t, api, "set_device_authorized", `{"device_id":"n1"}`); err == nil {
		t.Fatal("accepted missing authorized")
	}
	if _, err := call(t, api, "set_device_authorized", `{"device_id":"n1","authorized":false}`); err != nil {
		t.Fatal(err)
	}
	if api.authorized == nil || *api.authorized {
		t.Fatal("authorized=false not passed through")
	}
}
