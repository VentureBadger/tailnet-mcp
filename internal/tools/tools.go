package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/VentureBadger/tailnet-mcp/internal/mcp"
	"github.com/VentureBadger/tailnet-mcp/internal/tailscale"
)

type API interface {
	Devices(ctx context.Context) ([]tailscale.Device, error)
	Device(ctx context.Context, id string) (*tailscale.Device, error)
	SetAuthorized(ctx context.Context, id string, authorized bool) error
	SetTags(ctx context.Context, id string, tags []string) error
	Policy(ctx context.Context) (*tailscale.PolicyFile, error)
	ValidatePolicy(ctx context.Context, policy string) (*tailscale.Validation, error)
	PreviewRuleMatches(ctx context.Context, typ tailscale.PreviewType, target, policy string) (*tailscale.Preview, error)
}

type Options struct {
	AllowWrites bool
	Now         func() time.Time
}

type toolset struct {
	api API
	now func() time.Time
}

func New(api API, opts Options) []mcp.Tool {
	ts := &toolset{api: api, now: opts.Now}
	if ts.now == nil {
		ts.now = time.Now
	}

	tools := []mcp.Tool{
		{
			Name:        "list_devices",
			Description: "List devices in the tailnet with their addresses, owner, tags, OS, and connection state. All filters are optional and combine with AND.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"query": {"type": "string", "description": "Case-insensitive substring of the device name, hostname, or owner."},
					"tag": {"type": "string", "description": "Only devices carrying this tag, e.g. tag:prod."},
					"os": {"type": "string", "description": "Only devices on this OS, e.g. linux, macOS, windows."},
					"connected": {"type": "boolean", "description": "Only devices currently connected (true) or disconnected (false)."},
					"authorized": {"type": "boolean", "description": "Only authorized (true) or unauthorized (false) devices."}
				},
				"additionalProperties": false
			}`),
			Annotations: readOnly("List devices"),
			Handler:     ts.listDevices,
		},
		{
			Name:        "get_device",
			Description: "Get full details for one device, including advertised and enabled subnet routes and client connectivity.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"device_id": {"type": "string", "description": "The device's nodeId from list_devices."}
				},
				"required": ["device_id"],
				"additionalProperties": false
			}`),
			Annotations: readOnly("Get device"),
			Handler:     ts.getDevice,
		},
		{
			Name:        "audit_devices",
			Description: "Find devices that need attention: unauthorized devices, node keys expiring soon, devices not seen recently, and clients with updates available.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"expiring_within_days": {"type": "integer", "minimum": 1, "maximum": 365, "default": 14},
					"stale_after_days": {"type": "integer", "minimum": 1, "maximum": 365, "default": 30}
				},
				"additionalProperties": false
			}`),
			Annotations: readOnly("Audit devices"),
			Handler:     ts.auditDevices,
		},
		{
			Name:        "get_policy",
			Description: "Get the tailnet policy file (ACLs) as HuJSON, with its ETag.",
			InputSchema: json.RawMessage(`{"type": "object", "additionalProperties": false}`),
			Annotations: readOnly("Get policy file"),
			Handler:     ts.getPolicy,
		},
		{
			Name:        "validate_policy",
			Description: "Validate a proposed policy file and run its tests without saving it. Use this before suggesting any policy change.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"policy": {"type": "string", "description": "The complete proposed policy file, as HuJSON or JSON."}
				},
				"required": ["policy"],
				"additionalProperties": false
			}`),
			Annotations: readOnly("Validate policy file"),
			Handler:     ts.validatePolicy,
		},
		{
			Name:        "preview_access",
			Description: "Show which policy rules apply to a user (what they can reach) or to an IP:port (who can reach it). Uses the current policy unless a proposed one is given, so it can compare a change before it is made.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"user": {"type": "string", "description": "A user's email address. Give exactly one of user or ip_port."},
					"ip_port": {"type": "string", "description": "A tailnet IP address and port, e.g. 100.101.102.103:22."},
					"policy": {"type": "string", "description": "A proposed policy file to preview instead of the current one."}
				},
				"additionalProperties": false
			}`),
			Annotations: readOnly("Preview access"),
			Handler:     ts.previewAccess,
		},
	}

	if opts.AllowWrites {
		tools = append(tools,
			mcp.Tool{
				Name:        "set_device_authorized",
				Description: "Authorize or deauthorize a device. Deauthorizing disconnects it from the tailnet. Confirm with the user before calling.",
				InputSchema: json.RawMessage(`{
					"type": "object",
					"properties": {
						"device_id": {"type": "string"},
						"authorized": {"type": "boolean"}
					},
					"required": ["device_id", "authorized"],
					"additionalProperties": false
				}`),
				Annotations: write("Set device authorization"),
				Handler:     ts.setAuthorized,
			},
			mcp.Tool{
				Name:        "set_device_tags",
				Description: "Replace a device's tags with the given list. Tags change which policy rules apply to the device. Confirm with the user before calling.",
				InputSchema: json.RawMessage(`{
					"type": "object",
					"properties": {
						"device_id": {"type": "string"},
						"tags": {"type": "array", "items": {"type": "string", "pattern": "^tag:[A-Za-z0-9-]+$"}}
					},
					"required": ["device_id", "tags"],
					"additionalProperties": false
				}`),
				Annotations: write("Set device tags"),
				Handler:     ts.setTags,
			},
		)
	}
	return tools
}

func readOnly(title string) *mcp.Annotations {
	return &mcp.Annotations{Title: title, ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: true}
}

func write(title string) *mcp.Annotations {
	return &mcp.Annotations{Title: title, DestructiveHint: true, IdempotentHint: true, OpenWorldHint: true}
}

func decode(args json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	return nil
}

type deviceSummary struct {
	NodeID          string   `json:"nodeId"`
	Name            string   `json:"name"`
	Hostname        string   `json:"hostname"`
	User            string   `json:"user"`
	OS              string   `json:"os"`
	Addresses       []string `json:"addresses"`
	Tags            []string `json:"tags,omitempty"`
	Authorized      bool     `json:"authorized"`
	Connected       bool     `json:"connected"`
	LastSeen        string   `json:"lastSeen,omitempty"`
	KeyExpires      string   `json:"keyExpires,omitempty"`
	ClientVersion   string   `json:"clientVersion"`
	UpdateAvailable bool     `json:"updateAvailable"`
}

func summarize(d tailscale.Device) deviceSummary {
	s := deviceSummary{
		NodeID:          d.NodeID,
		Name:            d.Name,
		Hostname:        d.Hostname,
		User:            d.User,
		OS:              d.OS,
		Addresses:       d.Addresses,
		Tags:            d.Tags,
		Authorized:      d.Authorized,
		Connected:       d.ConnectedToControl,
		ClientVersion:   d.ClientVersion,
		UpdateAvailable: d.UpdateAvailable,
	}
	if !d.ConnectedToControl {
		s.LastSeen = d.LastSeen
	}
	if !d.KeyExpiryDisabled {
		s.KeyExpires = d.Expires
	}
	return s
}

func (t *toolset) listDevices(ctx context.Context, args json.RawMessage) (any, error) {
	var in struct {
		Query      string `json:"query"`
		Tag        string `json:"tag"`
		OS         string `json:"os"`
		Connected  *bool  `json:"connected"`
		Authorized *bool  `json:"authorized"`
	}
	if err := decode(args, &in); err != nil {
		return nil, err
	}
	devices, err := t.api.Devices(ctx)
	if err != nil {
		return nil, err
	}

	query := strings.ToLower(in.Query)
	out := []deviceSummary{}
	for _, d := range devices {
		switch {
		case query != "" && !containsFold(query, d.Name, d.Hostname, d.User):
		case in.Tag != "" && !slices.Contains(d.Tags, in.Tag):
		case in.OS != "" && !strings.EqualFold(d.OS, in.OS):
		case in.Connected != nil && d.ConnectedToControl != *in.Connected:
		case in.Authorized != nil && d.Authorized != *in.Authorized:
		default:
			out = append(out, summarize(d))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return map[string]any{"count": len(out), "total": len(devices), "devices": out}, nil
}

func containsFold(lowerNeedle string, fields ...string) bool {
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), lowerNeedle) {
			return true
		}
	}
	return false
}

func (t *toolset) getDevice(ctx context.Context, args json.RawMessage) (any, error) {
	var in struct {
		DeviceID string `json:"device_id"`
	}
	if err := decode(args, &in); err != nil {
		return nil, err
	}
	if in.DeviceID == "" {
		return nil, errors.New("device_id is required")
	}
	d, err := t.api.Device(ctx, in.DeviceID)
	if tailscale.IsNotFound(err) {
		return nil, fmt.Errorf("no device with id %q; use list_devices to find its nodeId", in.DeviceID)
	}
	return d, err
}

type finding struct {
	deviceSummary
	Detail string `json:"detail,omitempty"`
}

func (t *toolset) auditDevices(ctx context.Context, args json.RawMessage) (any, error) {
	in := struct {
		ExpiringWithinDays int `json:"expiring_within_days"`
		StaleAfterDays     int `json:"stale_after_days"`
	}{ExpiringWithinDays: 14, StaleAfterDays: 30}
	if err := decode(args, &in); err != nil {
		return nil, err
	}
	if in.ExpiringWithinDays < 1 || in.ExpiringWithinDays > 365 || in.StaleAfterDays < 1 || in.StaleAfterDays > 365 {
		return nil, errors.New("day values must be between 1 and 365")
	}
	devices, err := t.api.Devices(ctx)
	if err != nil {
		return nil, err
	}

	now := t.now()
	expiryCutoff := now.AddDate(0, 0, in.ExpiringWithinDays)
	staleCutoff := now.AddDate(0, 0, -in.StaleAfterDays)

	report := struct {
		Unauthorized    []finding `json:"unauthorized"`
		KeyExpiring     []finding `json:"keyExpiringOrExpired"`
		NotSeenRecently []finding `json:"notSeenRecently"`
		UpdateAvailable []finding `json:"updateAvailable"`
		Checked         int       `json:"devicesChecked"`
	}{[]finding{}, []finding{}, []finding{}, []finding{}, len(devices)}

	for _, d := range devices {
		s := summarize(d)
		if !d.Authorized {
			report.Unauthorized = append(report.Unauthorized, finding{deviceSummary: s})
		}
		if exp, ok := parseTime(d.Expires); ok && !d.KeyExpiryDisabled && exp.Before(expiryCutoff) {
			report.KeyExpiring = append(report.KeyExpiring, finding{s, expiryDetail(now, exp)})
		}
		if seen, ok := parseTime(d.LastSeen); ok && !d.ConnectedToControl && seen.Before(staleCutoff) {
			report.NotSeenRecently = append(report.NotSeenRecently, finding{s, fmt.Sprintf("last seen %d days ago", daysBetween(seen, now))})
		}
		if d.UpdateAvailable {
			report.UpdateAvailable = append(report.UpdateAvailable, finding{deviceSummary: s})
		}
	}
	return report, nil
}

func parseTime(v string) (time.Time, bool) {
	if v == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil || t.IsZero() || t.Year() < 2000 {
		return time.Time{}, false
	}
	return t, true
}

func daysBetween(from, to time.Time) int {
	return int(to.Sub(from).Hours() / 24)
}

func expiryDetail(now, exp time.Time) string {
	if exp.After(now) {
		return fmt.Sprintf("key expires in %d days", daysBetween(now, exp))
	}
	return fmt.Sprintf("key expired %d days ago", daysBetween(exp, now))
}

func (t *toolset) getPolicy(ctx context.Context, args json.RawMessage) (any, error) {
	var in struct{}
	if err := decode(args, &in); err != nil {
		return nil, err
	}
	p, err := t.api.Policy(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]string{"etag": p.ETag, "policy": p.HuJSON}, nil
}

func (t *toolset) validatePolicy(ctx context.Context, args json.RawMessage) (any, error) {
	var in struct {
		Policy string `json:"policy"`
	}
	if err := decode(args, &in); err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Policy) == "" {
		return nil, errors.New("policy is required")
	}
	return t.api.ValidatePolicy(ctx, in.Policy)
}

func (t *toolset) previewAccess(ctx context.Context, args json.RawMessage) (any, error) {
	var in struct {
		User   string `json:"user"`
		IPPort string `json:"ip_port"`
		Policy string `json:"policy"`
	}
	if err := decode(args, &in); err != nil {
		return nil, err
	}

	var typ tailscale.PreviewType
	var target string
	switch {
	case in.User != "" && in.IPPort == "":
		typ, target = tailscale.PreviewUser, in.User
	case in.IPPort != "" && in.User == "":
		typ, target = tailscale.PreviewIPPort, in.IPPort
	default:
		return nil, errors.New("give exactly one of user or ip_port")
	}

	policy, source := in.Policy, "proposed"
	if strings.TrimSpace(policy) == "" {
		current, err := t.api.Policy(ctx)
		if err != nil {
			return nil, err
		}
		policy, source = current.HuJSON, "current"
	}

	preview, err := t.api.PreviewRuleMatches(ctx, typ, target, policy)
	if err != nil {
		return nil, err
	}
	return map[string]any{"policy": source, "type": preview.Type, "previewFor": preview.PreviewFor, "matches": preview.Matches}, nil
}

func (t *toolset) setAuthorized(ctx context.Context, args json.RawMessage) (any, error) {
	var in struct {
		DeviceID   string `json:"device_id"`
		Authorized *bool  `json:"authorized"`
	}
	if err := decode(args, &in); err != nil {
		return nil, err
	}
	if in.DeviceID == "" || in.Authorized == nil {
		return nil, errors.New("device_id and authorized are required")
	}
	if err := t.api.SetAuthorized(ctx, in.DeviceID, *in.Authorized); err != nil {
		return nil, err
	}
	return map[string]any{"deviceId": in.DeviceID, "authorized": *in.Authorized}, nil
}

func (t *toolset) setTags(ctx context.Context, args json.RawMessage) (any, error) {
	var in struct {
		DeviceID string   `json:"device_id"`
		Tags     []string `json:"tags"`
	}
	if err := decode(args, &in); err != nil {
		return nil, err
	}
	if in.DeviceID == "" || in.Tags == nil {
		return nil, errors.New("device_id and tags are required")
	}
	for _, tag := range in.Tags {
		if !validTag(tag) {
			return nil, fmt.Errorf("invalid tag %q: tags look like tag:name", tag)
		}
	}
	if err := t.api.SetTags(ctx, in.DeviceID, in.Tags); err != nil {
		return nil, err
	}
	return map[string]any{"deviceId": in.DeviceID, "tags": in.Tags}, nil
}

func validTag(tag string) bool {
	name, ok := strings.CutPrefix(tag, "tag:")
	if !ok || name == "" {
		return false
	}
	for _, r := range name {
		if !(r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}
