package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const hujson = "application/hujson"

type PolicyFile struct {
	HuJSON string
	ETag   string
}

func (c *Client) Policy(ctx context.Context) (*PolicyFile, error) {
	resp, err := c.do(ctx, request{
		method: http.MethodGet,
		path:   c.tailnetPath("acl"),
		accept: hujson,
	})
	if err != nil {
		return nil, err
	}
	return &PolicyFile{
		HuJSON: string(resp.body),
		ETag:   strings.Trim(resp.header.Get("ETag"), `"`),
	}, nil
}

type Validation struct {
	Valid   bool            `json:"valid"`
	Message string          `json:"message,omitempty"`
	Details json.RawMessage `json:"details,omitempty"`
}

// The validate endpoint reports a failing policy as 200 with a message body,
// and an unparseable one as 400; both are a result, not an error.
func (c *Client) ValidatePolicy(ctx context.Context, policy string) (*Validation, error) {
	if strings.TrimSpace(policy) == "" {
		return nil, errors.New("tailscale: policy is required")
	}
	resp, err := c.do(ctx, request{
		method:      http.MethodPost,
		path:        c.tailnetPath("acl", "validate"),
		body:        []byte(policy),
		contentType: hujson,
	})
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusBadRequest {
		return &Validation{Valid: false, Message: apiErr.Message, Details: apiErr.Data}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(resp.body)) == 0 {
		return &Validation{Valid: true}, nil
	}
	var out struct {
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(resp.body, &out); err != nil {
		return nil, fmt.Errorf("tailscale: decoding validation result: %w", err)
	}
	if out.Message == "" && len(out.Data) == 0 {
		return &Validation{Valid: true}, nil
	}
	return &Validation{Valid: false, Message: out.Message, Details: out.Data}, nil
}

type PreviewType string

const (
	PreviewUser   PreviewType = "user"
	PreviewIPPort PreviewType = "ipport"
)

type RuleMatch struct {
	Users      []string `json:"users"`
	Ports      []string `json:"ports"`
	LineNumber int      `json:"lineNumber"`
}

type Preview struct {
	Type       PreviewType `json:"type"`
	PreviewFor string      `json:"previewFor"`
	Matches    []RuleMatch `json:"matches"`
}

func (c *Client) PreviewRuleMatches(ctx context.Context, typ PreviewType, target, policy string) (*Preview, error) {
	if typ != PreviewUser && typ != PreviewIPPort {
		return nil, fmt.Errorf("tailscale: preview type must be %q or %q", PreviewUser, PreviewIPPort)
	}
	if target == "" {
		return nil, errors.New("tailscale: preview target is required")
	}
	if strings.TrimSpace(policy) == "" {
		return nil, errors.New("tailscale: policy is required")
	}
	var out Preview
	err := c.doJSON(ctx, request{
		method:      http.MethodPost,
		path:        c.tailnetPath("acl", "preview"),
		query:       url.Values{"type": {string(typ)}, "previewFor": {target}},
		body:        []byte(policy),
		contentType: hujson,
	}, &out)
	if err != nil {
		return nil, err
	}
	if out.Matches == nil {
		out.Matches = []RuleMatch{}
	}
	return &out, nil
}
