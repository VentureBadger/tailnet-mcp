package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultBaseURL = "https://api.tailscale.com"

	maxResponseBytes = 16 << 20
	maxRetryAfter    = 30 * time.Second
	maxBackoff       = 5 * time.Second
)

type Credentials interface {
	Authorize(ctx context.Context, r *http.Request) error
}

type invalidator interface {
	Invalidate()
}

type Config struct {
	BaseURL     string
	Tailnet     string
	Credentials Credentials
	HTTPClient  *http.Client
	MaxRetries  int
	RetryWait   time.Duration
	Logger      *slog.Logger
}

type Client struct {
	baseURL    string
	tailnet    string
	creds      Credentials
	http       *http.Client
	maxRetries int
	retryWait  time.Duration
	log        *slog.Logger
}

func New(cfg Config) (*Client, error) {
	if cfg.Credentials == nil {
		return nil, errors.New("tailscale: credentials are required")
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		base = DefaultBaseURL
	}
	if _, err := url.ParseRequestURI(base); err != nil {
		return nil, fmt.Errorf("tailscale: invalid base URL: %w", err)
	}
	c := &Client{
		baseURL:    base,
		tailnet:    cfg.Tailnet,
		creds:      cfg.Credentials,
		http:       cfg.HTTPClient,
		maxRetries: cfg.MaxRetries,
		retryWait:  cfg.RetryWait,
		log:        cfg.Logger,
	}
	if c.tailnet == "" {
		c.tailnet = "-"
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: 30 * time.Second}
	}
	if c.maxRetries < 0 {
		c.maxRetries = 0
	}
	if c.retryWait <= 0 {
		c.retryWait = 250 * time.Millisecond
	}
	if c.log == nil {
		c.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return c, nil
}

type APIError struct {
	Status  int
	Message string
	Data    json.RawMessage
}

func (e *APIError) Error() string {
	text := http.StatusText(e.Status)
	if e.Message == "" {
		return fmt.Sprintf("tailscale api: %d %s", e.Status, text)
	}
	return fmt.Sprintf("tailscale api: %d %s: %s", e.Status, text, e.Message)
}

func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound
}

type request struct {
	method      string
	path        string
	query       url.Values
	body        []byte
	contentType string
	accept      string
}

type response struct {
	header http.Header
	body   []byte
}

func (c *Client) tailnetPath(parts ...string) string {
	return "/api/v2/tailnet/" + url.PathEscape(c.tailnet) + "/" + strings.Join(parts, "/")
}

func devicePath(id string, parts ...string) string {
	p := "/api/v2/device/" + url.PathEscape(id)
	if len(parts) > 0 {
		p += "/" + strings.Join(parts, "/")
	}
	return p
}

func (c *Client) doJSON(ctx context.Context, req request, out any) error {
	resp, err := c.do(ctx, req)
	if err != nil {
		return err
	}
	if out == nil || len(bytes.TrimSpace(resp.body)) == 0 {
		return nil
	}
	if err := json.Unmarshal(resp.body, out); err != nil {
		return fmt.Errorf("tailscale: decoding %s %s: %w", req.method, req.path, err)
	}
	return nil
}

func (c *Client) do(ctx context.Context, req request) (*response, error) {
	target := c.baseURL + req.path
	if len(req.query) > 0 {
		target += "?" + req.query.Encode()
	}

	reauthorized := false
	for attempt := 0; ; attempt++ {
		resp, err := c.attempt(ctx, req, target)
		if err == nil {
			return resp, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		var apiErr *APIError
		isAPIErr := errors.As(err, &apiErr)

		if isAPIErr && apiErr.Status == http.StatusUnauthorized && !reauthorized {
			if inv, ok := c.creds.(invalidator); ok {
				inv.Invalidate()
				reauthorized = true
				continue
			}
		}

		if attempt >= c.maxRetries || (isAPIErr && !retryableStatus(apiErr.Status)) {
			return nil, err
		}

		wait := c.backoff(attempt)
		if retryAfter, ok := err.(retryAfterError); ok && retryAfter.after > 0 {
			wait = retryAfter.after
		}
		c.log.Warn("retrying tailscale request",
			"method", req.method, "path", req.path, "attempt", attempt+1, "wait", wait, "error", err)
		if err := sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

type retryAfterError struct {
	*APIError
	after time.Duration
}

func (e retryAfterError) Unwrap() error { return e.APIError }

func (c *Client) attempt(ctx context.Context, req request, target string) (*response, error) {
	var body io.Reader
	if req.body != nil {
		body = bytes.NewReader(req.body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.method, target, body)
	if err != nil {
		return nil, fmt.Errorf("tailscale: building request: %w", err)
	}
	if req.contentType != "" {
		httpReq.Header.Set("Content-Type", req.contentType)
	}
	accept := req.accept
	if accept == "" {
		accept = "application/json"
	}
	httpReq.Header.Set("Accept", accept)
	httpReq.Header.Set("User-Agent", "tailnet-mcp")
	if err := c.creds.Authorize(ctx, httpReq); err != nil {
		return nil, err
	}

	httpResp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("tailscale: %s %s: %w", req.method, req.path, err)
	}
	defer httpResp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("tailscale: reading response: %w", err)
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("tailscale: response from %s exceeds %d bytes", req.path, maxResponseBytes)
	}

	if httpResp.StatusCode >= 400 {
		apiErr := parseAPIError(httpResp.StatusCode, data)
		if after := parseRetryAfter(httpResp.Header.Get("Retry-After"), time.Now()); after > 0 {
			return nil, retryAfterError{APIError: apiErr, after: after}
		}
		return nil, apiErr
	}
	return &response{header: httpResp.Header, body: data}, nil
}

func parseAPIError(status int, body []byte) *APIError {
	apiErr := &APIError{Status: status}
	var payload struct {
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	}
	if json.Unmarshal(body, &payload) == nil {
		apiErr.Message = payload.Message
		apiErr.Data = payload.Data
	} else {
		apiErr.Message = strings.TrimSpace(string(body))
	}
	return apiErr
}

func retryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable,
		http.StatusGatewayTimeout, http.StatusInternalServerError:
		return true
	}
	return false
}

func parseRetryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	var d time.Duration
	if secs, err := strconv.Atoi(v); err == nil {
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	if d < 0 {
		return 0
	}
	return min(d, maxRetryAfter)
}

func (c *Client) backoff(attempt int) time.Duration {
	ceiling := min(c.retryWait<<attempt, maxBackoff)
	return time.Duration(rand.Int63n(int64(ceiling) + 1))
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
