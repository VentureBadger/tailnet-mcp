package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type APIKey string

func (k APIKey) Authorize(_ context.Context, r *http.Request) error {
	r.SetBasicAuth(string(k), "")
	return nil
}

type OAuthConfig struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
	TokenURL     string
	HTTPClient   *http.Client
}

type OAuth struct {
	cfg OAuthConfig
	now func() time.Time

	mu     sync.Mutex
	token  string
	expiry time.Time
}

const tokenRefreshMargin = time.Minute

func NewOAuth(cfg OAuthConfig) (*OAuth, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("tailscale: oauth client id and secret are required")
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = DefaultBaseURL + "/api/v2/oauth/token"
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &OAuth{cfg: cfg, now: time.Now}, nil
}

func (o *OAuth) Authorize(ctx context.Context, r *http.Request) error {
	token, err := o.accessToken(ctx)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (o *OAuth) Invalidate() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.token = ""
	o.expiry = time.Time{}
}

func (o *OAuth) accessToken(ctx context.Context) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.token != "" && o.now().Before(o.expiry.Add(-tokenRefreshMargin)) {
		return o.token, nil
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {o.cfg.ClientID},
		"client_secret": {o.cfg.ClientSecret},
	}
	if len(o.cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(o.cfg.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("tailscale oauth: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := o.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("tailscale oauth: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("tailscale oauth: reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("tailscale oauth: %w", parseAPIError(resp.StatusCode, body))
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("tailscale oauth: decoding token: %w", err)
	}
	if tok.AccessToken == "" {
		return "", errors.New("tailscale oauth: token response had no access_token")
	}
	lifetime := time.Duration(tok.ExpiresIn) * time.Second
	if lifetime <= 0 {
		lifetime = time.Hour
	}

	o.token = tok.AccessToken
	o.expiry = o.now().Add(lifetime)
	return o.token, nil
}
