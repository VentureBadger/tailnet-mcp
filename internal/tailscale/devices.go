package tailscale

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
)

type Device struct {
	ID                        string          `json:"id"`
	NodeID                    string          `json:"nodeId"`
	Name                      string          `json:"name"`
	Hostname                  string          `json:"hostname"`
	User                      string          `json:"user"`
	OS                        string          `json:"os"`
	Addresses                 []string        `json:"addresses"`
	Tags                      []string        `json:"tags"`
	Authorized                bool            `json:"authorized"`
	ConnectedToControl        bool            `json:"connectedToControl"`
	LastSeen                  string          `json:"lastSeen"`
	Created                   string          `json:"created"`
	Expires                   string          `json:"expires"`
	KeyExpiryDisabled         bool            `json:"keyExpiryDisabled"`
	ClientVersion             string          `json:"clientVersion"`
	UpdateAvailable           bool            `json:"updateAvailable"`
	IsEphemeral               bool            `json:"isEphemeral"`
	IsExternal                bool            `json:"isExternal"`
	BlocksIncomingConnections bool            `json:"blocksIncomingConnections"`
	TailnetLockError          string          `json:"tailnetLockError,omitempty"`
	AdvertisedRoutes          []string        `json:"advertisedRoutes,omitempty"`
	EnabledRoutes             []string        `json:"enabledRoutes,omitempty"`
	ClientConnectivity        json.RawMessage `json:"clientConnectivity,omitempty"`
}

func (c *Client) Devices(ctx context.Context) ([]Device, error) {
	var out struct {
		Devices []Device `json:"devices"`
	}
	err := c.doJSON(ctx, request{method: http.MethodGet, path: c.tailnetPath("devices")}, &out)
	if err != nil {
		return nil, err
	}
	return out.Devices, nil
}

func (c *Client) Device(ctx context.Context, id string) (*Device, error) {
	if id == "" {
		return nil, errors.New("tailscale: device id is required")
	}
	var d Device
	err := c.doJSON(ctx, request{
		method: http.MethodGet,
		path:   devicePath(id),
		query:  url.Values{"fields": {"all"}},
	}, &d)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (c *Client) SetAuthorized(ctx context.Context, id string, authorized bool) error {
	if id == "" {
		return errors.New("tailscale: device id is required")
	}
	body, err := json.Marshal(map[string]bool{"authorized": authorized})
	if err != nil {
		return err
	}
	return c.doJSON(ctx, request{
		method:      http.MethodPost,
		path:        devicePath(id, "authorized"),
		body:        body,
		contentType: "application/json",
	}, nil)
}

func (c *Client) SetTags(ctx context.Context, id string, tags []string) error {
	if id == "" {
		return errors.New("tailscale: device id is required")
	}
	if tags == nil {
		tags = []string{}
	}
	body, err := json.Marshal(map[string][]string{"tags": tags})
	if err != nil {
		return err
	}
	return c.doJSON(ctx, request{
		method:      http.MethodPost,
		path:        devicePath(id, "tags"),
		body:        body,
		contentType: "application/json",
	}, nil)
}
