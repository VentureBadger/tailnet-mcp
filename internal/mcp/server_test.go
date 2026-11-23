package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type session struct {
	t      *testing.T
	in     *io.PipeWriter
	out    *bufio.Scanner
	done   chan error
	cancel context.CancelFunc
}

func start(t *testing.T, tools []Tool) *session {
	t.Helper()
	srv, err := NewServer(Implementation{Name: "test", Version: "1"}, "be careful", tools, nil)
	if err != nil {
		t.Fatal(err)
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	s := &session{t: t, in: inW, out: bufio.NewScanner(outR), done: make(chan error, 1), cancel: cancel}
	go func() { s.done <- srv.Serve(ctx, inR, outW) }()
	t.Cleanup(func() {
		cancel()
		_ = inW.Close()
		_ = outR.Close()
	})
	return s
}

func (s *session) send(msg string) {
	s.t.Helper()
	if _, err := io.WriteString(s.in, msg+"\n"); err != nil {
		s.t.Fatal(err)
	}
}

func (s *session) recv() map[string]any {
	s.t.Helper()
	got := make(chan map[string]any, 1)
	go func() {
		if !s.out.Scan() {
			got <- nil
			return
		}
		var m map[string]any
		if err := json.Unmarshal(s.out.Bytes(), &m); err != nil {
			s.t.Errorf("bad json %q: %v", s.out.Text(), err)
		}
		got <- m
	}()
	select {
	case m := <-got:
		return m
	case <-time.After(5 * time.Second):
		s.t.Fatal("timed out waiting for a reply")
		return nil
	}
}

var echo = Tool{
	Name:        "echo",
	Description: "echo",
	InputSchema: json.RawMessage(`{"type":"object"}`),
	Handler: func(_ context.Context, args json.RawMessage) (any, error) {
		var in struct{ Text string }
		_ = json.Unmarshal(args, &in)
		if in.Text == "fail" {
			return nil, errors.New("it failed")
		}
		return map[string]string{"echo": in.Text}, nil
	},
}

func TestInitializeNegotiatesVersion(t *testing.T) {
	s := start(t, []Tool{echo})

	s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`)
	r := s.recv()["result"].(map[string]any)
	if r["protocolVersion"] != "2025-03-26" || r["instructions"] != "be careful" {
		t.Fatalf("result = %v", r)
	}

	s.send(`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`)
	r = s.recv()["result"].(map[string]any)
	if r["protocolVersion"] != SupportedProtocolVersions[0] {
		t.Fatalf("unsupported version not replaced with latest: %v", r["protocolVersion"])
	}
}

func TestNotificationsGetNoReply(t *testing.T) {
	s := start(t, []Tool{echo})
	s.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	s.send(`{"jsonrpc":"2.0","id":"after","method":"ping"}`)
	if m := s.recv(); m["id"] != "after" {
		t.Fatalf("first reply = %v, want the ping", m)
	}
}

func TestToolsListAndCall(t *testing.T) {
	s := start(t, []Tool{echo})

	s.send(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	tools := s.recv()["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "echo" {
		t.Fatalf("tools = %v", tools)
	}

	s.send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"Text":"hi"}}}`)
	res := s.recv()["result"].(map[string]any)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	if res["isError"] != nil || !strings.Contains(text, `"echo": "hi"`) {
		t.Fatalf("result = %v", res)
	}
}

func TestToolErrorsAreResultsNotProtocolErrors(t *testing.T) {
	s := start(t, []Tool{echo})
	s.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"Text":"fail"}}}`)
	m := s.recv()
	res := m["result"].(map[string]any)
	if m["error"] != nil || res["isError"] != true || res["content"].([]any)[0].(map[string]any)["text"] != "it failed" {
		t.Fatalf("reply = %v", m)
	}
}

func TestProtocolErrors(t *testing.T) {
	s := start(t, []Tool{echo})
	cases := []struct {
		msg  string
		code float64
	}{
		{`not json`, codeParseError},
		{`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`, codeMethodNotFound},
		{`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nope"}}`, codeInvalidParams},
		{`{"jsonrpc":"1.0","id":3,"method":"ping"}`, codeInvalidRequest},
	}
	for _, tc := range cases {
		s.send(tc.msg)
		m := s.recv()
		e, ok := m["error"].(map[string]any)
		if !ok || e["code"] != tc.code {
			t.Errorf("%s: reply = %v, want code %v", tc.msg, m, tc.code)
		}
	}
}

func TestCancelledRequestGetsNoReply(t *testing.T) {
	started := make(chan struct{})
	slow := Tool{
		Name:        "slow",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler: func(ctx context.Context, _ json.RawMessage) (any, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	s := start(t, []Tool{slow})

	s.send(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"slow"}}`)
	<-started
	s.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}`)
	s.send(`{"jsonrpc":"2.0","id":8,"method":"ping"}`)
	if m := s.recv(); m["id"] != float64(8) {
		t.Fatalf("got reply for cancelled request: %v", m)
	}
}

func TestPanickingToolReturnsInternalError(t *testing.T) {
	boom := Tool{
		Name:        "boom",
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Handler:     func(context.Context, json.RawMessage) (any, error) { panic("boom") },
	}
	s := start(t, []Tool{boom})
	s.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"boom"}}`)
	if e, ok := s.recv()["error"].(map[string]any); !ok || e["code"] != float64(codeInternalError) {
		t.Fatal("panic not converted to internal error")
	}
}

func TestServeReturnsAtEOF(t *testing.T) {
	s := start(t, []Tool{echo})
	_ = s.in.Close()
	select {
	case err := <-s.done:
		if err != nil {
			t.Fatalf("Serve = %v, want nil at EOF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return at EOF")
	}
}

func TestNewServerRejectsBadTools(t *testing.T) {
	if _, err := NewServer(Implementation{}, "", []Tool{{Name: "x", InputSchema: json.RawMessage(`{}`)}}, nil); err == nil {
		t.Error("accepted a tool without a handler")
	}
	if _, err := NewServer(Implementation{}, "", []Tool{echo, echo}, nil); err == nil {
		t.Error("accepted duplicate tools")
	}
}
