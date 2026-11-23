package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sync"
)

var SupportedProtocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

const maxMessageBytes = 16 << 20

const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Annotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    bool   `json:"readOnlyHint"`
	DestructiveHint bool   `json:"destructiveHint"`
	IdempotentHint  bool   `json:"idempotentHint"`
	OpenWorldHint   bool   `json:"openWorldHint"`
}

type Handler func(ctx context.Context, args json.RawMessage) (any, error)

type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations *Annotations    `json:"annotations,omitempty"`
	Handler     Handler         `json:"-"`
}

type Server struct {
	info         Implementation
	instructions string
	tools        []Tool
	byName       map[string]*Tool
	log          *slog.Logger

	writeMu sync.Mutex
	out     io.Writer

	inflightMu sync.Mutex
	inflight   map[string]context.CancelFunc
}

func NewServer(info Implementation, instructions string, tools []Tool, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{
		info:         info,
		instructions: instructions,
		tools:        tools,
		byName:       make(map[string]*Tool, len(tools)),
		log:          log,
		inflight:     make(map[string]context.CancelFunc),
	}
	for i := range tools {
		t := &tools[i]
		if t.Handler == nil {
			return nil, fmt.Errorf("mcp: tool %q has no handler", t.Name)
		}
		if !json.Valid(t.InputSchema) {
			return nil, fmt.Errorf("mcp: tool %q has an invalid input schema", t.Name)
		}
		if _, dup := s.byName[t.Name]; dup {
			return nil, fmt.Errorf("mcp: duplicate tool %q", t.Name)
		}
		s.byName[t.Name] = t
	}
	return s, nil
}

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type reply struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	s.out = out
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	lines := make(chan []byte)
	readErr := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(in)
		sc.Buffer(make([]byte, 64<<10), maxMessageBytes)
		for sc.Scan() {
			line := bytes.Clone(sc.Bytes())
			select {
			case lines <- line:
			case <-ctx.Done():
				return
			}
		}
		readErr <- sc.Err()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErr:
			wg.Wait()
			return err
		case line := <-lines:
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			s.dispatch(ctx, line, &wg)
		}
	}
}

func (s *Server) dispatch(ctx context.Context, line []byte, wg *sync.WaitGroup) {
	var msg message
	if err := json.Unmarshal(line, &msg); err != nil {
		s.send(reply{ID: json.RawMessage("null"), Error: &rpcError{codeParseError, "parse error"}})
		return
	}
	if msg.JSONRPC != "2.0" || msg.Method == "" {
		if len(msg.ID) > 0 {
			s.send(reply{ID: msg.ID, Error: &rpcError{codeInvalidRequest, "invalid request"}})
		}
		return
	}
	if len(msg.ID) == 0 || string(msg.ID) == "null" {
		s.notify(msg)
		return
	}

	reqCtx, cancel := context.WithCancel(ctx)
	key := string(msg.ID)
	s.inflightMu.Lock()
	s.inflight[key] = cancel
	s.inflightMu.Unlock()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			s.inflightMu.Lock()
			delete(s.inflight, key)
			s.inflightMu.Unlock()
			cancel()
		}()
		result, rerr := s.handle(reqCtx, msg)
		if reqCtx.Err() != nil && ctx.Err() == nil {
			return
		}
		s.send(reply{ID: msg.ID, Result: result, Error: rerr})
	}()
}

func (s *Server) notify(msg message) {
	if msg.Method != "notifications/cancelled" {
		return
	}
	var p struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if json.Unmarshal(msg.Params, &p) != nil {
		return
	}
	s.inflightMu.Lock()
	cancel, ok := s.inflight[string(p.RequestID)]
	s.inflightMu.Unlock()
	if ok {
		cancel()
	}
}

func (s *Server) handle(ctx context.Context, msg message) (result any, rerr *rpcError) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("panic handling request", "method", msg.Method, "panic", r)
			result, rerr = nil, &rpcError{codeInternalError, "internal error"}
		}
	}()

	switch msg.Method {
	case "initialize":
		return s.initialize(msg.Params)
	case "ping":
		return struct{}{}, nil
	case "tools/list":
		return map[string]any{"tools": s.tools}, nil
	case "tools/call":
		return s.callTool(ctx, msg.Params)
	default:
		return nil, &rpcError{codeMethodNotFound, "method not found: " + msg.Method}
	}
}

func (s *Server) initialize(params json.RawMessage) (any, *rpcError) {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{codeInvalidParams, "invalid initialize params"}
	}
	version := SupportedProtocolVersions[0]
	if slices.Contains(SupportedProtocolVersions, p.ProtocolVersion) {
		version = p.ProtocolVersion
	}
	result := map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]bool{"listChanged": false}},
		"serverInfo":      s.info,
	}
	if s.instructions != "" {
		result["instructions"] = s.instructions
	}
	return result, nil
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type callResult struct {
	Content []content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

func (s *Server) callTool(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{codeInvalidParams, "invalid tools/call params"}
	}
	tool, ok := s.byName[p.Name]
	if !ok {
		return nil, &rpcError{codeInvalidParams, "unknown tool: " + p.Name}
	}
	if len(p.Arguments) == 0 || string(p.Arguments) == "null" {
		p.Arguments = json.RawMessage("{}")
	}

	out, err := tool.Handler(ctx, p.Arguments)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, &rpcError{codeInternalError, "request cancelled"}
		}
		s.log.Info("tool returned an error", "tool", p.Name, "error", err)
		return callResult{Content: []content{{Type: "text", Text: err.Error()}}, IsError: true}, nil
	}

	text, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, &rpcError{codeInternalError, "encoding tool result failed"}
	}
	return callResult{Content: []content{{Type: "text", Text: string(text)}}}, nil
}

func (s *Server) send(r reply) {
	r.JSONRPC = "2.0"
	data, err := json.Marshal(r)
	if err != nil {
		s.log.Error("encoding reply failed", "error", err)
		return
	}
	data = append(data, '\n')
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.out.Write(data); err != nil {
		s.log.Error("writing reply failed", "error", err)
	}
}
