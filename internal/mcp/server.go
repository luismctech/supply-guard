package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/AlbertoMZCruz/supply-guard/internal/version"
)

// Server implements an MCP server over stdio using JSON-RPC 2.0.
type Server struct {
	tools     map[string]ToolHandler
	resources []resourceDefinition
	resRead   map[string]ResourceReader
}

// ToolHandler processes an MCP tool call and returns text content.
type ToolHandler func(ctx context.Context, args json.RawMessage) (string, error)

// ResourceReader returns the text content for a resource URI.
type ResourceReader func(ctx context.Context, uri string) (string, error)

func NewServer() *Server {
	return &Server{
		tools:   make(map[string]ToolHandler),
		resRead: make(map[string]ResourceReader),
	}
}

func (s *Server) RegisterTool(name, description string, schema json.RawMessage, handler ToolHandler) {
	s.tools[name] = handler
	_ = toolDefinition{Name: name, Description: description, InputSchema: schema}
}

func (s *Server) RegisterResource(uri, name, description, mimeType string, reader ResourceReader) {
	s.resources = append(s.resources, resourceDefinition{
		URI:         uri,
		Name:        name,
		Description: description,
		MIMEType:    mimeType,
	})
	s.resRead[uri] = reader
}

// Run starts the stdio JSON-RPC loop. It blocks until stdin is closed.
func (s *Server) Run(ctx context.Context) error {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req jsonrpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.writeError(nil, -32700, "Parse error: "+err.Error())
			continue
		}

		resp := s.handleRequest(ctx, &req)
		if resp != nil {
			s.writeResponse(resp)
		}
	}

	return scanner.Err()
}

func (s *Server) handleRequest(ctx context.Context, req *jsonrpcRequest) *jsonrpcResponse {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "initialized":
		return nil // notification, no response
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(ctx, req)
	case "resources/list":
		return s.handleResourcesList(req)
	case "resources/read":
		return s.handleResourcesRead(ctx, req)
	case "notifications/cancelled":
		return nil
	default:
		return &jsonrpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &jsonrpcError{Code: -32601, Message: "Method not found: " + req.Method},
		}
	}
}

func (s *Server) handleInitialize(req *jsonrpcRequest) *jsonrpcResponse {
	return &jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: initializeResult{
			ProtocolVersion: "2024-11-05",
			ServerInfo: serverInfo{
				Name:    "supply-guard",
				Version: version.Version,
			},
			Capabilities: serverCapabilities{
				Tools:     &capabilityObj{},
				Resources: &capabilityObj{},
			},
		},
	}
}

func (s *Server) handleToolsList(req *jsonrpcRequest) *jsonrpcResponse {
	tools := getToolDefinitions()
	return &jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  toolsListResult{Tools: tools},
	}
}

func (s *Server) handleToolsCall(ctx context.Context, req *jsonrpcRequest) *jsonrpcResponse {
	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &jsonrpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &jsonrpcError{Code: -32602, Message: "Invalid params: " + err.Error()},
		}
	}

	handler, ok := s.tools[params.Name]
	if !ok {
		return &jsonrpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &jsonrpcError{Code: -32602, Message: "Unknown tool: " + params.Name},
		}
	}

	text, err := handler(ctx, params.Arguments)
	if err != nil {
		return &jsonrpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: toolCallResult{
				Content: []contentItem{{Type: "text", Text: "Error: " + err.Error()}},
				IsError: true,
			},
		}
	}

	return &jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: toolCallResult{
			Content: []contentItem{{Type: "text", Text: text}},
		},
	}
}

func (s *Server) handleResourcesList(req *jsonrpcRequest) *jsonrpcResponse {
	return &jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  resourcesListResult{Resources: s.resources},
	}
}

func (s *Server) handleResourcesRead(ctx context.Context, req *jsonrpcRequest) *jsonrpcResponse {
	var params resourceReadParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &jsonrpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &jsonrpcError{Code: -32602, Message: "Invalid params: " + err.Error()},
		}
	}

	reader, ok := s.findResourceReader(params.URI)
	if !ok {
		return &jsonrpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &jsonrpcError{Code: -32602, Message: "Unknown resource: " + params.URI},
		}
	}

	text, err := reader(ctx, params.URI)
	if err != nil {
		return &jsonrpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &jsonrpcError{Code: -32603, Message: err.Error()},
		}
	}

	return &jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: resourceReadResult{
			Contents: []resourceContent{{
				URI:      params.URI,
				MIMEType: "text/plain",
				Text:     text,
			}},
		},
	}
}

func (s *Server) findResourceReader(uri string) (ResourceReader, bool) {
	if reader, ok := s.resRead[uri]; ok {
		return reader, true
	}
	for registeredURI, reader := range s.resRead {
		if strings.HasSuffix(registeredURI, "/{dir}") {
			prefix := strings.TrimSuffix(registeredURI, "{dir}")
			if strings.HasPrefix(uri, prefix) {
				return reader, true
			}
		}
	}
	return nil, false
}

func (s *Server) writeResponse(resp *jsonrpcResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		s.writeError(nil, -32603, "Internal error: "+err.Error())
		return
	}
	fmt.Fprintf(os.Stdout, "%s\n", data)
}

func (s *Server) writeError(id json.RawMessage, code int, msg string) {
	resp := &jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonrpcError{Code: code, Message: msg},
	}
	data, _ := json.Marshal(resp)
	fmt.Fprintf(os.Stdout, "%s\n", data)
}

// Discard stderr during MCP mode to keep stdio clean
func init() {
	_ = io.Discard
}
