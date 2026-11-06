// Package mcp answers the Model Context Protocol on POST /mcp, so an agent --
// Claude Code, or any MCP client that can send a header -- can use this app
// through the same API keys and the same admin/user roles as every other
// script. It is the protocol only: which tools exist is decided by whoever
// registers them (server/routes/mcp_tools.go), and who may call them is
// decided where the route is registered (routes.go) and by each tool's
// AdminOnly flag, read against the actor's effective role.
//
// It speaks the Streamable HTTP transport in its simplest legal form:
// stateless, one JSON-RPC message per POST, a plain JSON reply. No SSE
// stream, no Mcp-Session-Id, no server-initiated messages. A tool call here is
// an ordinary request -- authenticate, check, act, answer -- so there is no
// per-client state to hold, expire, or leak between keys, and nothing about it
// needs a second process or a sticky load balancer.
//
// Written by hand rather than with an SDK because the subset is small (four
// methods) and the template's rule is no dependency it does not need: an SDK
// would bring net/http adaptors, a schema library, and transport code for the
// half of the spec this server deliberately does not use.
package mcp

import (
	bytes "bytes"
	json "encoding/json"
	errors "errors"
	log "log"
	url "net/url"

	fiber "github.com/gofiber/fiber/v3"

	security "ipb/server/security"
)

// SupportedVersions are the protocol revisions this server can answer, newest
// first. Everything used here (tools, JSON responses, annotations) means the
// same in each of them.
var SupportedVersions = []string{ "2025-11-25" , "2025-06-18" , "2025-03-26" }

// JSON-RPC error codes. Only these leave the server; anything else that goes
// wrong inside a tool is a tool result with isError set, which is what the
// spec asks for so the model can read the failure and react.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

type Server struct {
	Name    string
	Version string
	tools   []*Tool
	by_name map[ string ]*Tool
}

func New( name string , version string ) ( server *Server ) {
	server = &Server{ Name: name , Version: version , by_name: map[ string ]*Tool{} }
	return
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// Handle is the POST /mcp endpoint. routes.go puts RequireLogin and
// RequireAPIKey in front of it, so an actor is always present and always
// came in through a key.
func ( server *Server ) Handle( c fiber.Ctx ) ( err error ) {
	// The spec asks servers to check Origin against DNS rebinding. With a
	// bearer key required that attack has nothing to ride on -- a rebound
	// page carries no key -- but a browser page has no business here either,
	// so a cross-origin one is refused rather than reasoned about.
	if origin := c.Get( fiber.HeaderOrigin ); origin != "" {
		parsed , parse_err := url.Parse( origin )
		if parse_err != nil || parsed.Host != c.Host() {
			err = c.Status( fiber.StatusForbidden ).JSON( fiber.Map{ "error": "cross-origin requests are not accepted" } )
			return
		}
	}
	// After initialize, a client names the revision it settled on in this
	// header on every request. One we never offered means the two sides
	// disagree about the protocol, which is better said than guessed past.
	if version := c.Get( "MCP-Protocol-Version" ); version != "" && supported( version ) == false {
		err = c.Status( fiber.StatusBadRequest ).JSON( fiber.Map{ "error": "unsupported MCP-Protocol-Version" } )
		return
	}

	body := bytes.TrimSpace( c.Body() )
	// JSON-RPC batches were removed from MCP in 2025-06-18; refusing them
	// keeps one message per request, which is what makes the rate limiter
	// and the logs mean something.
	if len( body ) > 0 && body[ 0 ] == '[' {
		err = server.fail( c , fiber.StatusBadRequest , nil , codeInvalidRequest , "batch requests are not supported" )
		return
	}
	var message request
	if json.Unmarshal( body , &message ) != nil {
		err = server.fail( c , fiber.StatusBadRequest , nil , codeParseError , "parse error" )
		return
	}
	if message.JSONRPC != "2.0" || message.Method == "" {
		err = server.fail( c , fiber.StatusBadRequest , message.ID , codeInvalidRequest , "invalid request" )
		return
	}
	// A notification (no id) gets no answer, only an acknowledgement. The
	// ones a client sends -- initialized, cancelled -- need nothing from a
	// stateless server, so they are all accepted and dropped.
	if len( message.ID ) == 0 {
		err = c.SendStatus( fiber.StatusAccepted )
		return
	}
	if bytes.Equal( message.ID , []byte( "null" ) ) {
		err = server.fail( c , fiber.StatusBadRequest , nil , codeInvalidRequest , "id must not be null" )
		return
	}

	actor := security.ActorFrom( c )
	var result any
	var call_err error
	switch message.Method {
	case "initialize":
		result , call_err = server.initialize( message.Params )
	case "ping":
		result = fiber.Map{}
	case "tools/list":
		result = fiber.Map{ "tools": server.visible( actor ) }
	case "tools/call":
		result , call_err = server.call( c , actor , message.Params )
	default:
		call_err = &rpcError{ Code: codeMethodNotFound , Message: "method not found: " + message.Method }
	}
	if call_err != nil {
		var rpc_err *rpcError
		if errors.As( call_err , &rpc_err ) == false {
			log.Printf( "[mcp] %s: %v" , message.Method , call_err )
			rpc_err = &rpcError{ Code: codeInternalError , Message: "internal error" }
		}
		err = server.fail( c , fiber.StatusOK , message.ID , rpc_err.Code , rpc_err.Message )
		return
	}
	err = c.JSON( response{ JSONRPC: "2.0" , ID: message.ID , Result: result } )
	return
}

// MethodNotAllowed answers GET and DELETE on /mcp. GET is how a client asks
// for a server-to-client SSE stream and DELETE how it ends a session; this
// server has neither, and 405 is the reply the spec gives for that.
func ( server *Server ) MethodNotAllowed( c fiber.Ctx ) ( err error ) {
	c.Set( fiber.HeaderAllow , fiber.MethodPost )
	err = c.SendStatus( fiber.StatusMethodNotAllowed )
	return
}

func ( rpc_err *rpcError ) Error() ( result string ) {
	result = rpc_err.Message
	return
}

func ( server *Server ) fail( c fiber.Ctx , status int , id json.RawMessage , code int , message string ) ( err error ) {
	if len( id ) == 0 {
		id = json.RawMessage( "null" )
	}
	err = c.Status( status ).JSON( response{ JSONRPC: "2.0" , ID: id , Error: &rpcError{ Code: code , Message: message } } )
	return
}

func supported( version string ) ( result bool ) {
	for _ , known := range SupportedVersions {
		if known == version {
			result = true
			return
		}
	}
	return
}

// initialize negotiates the revision: the client's if we know it, otherwise
// our newest, and the client decides whether it can live with that.
func ( server *Server ) initialize( params json.RawMessage ) ( result any , err error ) {
	var body struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if len( params ) > 0 && json.Unmarshal( params , &body ) != nil {
		err = &rpcError{ Code: codeInvalidParams , Message: "invalid initialize params" }
		return
	}
	version := SupportedVersions[ 0 ]
	if supported( body.ProtocolVersion ) {
		version = body.ProtocolVersion
	}
	result = fiber.Map{
		"protocolVersion": version,
		// listChanged false: the tool list is fixed at startup. It differs
		// between keys (admin tools are hidden from a user-scoped key), but
		// never changes under one.
		"capabilities": fiber.Map{ "tools": fiber.Map{ "listChanged": false } },
		"serverInfo":   fiber.Map{ "name": server.Name , "version": server.Version },
	}
	return
}

func ( server *Server ) call( c fiber.Ctx , actor *security.Actor , params json.RawMessage ) ( result any , err error ) {
	var body struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal( params , &body ) != nil || body.Name == "" {
		err = &rpcError{ Code: codeInvalidParams , Message: "tools/call needs a tool name" }
		return
	}
	tool := server.by_name[ body.Name ]
	// An admin tool asked for by a user-scoped key answers exactly like a
	// tool that does not exist: it was never listed to that key, and saying
	// "forbidden" would only confirm the name.
	if tool == nil || tool.visibleTo( actor ) == false {
		err = &rpcError{ Code: codeInvalidParams , Message: "unknown tool: " + body.Name }
		return
	}

	value , tool_err := tool.Call( &Call{ Ctx: c , Actor: actor , Args: body.Arguments } )
	if tool_err != nil {
		var invalid *invalidArgs
		var refused *Refusal
		switch {
		case errors.As( tool_err , &invalid ):
			err = &rpcError{ Code: codeInvalidParams , Message: invalid.message }
		case errors.As( tool_err , &refused ):
			result = toolResult( fiber.Map{ "error": refused.Message } , true )
		default:
			// Same rule as the HTTP error handler: the detail goes to the
			// log, never to the caller.
			log.Printf( "[mcp] tool %s: %v" , tool.Name , tool_err )
			result = toolResult( fiber.Map{ "error": "internal error" } , true )
		}
		return
	}
	result = toolResult( value , false )
	return
}

// toolResult wraps a tool's return value both ways the spec offers: as JSON
// text, which every client can show a model, and as structuredContent, which
// newer clients read directly. Tools return objects so the second is always
// valid -- structuredContent must be one.
func toolResult( value any , is_error bool ) ( result fiber.Map ) {
	encoded , _ := json.Marshal( value )
	result = fiber.Map{
		"content": []fiber.Map{ { "type": "text" , "text": string( encoded ) } },
		"isError": is_error,
	}
	if len( encoded ) > 0 && encoded[ 0 ] == '{' {
		result[ "structuredContent" ] = json.RawMessage( encoded )
	}
	return
}
