package mcp

import (
	bytes "bytes"
	json "encoding/json"
	fmt "fmt"

	fiber "github.com/gofiber/fiber/v3"

	security "ipb/server/security"
)

// Tool is one thing an agent can do through /mcp.
//
// Adding one is the MCP version of adding a route: write it next to the
// others in server/routes/mcp_tools.go, calling the same model functions the
// matching HTTP handler calls, so a rule enforced in a model holds whichever
// door a change comes through. The defaults match the rest of the template:
//
//   - Any signed-in key, unless the user asked for admin. AdminOnly hides the
//     tool from user-scoped keys entirely.
//   - Never create a credential or delete anything. /mcp only accepts API
//     keys, and those routes need a browser session (see RequireSession) so
//     that revoking a leaked key really ends it, and so that a key can never
//     erase what cannot be put back. A tool is a key-authenticated route; the
//     same rule applies.
//   - Mark the hints honestly. ReadOnly and Destructive become the spec's
//     readOnlyHint / destructiveHint, which a client uses to decide whether to
//     ask the person before calling. They are advice to the client, not
//     protection -- the protection is the role check and the model rules.
type Tool struct {
	Name        string
	Title       string
	Description string
	// InputSchema is the JSON Schema of the arguments object. Nil means the
	// tool takes none.
	InputSchema fiber.Map
	ReadOnly    bool
	Destructive bool
	AdminOnly   bool
	// Enabled, when set, is asked on every call: a tool for a feature that is
	// switched off answers exactly like one that does not exist. Nil is always.
	Enabled func() bool
	Call        func( call *Call ) ( result any , err error )
}

// Call is what a tool gets: the request (for anything the handler would
// read), who is calling at which effective role, and its raw arguments.
type Call struct {
	Ctx   fiber.Ctx
	Actor *security.Actor
	Args  json.RawMessage
}

// Bind decodes the arguments into a struct, strictly: an unknown field is an
// error, the same rule config.yaml follows, so a misspelt argument is reported
// rather than silently ignored. Its error turns into a JSON-RPC
// invalid-params reply.
func ( call *Call ) Bind( out any ) ( err error ) {
	raw := call.Args
	if len( bytes.TrimSpace( raw ) ) == 0 || bytes.Equal( bytes.TrimSpace( raw ) , []byte( "null" ) ) {
		raw = json.RawMessage( "{}" )
	}
	decoder := json.NewDecoder( bytes.NewReader( raw ) )
	decoder.DisallowUnknownFields()
	if decode_err := decoder.Decode( out ); decode_err != nil {
		err = &invalidArgs{ message: "invalid arguments: " + decode_err.Error() }
	}
	return
}

// Refusal is a tool saying no for a reason the caller should read -- "no such
// user", "the owner account cannot be disabled". It becomes a tool result
// with isError set, worded like the HTTP route's error, so the model sees why
// and can try something else. Any other error is logged and reported only as
// "internal error".
type Refusal struct {
	Message string
}

func ( refusal *Refusal ) Error() ( result string ) {
	result = refusal.Message
	return
}

func Refuse( message string ) ( err error ) {
	err = &Refusal{ Message: message }
	return
}

type invalidArgs struct {
	message string
}

func ( invalid *invalidArgs ) Error() ( result string ) {
	result = invalid.message
	return
}

// Register adds a tool. A duplicate name is a programming error and panics at
// startup, where it is noticed, rather than one tool silently shadowing
// another.
func ( server *Server ) Register( tool *Tool ) {
	if _ , exists := server.by_name[ tool.Name ]; exists {
		panic( fmt.Sprintf( "mcp: tool %q registered twice" , tool.Name ) )
	}
	server.tools = append( server.tools , tool )
	server.by_name[ tool.Name ] = tool
}

func ( tool *Tool ) visibleTo( actor *security.Actor ) ( result bool ) {
	if tool.Enabled != nil && tool.Enabled() == false { return }
	result = tool.AdminOnly == false || ( actor != nil && actor.IsAdmin() )
	return
}

// visible is tools/list for one actor: the tools its effective role may call,
// in registration order, so a user-scoped key is never even told the admin
// tools exist.
func ( server *Server ) visible( actor *security.Actor ) ( listed []fiber.Map ) {
	listed = []fiber.Map{}
	for _ , tool := range server.tools {
		if tool.visibleTo( actor ) == false { continue }
		schema := tool.InputSchema
		if schema == nil {
			schema = fiber.Map{ "type": "object" , "properties": fiber.Map{} , "additionalProperties": false }
		}
		listed = append( listed , fiber.Map{
			"name":        tool.Name,
			"title":       tool.Title,
			"description": tool.Description,
			"inputSchema": schema,
			"annotations": fiber.Map{
				"title":           tool.Title,
				"readOnlyHint":    tool.ReadOnly,
				"destructiveHint": tool.Destructive,
				// Every tool here acts on this server's own records, never
				// the open internet.
				"openWorldHint": false,
			},
		} )
	}
	return
}
