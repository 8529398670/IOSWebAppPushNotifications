package routes

import (
	strconv "strconv"

	fiber "github.com/gofiber/fiber/v3"

	mcp "ipb/server/mcp"
)

// Every list the API hands out is paged the same way: ?limit= and ?offset= in,
// and { "<rows>": [...], "next": <offset of the next page, or null>, "total":
// <rows in all> } out.
//
// An offset rather than a cursor, on purpose. Most of these lists sort on a
// field that is encrypted at rest, so every page has to read the whole list
// anyway and a cursor would save nothing; and the natural cursor for a key or
// a session is its record id, which has no business in a URL. The cost is that
// a row deleted between two pages shifts the next one by a row. The screens
// reload from the first page after any change, so they never see that.
//
// Paging here bounds the response, not the read. See Known limits in
// references/architecture.md.

const (
	pageDefault       = 200
	pageMax           = 1000
	pageLimitMessage  = "limit must be 1-1000"
	pageOffsetMessage = "offset must be 0 or more"
)

// pageArgs is the arguments of a paged MCP tool.
type pageArgs struct {
	Limit  *int `json:"limit"`
	Offset *int `json:"offset"`
}

// pageSchema is the input schema of a paged MCP tool. Both are optional.
var pageSchema = fiber.Map{
	"type": "object",
	"properties": fiber.Map{
		"limit":  fiber.Map{ "type": "integer" , "minimum": 1 , "maximum": pageMax , "description": "Rows to return. Default 200." },
		"offset": fiber.Map{ "type": "integer" , "minimum": 0 , "description": "Rows to skip: the next value of the previous page." },
	},
	"additionalProperties": false,
}

// pageBody cuts one page out of rows, which must already be in their final
// order. name is the field the rows go under.
func pageBody[ T any ]( name string , rows []T , limit int , offset int ) ( body fiber.Map ) {
	total := len( rows )
	start := min( offset , total )
	end := min( start + limit , total )
	body = fiber.Map{ name: rows[ start:end ] , "next": nil , "total": total }
	if end < total {
		body[ "next" ] = end
	}
	return
}

// sendPage answers a list route with the page its query asks for.
func sendPage[ T any ]( c fiber.Ctx , name string , rows []T ) ( err error ) {
	limit := pageDefault
	if raw := c.Query( "limit" ); raw != "" {
		parsed , parse_err := strconv.Atoi( raw )
		if parse_err != nil || parsed < 1 || parsed > pageMax {
			err = badRequest( c , pageLimitMessage )
			return
		}
		limit = parsed
	}
	offset := 0
	if raw := c.Query( "offset" ); raw != "" {
		parsed , parse_err := strconv.Atoi( raw )
		if parse_err != nil || parsed < 0 {
			err = badRequest( c , pageOffsetMessage )
			return
		}
		offset = parsed
	}
	err = c.JSON( pageBody( name , rows , limit , offset ) )
	return
}

// toolPage is sendPage for an MCP tool, so the two doors page the same way.
func toolPage[ T any ]( call *mcp.Call , name string , load func() ( []T , error ) ) ( result any , err error ) {
	var args pageArgs
	if err = call.Bind( &args ); err != nil { return }
	limit , offset := pageDefault , 0
	if args.Limit != nil {
		limit = *args.Limit
	}
	if args.Offset != nil {
		offset = *args.Offset
	}
	if limit < 1 || limit > pageMax {
		err = mcp.Refuse( pageLimitMessage )
		return
	}
	if offset < 0 {
		err = mcp.Refuse( pageOffsetMessage )
		return
	}
	rows , err := load()
	if err != nil { return }
	result = pageBody( name , rows , limit , offset )
	return
}
