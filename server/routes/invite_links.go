package routes

import (
	errors "errors"
	strings "strings"
	time "time"


	fiber "github.com/gofiber/fiber/v3"

	db "ipb/server/db"
	logs "ipb/server/logs"
	models "ipb/server/models"
	security "ipb/server/security"
)

// Managing invite links (see models/invite_link.go; joining through one is
// join.go). Admin only, registered under /api/admin. The link's credential is
// returned once, on creation, as a path -- the browser adds its own origin,
// like a login link.

// inviteLinksOn is auth.invite_links, read per request since it can change
// while the server runs.
func ( handlers *Handlers ) inviteLinksOn() ( result bool ) {
	result = handlers.cfg().InviteLinksEnabled
	return
}

// RequireInviteLinks makes every invite route answer 404 while
// auth.invite_links is off. The /join page does its own check, so a person
// gets the styled page rather than this JSON. See ShowJoinPage.
func ( handlers *Handlers ) RequireInviteLinks( c fiber.Ctx ) ( err error ) {
	if handlers.inviteLinksOn() == false {
		err = notFound( c , "not found" )
		return
	}
	err = c.Next()
	return
}

type inviteLinkRequest struct {
	Label     string `json:"label"`
	MaxUses   int    `json:"max_uses"`
	Days      int    `json:"days"`
	CSRFToken string `json:"csrf_token"`
}

// renameInviteRequest's Expect is the label the caller thinks it is replacing, so
// an undo cannot overwrite a rename made elsewhere.
type renameInviteRequest struct {
	Label     string  `json:"label"`
	Expect    *string `json:"expect"`
	CSRFToken string  `json:"csrf_token"`
}

// inviteLimitsRequest's Days is a pointer because leaving it out means "keep the
// expiry", which is not the same as any number of days.
type inviteLimitsRequest struct {
	MaxUses   int    `json:"max_uses"`
	Days      *int   `json:"days"`
	CSRFToken string `json:"csrf_token"`
}

func ( handlers *Handlers ) inviteLinkRow( link *models.InviteLink ) ( row fiber.Map ) {
	row = fiber.Map{
		"id":         link.ID,
		"label":      link.Label,
		"max_uses":   link.MaxUses,
		"used":       len( link.Accounts ),
		"remaining":  link.Remaining(),
		"live":       link.Live(),
		"expires_at": link.ExpiresAt,
		"revoked":    link.RevokedAt != nil,
		"created_by": link.CreatedBy,
	}
	// A link outlives its maker's admin rights only on paper: it stops
	// working the moment they lose them (see models.LoadInviteLink).
	if creator , get_err := models.GetUser( handlers.Store , link.CreatedBy ); get_err == nil {
		row[ "created_by_name" ] = creator.DisplayName
		if creator.Disabled() || creator.IsAdmin() == false { row[ "live" ] = false }
	} else {
		row[ "live" ] = false
	}
	return
}

func ( handlers *Handlers ) ListInviteLinks( c fiber.Ctx ) ( err error ) {
	rows , list_err := handlers.inviteLinkRows()
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	err = sendPage( c , "invite_links" , rows )
	return
}

// inviteLinkRows is shared with the MCP admin_list_invite_links tool.
func ( handlers *Handlers ) inviteLinkRows() ( rows []fiber.Map , err error ) {
	links , err := models.ListInviteLinks( handlers.Store )
	if err != nil { return }
	rows = []fiber.Map{}
	for _ , link := range links {
		rows = append( rows , handlers.inviteLinkRow( link ) )
	}
	return
}

func ( handlers *Handlers ) CreateInviteLink( c fiber.Ctx ) ( err error ) {
	var body inviteLinkRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	if models.ValidInviteLink( body.Label , body.MaxUses , body.Days ) == false {
		err = badRequest( c , "label must be 1-80 characters, uses 1-1000, days 1-365" )
		return
	}
	ttl := time.Duration( body.Days ) * 24 * time.Hour
	credential , link , issue_err := models.IssueInviteLink( handlers.Store , body.Label , body.MaxUses , ttl , security.UserFrom( c ).ID )
	if issue_err != nil {
		err = serverError( c , issue_err )
		return
	}
	row := handlers.inviteLinkRow( link )
	row[ "join_path" ] = "/join/" + credential
	handlers.audit( c , logs.KindAdmin , "invite link created" , fiber.Map{ "link_id": link.ID , "label": link.Label , "max_uses": link.MaxUses } )
	handlers.Webhooks.Emit( models.EventInviteLinkCreated , map[string]any{ "link_id": link.ID , "label": link.Label } )
	err = c.Status( fiber.StatusCreated ).JSON( row )
	return
}

// RevokeInviteLink switches a link off. The accounts it made keep working.
// RenameInviteLink changes a link's label.
func ( handlers *Handlers ) RenameInviteLink( c fiber.Ctx ) ( err error ) {
	var body renameInviteRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	if models.ValidInviteLabel( body.Label ) == false {
		err = badRequest( c , "label must be 1-80 characters" )
		return
	}
	// Clone: the log entry outlives this request, and fiber reuses the buffer.
	link_id := strings.Clone( c.Params( "link_id" ) )
	rename_err := models.RenameInviteLink( handlers.Store , link_id , body.Label , body.Expect )
	var refusal *models.RenameConflictError
	switch {
	case errors.As( rename_err , &refusal ):
		err = conflict( c , refusal.Error() , fiber.Map{ "label": refusal.Current } )
		return
	case errors.Is( rename_err , db.ErrNotFound ):
		err = notFound( c , "no such invite link" )
		return
	case rename_err != nil:
		err = serverError( c , rename_err )
		return
	}
	label := strings.TrimSpace( body.Label )
	handlers.audit( c , logs.KindAdmin , "invite link renamed" , fiber.Map{ "link_id": link_id , "label": label } )
	err = c.JSON( fiber.Map{ "ok": true , "label": label } )
	return
}

// SetInviteLinkLimits changes a link's places, and its expiry when days is given.
// It needs a session, like making a link: more places is more accounts, so a
// leaked admin key must not be a way to add them.
func ( handlers *Handlers ) SetInviteLinkLimits( c fiber.Ctx ) ( err error ) {
	var body inviteLimitsRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	if models.ValidInviteLimits( body.MaxUses , body.Days ) == false {
		err = badRequest( c , "uses must be 1-1000 and days 1-365" )
		return
	}
	var ttl time.Duration
	if body.Days != nil { ttl = time.Duration( *body.Days ) * 24 * time.Hour }
	link , set_err := models.SetInviteLinkLimits( handlers.Store , c.Params( "link_id" ) , body.MaxUses , ttl )
	switch {
	case errors.Is( set_err , db.ErrNotFound ):
		err = notFound( c , "no such invite link" )
		return
	case errors.Is( set_err , models.ErrInvitePlaces ):
		err = badRequest( c , set_err.Error() )
		return
	case set_err != nil:
		err = serverError( c , set_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "invite link limits changed" , fiber.Map{ "link_id": link.ID , "max_uses": link.MaxUses , "expires_at": link.ExpiresAt } )
	err = c.JSON( handlers.inviteLinkRow( link ) )
	return
}

// SwitchOnInviteLink undoes RevokeInviteLink. Switching off is safe for an admin
// key; this needs a session, or a leaked key could reopen a closed link.
func ( handlers *Handlers ) SwitchOnInviteLink( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	link , switch_err := models.SwitchOnInviteLink( handlers.Store , c.Params( "link_id" ) )
	if errors.Is( switch_err , db.ErrNotFound ) {
		err = notFound( c , "no such invite link" )
		return
	}
	if switch_err != nil {
		err = serverError( c , switch_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "invite link switched back on" , fiber.Map{ "link_id": link.ID } )
	err = c.JSON( handlers.inviteLinkRow( link ) )
	return
}

func ( handlers *Handlers ) RevokeInviteLink( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	if models.RevokeInviteLink( handlers.Store , c.Params( "link_id" ) ) != nil {
		err = notFound( c , "no such invite link" )
		return
	}
	handlers.audit( c , logs.KindAdmin , "invite link revoked" , fiber.Map{ "link_id": c.Params( "link_id" ) } )
	handlers.Webhooks.Emit( models.EventInviteLinkRevoked , map[string]any{ "link_id": c.Params( "link_id" ) } )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

// DeleteInviteLink drops a link from the list. The accounts it made stay;
// they just can no longer sign in on a new device through it.
// RestoreInviteLink undoes it for a few minutes.
func ( handlers *Handlers ) DeleteInviteLink( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	if models.DeleteInviteLink( handlers.Store , c.Params( "link_id" ) , security.UserFrom( c ).ID ) != nil {
		err = notFound( c , "no such invite link" )
		return
	}
	handlers.audit( c , logs.KindAdmin , "invite link deleted" , fiber.Map{ "link_id": c.Params( "link_id" ) } )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

// RestoreInviteLink undoes DeleteInviteLink, within models.RestoreWindow. The
// link works again exactly as before, uses and expiry included.
func ( handlers *Handlers ) RestoreInviteLink( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	actor := security.UserFrom( c )
	link , restore_err := models.RestoreInviteLink( handlers.Store , c.Params( "link_id" ) , actor.ID , actor.IsAdmin() )
	if restore_err != nil {
		err = restoreRefused( c , restore_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "invite link restored" , fiber.Map{ "link_id": c.Params( "link_id" ) } )
	err = c.JSON( handlers.inviteLinkRow( link ) )
	return
}
