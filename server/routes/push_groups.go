package routes

import (
	errors "errors"
	strings "strings"

	fiber "github.com/gofiber/fiber/v3"

	logs "ipb/server/logs"
	models "ipb/server/models"
	security "ipb/server/security"
)

func canManageGroup( group *models.PushGroup , actor *security.Actor ) ( result bool ) {
	result = group.OwnerID == actor.User.ID || actor.IsAdmin()
	return
}

func groupRow( group *models.PushGroup , actor *security.Actor , names map[uint64]string ) ( row fiber.Map ) {
	members := []fiber.Map{}
	for _ , member := range group.Members {
		members = append( members , fiber.Map{ "id": member , "display_name": names[ member ] } )
	}
	row = fiber.Map{
		"id":         group.ID,
		"name":       group.Name,
		"key":        group.Key,
		"owner_name": names[ group.OwnerID ],
		"members":    members,
		"is_member":  group.HasMember( actor.User.ID ),
		"can_manage": canManageGroup( group , actor ),
	}
	return
}

// ListGroups is the groups this person made or is in; an admin sees them all.
func ( handlers *Handlers ) ListGroups( c fiber.Ctx ) ( err error ) {
	actor := security.ActorFrom( c )
	groups , list_err := models.ListPushGroups( handlers.Store )
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	names , names_err := handlers.userNames()
	if names_err != nil {
		err = serverError( c , names_err )
		return
	}
	rows := []fiber.Map{}
	for _ , group := range groups {
		if canManageGroup( group , actor ) || group.HasMember( actor.User.ID ) {
			rows = append( rows , groupRow( group , actor , names ) )
		}
	}
	err = sendPage( c , "groups" , rows )
	return
}

type groupRequest struct {
	Name      string   `json:"name"`
	Members   []uint64 `json:"members"`
	CSRFToken string   `json:"csrf_token"`
}

func ( handlers *Handlers ) CreateGroup( c fiber.Ctx ) ( err error ) {
	var body groupRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	group , create_err := models.CreatePushGroup( handlers.Store , security.UserFrom( c ).ID , body.Name , body.Members )
	if errors.Is( create_err , models.ErrPushGroupName ) {
		err = badRequest( c , create_err.Error() )
		return
	}
	if create_err != nil {
		err = serverError( c , create_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "group created" , fiber.Map{ "group_id": group.ID , "name": group.Name } )
	err = c.JSON( fiber.Map{ "id": group.ID , "key": group.Key } )
	return
}

// managedGroup loads the group in the URL for someone allowed to change it.
func ( handlers *Handlers ) managedGroup( c fiber.Ctx ) ( group *models.PushGroup , err error ) {
	found , get_err := models.GetPushGroup( handlers.Store , strings.Clone( c.Params( "group_id" ) ) )
	if errors.Is( get_err , models.ErrPushGroupGone ) {
		err = notFound( c , "no such group" )
		return
	}
	if get_err != nil {
		err = serverError( c , get_err )
		return
	}
	if canManageGroup( found , security.ActorFrom( c ) ) == false {
		err = notFound( c , "no such group" )
		return
	}
	group = found
	return
}

func ( handlers *Handlers ) UpdateGroup( c fiber.Ctx ) ( err error ) {
	var body groupRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	group , err := handlers.managedGroup( c )
	if group == nil { return }
	update_err := models.UpdatePushGroup( handlers.Store , group.ID , body.Name , body.Members )
	if errors.Is( update_err , models.ErrPushGroupName ) {
		err = badRequest( c , update_err.Error() )
		return
	}
	if update_err != nil {
		err = serverError( c , update_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "group changed" , fiber.Map{ "group_id": group.ID } )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

// LeaveGroup needs no say-so from whoever made the group.
func ( handlers *Handlers ) LeaveGroup( c fiber.Ctx ) ( err error ) {
	ok , err := handlers.checkedCSRF( c )
	if ok == false { return }
	leave_err := models.LeavePushGroup( handlers.Store , strings.Clone( c.Params( "group_id" ) ) , security.UserFrom( c ).ID )
	if errors.Is( leave_err , models.ErrPushGroupGone ) {
		err = notFound( c , "no such group" )
		return
	}
	if leave_err != nil {
		err = serverError( c , leave_err )
		return
	}
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

func ( handlers *Handlers ) RotateGroupKey( c fiber.Ctx ) ( err error ) {
	ok , err := handlers.checkedCSRF( c )
	if ok == false { return }
	group , err := handlers.managedGroup( c )
	if group == nil { return }
	key , rotate_err := models.RotatePushGroupKey( handlers.Store , group.ID )
	if rotate_err != nil {
		err = serverError( c , rotate_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "group key rotated" , fiber.Map{ "group_id": group.ID } )
	err = c.JSON( fiber.Map{ "key": key } )
	return
}

func ( handlers *Handlers ) DeleteGroup( c fiber.Ctx ) ( err error ) {
	ok , err := handlers.checkedCSRF( c )
	if ok == false { return }
	group , err := handlers.managedGroup( c )
	if group == nil { return }
	if delete_err := models.DeletePushGroup( handlers.Store , group.ID , security.UserFrom( c ).ID ); delete_err != nil {
		err = serverError( c , delete_err )
		return
	}
	handlers.audit( c , logs.KindAdmin , "group deleted" , fiber.Map{ "group_id": group.ID } )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

func ( handlers *Handlers ) RestoreGroup( c fiber.Ctx ) ( err error ) {
	ok , err := handlers.checkedCSRF( c )
	if ok == false { return }
	actor := security.ActorFrom( c )
	restore_err := models.RestorePushGroup( handlers.Store , strings.Clone( c.Params( "group_id" ) ) , actor.User.ID , actor.IsAdmin() )
	if restore_err != nil {
		err = restoreRefused( c , restore_err )
		return
	}
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}
