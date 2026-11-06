package routes

import (
	fiber "github.com/gofiber/fiber/v3"

	models "ipb/server/models"
)

// ListTeam exists so that ordinary features -- an assignee dropdown, an owner
// picker, an @mention list -- do not need admin rights just to render a list
// of names. It returns id and display name only; role and disabled status
// stay behind the admin endpoint, because those are facts about who
// administers the app rather than about who you can hand work to.
func ( handlers *Handlers ) ListTeam( c fiber.Ctx ) ( err error ) {
	members , list_err := handlers.teamRows()
	if list_err != nil {
		err = serverError( c , list_err )
		return
	}
	err = sendPage( c , "members" , members )
	return
}

// teamRows is shared with the MCP list_team tool.
func ( handlers *Handlers ) teamRows() ( members []fiber.Map , err error ) {
	users , err := models.ListUsers( handlers.Store )
	if err != nil { return }

	members = []fiber.Map{}
	for _ , user := range users {
		if user.Disabled() { continue }
		members = append( members , fiber.Map{ "id": user.ID , "display_name": user.DisplayName } )
	}
	return
}
