package routes

import (
	bytes "bytes"
	json "encoding/json"
	errors "errors"

	fiber "github.com/gofiber/fiber/v3"

	config "ipb/server/config"
	logs "ipb/server/logs"
)

// The owner's Settings screen: config.yaml, one field per key (see
// static/js/settings.js). Both routes are the owner's alone, from a browser
// session (Guard.RequireOwner), like the activity log.
//
// What is shown and saved comes from config.Holder, which owns the file:
// GetSettings is Holder.Snapshot, SaveSettings is Holder.Save. The secret key
// is never part of either -- it is not in config.yaml, and the screen only
// says where secret.key is.

func ( handlers *Handlers ) GetSettings( c fiber.Ctx ) ( err error ) {
	snapshot , snapshot_err := handlers.Settings.Snapshot()
	if snapshot_err != nil {
		err = serverError( c , snapshot_err )
		return
	}
	err = c.JSON( snapshot )
	return
}

type saveSettingsRequest struct {
	CSRFToken string         `json:"csrf_token"`
	Version   string         `json:"version"`
	Changes   map[string]any `json:"changes"`
}

// SaveSettings applies {version, changes: {"section.key": value}}. version
// is the one GetSettings returned; a file changed since is a 409 with the
// current version, so the page can offer to reload rather than overwrite.
func ( handlers *Handlers ) SaveSettings( c fiber.Ctx ) ( err error ) {
	var body saveSettingsRequest
	// UseNumber, so an int arrives as an int: a float64 would let 1.5 through
	// as 1.
	decoder := json.NewDecoder( bytes.NewReader( c.Body() ) )
	decoder.UseNumber()
	if decoder.Decode( &body ) != nil || body.Changes == nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}

	result , save_err := handlers.Settings.Save( body.Version , body.Changes )
	var changed *config.ConflictError
	var validation *config.ValidationError
	var unknown *config.UnknownSettingError
	switch {
	case errors.As( save_err , &changed ):
		err = conflict( c , "settings_changed" , fiber.Map{ "version": changed.Version } )
	case errors.Is( save_err , config.ErrStale ):
		err = conflict( c , "settings_stale" , nil )
	case errors.Is( save_err , config.ErrReadOnly ):
		err = conflict( c , "settings_read_only" , nil )
	case errors.Is( save_err , config.ErrLocked ):
		err = forbidden( c , "settings_locked" )
	case errors.As( save_err , &validation ):
		err = c.Status( fiber.StatusBadRequest ).JSON( fiber.Map{ "error": "invalid_settings" , "problems": validation.Problems } )
	case errors.As( save_err , &unknown ):
		err = c.Status( fiber.StatusBadRequest ).JSON( fiber.Map{ "error": "unknown_setting" , "key": unknown.Key } )
	case errors.Is( save_err , config.ErrHandEdit ):
		err = c.Status( fiber.StatusBadRequest ).JSON( fiber.Map{ "error": "settings_hand_edit" , "problems": []string{ save_err.Error() } } )
	case save_err != nil:
		err = save_err
	default:
		if len( result.Changes ) > 0 {
			handlers.audit( c , logs.KindAdmin , "settings changed" , fiber.Map{
				"changes": result.Changes,
				"restart": result.Restart,
				"scripts": result.Scripts,
			} )
		}
		err = c.JSON( result )
	}
	return
}
