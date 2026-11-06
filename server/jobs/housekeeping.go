package jobs

import (
	errors "errors"
	fmt "fmt"
	filepath "path/filepath"
	time "time"

	backup "ipb/server/backup"
	config "ipb/server/config"
	db "ipb/server/db"
	logs "ipb/server/logs"
	models "ipb/server/models"
)

const housekeepingInterval = time.Hour

// Housekeeping registers the jobs every app has. prune-logs is left out when
// the activity log is off: logs.enabled needs a restart, so it cannot appear
// later.
func Housekeeping( registry *Registry , store *db.Store , logger *logs.Logger , settings *config.Holder ) {
	registry.Register( "purge" , housekeepingInterval , purge( store ) )
	if logger.Enabled() {
		registry.Register( "prune-logs" , housekeepingInterval , pruneLogs( logger ) )
	}
	registry.Register( "backup" , housekeepingInterval , scheduledBackup( store , logger , settings ) )
	registry.Register( "files" , housekeepingInterval , sweepFiles( store , settings ) )
}

// purge drops expired sessions, login links and sign-in challenges, the API
// keys and invite links that have been dead long enough to stop being worth
// listing, and old webhook rows. None of it is a correctness issue -- every one of those is
// already refused on read -- so this only stops the bolt file growing forever.
// Every step runs whatever happens to the one before it.
func purge( store *db.Store ) ( run Func ) {
	run = func() ( note string , err error ) {
		sessions , sessions_err := models.PurgeExpiredSessions( store )
		tokens , tokens_err := models.PurgeExpiredLoginTokens( store )
		keys , keys_err := models.PurgeDeadAPIKeys( store )
		invites , invites_err := models.PurgeDeadInviteLinks( store )
		challenges , challenges_err := models.PurgeExpiredChallenges( store )
		webhooks , webhooks_err := models.PurgeWebhooks( store )
		note = fmt.Sprintf( "removed %d sessions, %d login links, %d keys, %d invite links, %d challenges, %d webhook rows" , sessions , tokens , keys , invites , challenges , webhooks )
		err = errors.Join( sessions_err , tokens_err , keys_err , invites_err , challenges_err , webhooks_err )
		return
	}
	return
}

// pruneLogs is the activity log's retention: compress, expire, recycle.
func pruneLogs( logger *logs.Logger ) ( run Func ) {
	run = func() ( note string , err error ) {
		pruned , err := logger.Prune()
		if err != nil { return }
		note = fmt.Sprintf( "%d days deleted, %d compressed" , pruned.Deleted , pruned.Compressed )
		if pruned.Deleted > 0 || pruned.Compressed > 0 {
			logger.System( logs.LevelInfo , "logs pruned" , map[string]any{ "deleted": pruned.Deleted , "compressed": pruned.Compressed } )
		}
		return
	}
	return
}

// scheduledBackup checks hourly; backups.interval_hours decides whether a
// check makes one. The settings are read on every run, so switching backups on
// needs no restart.
func scheduledBackup( store *db.Store , logger *logs.Logger , settings *config.Holder ) ( run Func ) {
	run = func() ( note string , err error ) {
		cfg := settings.Get()
		if cfg.Backups.Enabled == false {
			note = "off"
			return
		}
		made , removed , err := backup.RunScheduled( store , cfg )
		if made == nil {
			if err == nil {
				note = "not due"
			}
			return
		}
		note = fmt.Sprintf( "wrote %s, removed %d old" , filepath.Base( made.Path ) , removed )
		logger.System( logs.LevelInfo , "scheduled backup written" , map[string]any{ "path": made.Path , "bytes": made.Bytes , "removed": removed } )
		return
	}
	return
}
