package models

import (
	errors "errors"
	time "time"
)

// RestoreWindow is how long a deleted API key or invite link can still be
// put back. Delete is the undoable one of the two ways to switch something
// off (revoke is final), and this is the length of that undo: long enough
// for the toast's Undo and a Ctrl+Z a few minutes later, short enough that
// "deleted" soon means gone. The row is dead the moment it is deleted; the
// window only decides how long the purge leaves it lying there.
const RestoreWindow = 10 * time.Minute

var (
	ErrRestoreGone      = errors.New( "it is not there to restore" )
	ErrRestoreForbidden = errors.New( "only whoever deleted it, or an admin, can put it back" )
	ErrRestoreExpired   = errors.New( "it was deleted too long ago to put back" )
)

// SoftDelete is embedded in the records that delete marks rather than
// removes (APIKey, InviteLink). encoding/json flattens it, so the fields sit
// in the record like any other.
type SoftDelete struct {
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
	// DeletedBy is the user who deleted it: the one, besides an admin, who
	// may restore it.
	DeletedBy uint64 `json:"deleted_by,omitempty"`
}

func ( mark *SoftDelete ) Deleted() ( result bool ) {
	result = mark.DeletedAt != nil
	return
}

// markDeleted is the delete itself, for UpdateValue. Deleting twice keeps
// the first mark, like revoking; marked is false when it was already
// deleted.
func ( mark *SoftDelete ) markDeleted( actor_id uint64 ) ( marked bool ) {
	if mark.DeletedAt != nil { return }
	now := time.Now().UTC()
	mark.DeletedAt = &now
	mark.DeletedBy = actor_id
	marked = true
	return
}

// unmarkDeleted is the restore, for UpdateValue: an error here aborts the
// write.
func ( mark *SoftDelete ) unmarkDeleted( actor_id uint64 , actor_is_admin bool ) ( err error ) {
	switch {
	case mark.DeletedAt == nil:
		err = ErrRestoreGone
	case actor_is_admin == false && mark.DeletedBy != actor_id:
		err = ErrRestoreForbidden
	case time.Since( *mark.DeletedAt ) > RestoreWindow:
		err = ErrRestoreExpired
	default:
		mark.DeletedAt = nil
		mark.DeletedBy = 0
	}
	return
}

// deletedLongAgo is for the purges: a deletion past its undo window.
func ( mark *SoftDelete ) deletedLongAgo() ( result bool ) {
	result = mark.DeletedAt != nil && time.Since( *mark.DeletedAt ) > RestoreWindow
	return
}
