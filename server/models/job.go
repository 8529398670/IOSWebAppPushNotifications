package models

import (
	errors "errors"
	time "time"

	db "ipb/server/db"
)

// JobRecord is what a background job remembers between runs. It is kept in
// the database rather than in memory so that a restart does not make every
// job due again, and so the owner can still see how the last run went.
//
// LastStarted is written before the job runs: a job that takes the whole
// process down with it has then still used up its turn, and cannot crash the
// server again on every boot.
type JobRecord struct {
	Name         string     `json:"name"`
	Runs         int        `json:"runs"`
	LastStarted  *time.Time `json:"last_started,omitempty"`
	LastFinished *time.Time `json:"last_finished,omitempty"`
	LastOK       *bool      `json:"last_ok,omitempty"`
	LastNote     string     `json:"last_note,omitempty"`
	LastError    string     `json:"last_error,omitempty"`
	LastSuccess  *time.Time `json:"last_success,omitempty"`
	LastFailure  *time.Time `json:"last_failure,omitempty"`
}

// LoadJobRecord returns what is remembered about a job, or an empty record for
// one that has never run.
func LoadJobRecord( store *db.Store , name string ) ( record *JobRecord , err error ) {
	record = &JobRecord{}
	err = store.Get( db.BucketJobs , []byte( name ) , record )
	if errors.Is( err , db.ErrNotFound ) {
		err = nil
	}
	record.Name = name
	return
}

func SaveJobRecord( store *db.Store , record *JobRecord ) ( err error ) {
	err = store.Put( db.BucketJobs , []byte( record.Name ) , record )
	return
}
