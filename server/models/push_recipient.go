package models

import (
	errors "errors"

	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

// keyLength matches Pushover's 30 character keys, which some tools check for.
const keyLength = 30

const (
	RecipientUser  = "user"
	RecipientGroup = "group"
)

var ErrRecipient = errors.New( "that user value is not a key iPB knows: copy a user key from Notifications, or a group key from Groups" )

// RecipientKey is one row of the index that lets a send's `user` field name a
// person or a group with one lookup. A key says who a message is for and
// nothing more: sending also needs an app token, so a key is shown on screen
// rather than hashed away, and can be handed to whoever writes the script.
type RecipientKey struct {
	Kind    string `json:"kind"`
	UserID  uint64 `json:"user_id,omitempty"`
	GroupID string `json:"group_id,omitempty"`
}

// PushPrefs is one person's notification settings.
type PushPrefs struct {
	UserID    uint64   `json:"user_id"`
	UserKey   string   `json:"user_key"`
	MutedApps []string `json:"muted_apps"`
}

func ( prefs *PushPrefs ) Muted( app_id string ) ( result bool ) {
	for _ , muted := range prefs.MutedApps {
		if muted == app_id {
			result = true
			return
		}
	}
	return
}

func newRecipientKey( prefix string ) ( key string ) {
	key = prefix + encryption.GenerateRandomString( keyLength - len( prefix ) )
	return
}

// prefsTx loads someone's settings inside a transaction, giving them a key the
// first time, so nobody has a settings row without one.
func prefsTx( tx *db.Tx , user_id uint64 ) ( prefs *PushPrefs , err error ) {
	found := &PushPrefs{}
	err = tx.Get( db.BucketPushPrefs , encryption.Uint64ToBytes( user_id ) , found )
	if err == nil {
		prefs = found
		return
	}
	if errors.Is( err , db.ErrNotFound ) == false { return }
	prefs = &PushPrefs{ UserID: user_id , UserKey: newRecipientKey( "u" ) , MutedApps: []string{} }
	if err = tx.Put( db.BucketRecipientKeys , []byte( prefs.UserKey ) , &RecipientKey{ Kind: RecipientUser , UserID: user_id } ); err != nil { return }
	err = tx.Put( db.BucketPushPrefs , encryption.Uint64ToBytes( user_id ) , prefs )
	return
}

// GetPushPrefs is someone's settings and user key.
func GetPushPrefs( store *db.Store , user_id uint64 ) ( prefs *PushPrefs , err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		prefs , tx_err = prefsTx( tx , user_id )
		return
	} )
	return
}

// RotateUserKey ends the old key at once. Scripts holding it stop reaching this
// person until they are given the new one.
func RotateUserKey( store *db.Store , user_id uint64 ) ( key string , err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		prefs , tx_err := prefsTx( tx , user_id )
		if tx_err != nil { return }
		if tx_err = tx.Delete( db.BucketRecipientKeys , []byte( prefs.UserKey ) ); tx_err != nil { return }
		prefs.UserKey = newRecipientKey( "u" )
		if tx_err = tx.Put( db.BucketRecipientKeys , []byte( prefs.UserKey ) , &RecipientKey{ Kind: RecipientUser , UserID: user_id } ); tx_err != nil { return }
		tx_err = tx.Put( db.BucketPushPrefs , encryption.Uint64ToBytes( user_id ) , prefs )
		key = prefs.UserKey
		return
	} )
	return
}

// SetAppMuted mutes or unmutes one app for one person. A muted app's messages
// still reach the inbox; only the push is skipped.
func SetAppMuted( store *db.Store , user_id uint64 , app_id string , muted bool ) ( err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		prefs , tx_err := prefsTx( tx , user_id )
		if tx_err != nil { return }
		kept := []string{}
		for _ , existing := range prefs.MutedApps {
			if existing != app_id { kept = append( kept , existing ) }
		}
		if muted { kept = append( kept , app_id ) }
		prefs.MutedApps = kept
		tx_err = tx.Put( db.BucketPushPrefs , encryption.Uint64ToBytes( user_id ) , prefs )
		return
	} )
	return
}

// ResolveRecipient turns a send's `user` field into the people it reaches.
func ResolveRecipient( store *db.Store , key string ) ( user_ids []uint64 , err error ) {
	found := &RecipientKey{}
	if get_err := store.Get( db.BucketRecipientKeys , []byte( key ) , found ); get_err != nil {
		err = ErrRecipient
		if errors.Is( get_err , db.ErrNotFound ) == false { err = get_err }
		return
	}
	if found.Kind == RecipientUser {
		user_ids = []uint64{ found.UserID }
		return
	}
	group , group_err := GetPushGroup( store , found.GroupID )
	if group_err != nil {
		err = ErrRecipient
		return
	}
	user_ids = group.Members
	return
}

// deletePushRecordsForUserTx takes everything notifications hold about a person
// with their account, in the same transaction.
func deletePushRecordsForUserTx( tx *db.Tx , user_id uint64 ) ( err error ) {
	if err = deletePushSubscriptionsTx( tx , user_id ); err != nil { return }

	prefs := &PushPrefs{}
	get_err := tx.Get( db.BucketPushPrefs , encryption.Uint64ToBytes( user_id ) , prefs )
	if get_err == nil {
		if err = tx.Delete( db.BucketRecipientKeys , []byte( prefs.UserKey ) ); err != nil { return }
		if err = tx.Delete( db.BucketPushPrefs , encryption.Uint64ToBytes( user_id ) ); err != nil { return }
	} else if errors.Is( get_err , db.ErrNotFound ) == false {
		err = get_err
		return
	}

	if _ , err = tx.DeleteWhere( db.BucketInbox ,
		func() any { return &InboxItem{} } ,
		func( _ []byte , item any ) bool { return item.( *InboxItem ).UserID == user_id } ); err != nil { return }
	if _ , err = tx.DeleteWhere( db.BucketPushRepeats ,
		func() any { return &PushRepeat{} } ,
		func( _ []byte , item any ) bool { return item.( *PushRepeat ).UserID == user_id } ); err != nil { return }

	groups := []*PushGroup{}
	err = tx.ForEach( db.BucketPushGroups ,
		func() any { return &PushGroup{} } ,
		func( _ []byte , item any ) bool {
			group := item.( *PushGroup )
			if group.HasMember( user_id ) { groups = append( groups , group ) }
			return true
		} )
	if err != nil { return }
	for _ , group := range groups {
		group.removeMember( user_id )
		if err = tx.Put( db.BucketPushGroups , []byte( group.ID ) , group ); err != nil { return }
	}
	return
}
