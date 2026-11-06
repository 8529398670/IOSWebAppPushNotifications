package models

import (
	errors "errors"
	sort "sort"
	strings "strings"
	time "time"

	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

const PushGroupNameMax = 60

var (
	ErrPushGroupName = errors.New( "a group needs a name of up to 60 characters" )
	ErrPushGroupGone = errors.New( "no such group" )
)

// PushGroup is a set of people one key reaches. Whoever makes it picks the
// members, and any member can leave.
type PushGroup struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	OwnerID   uint64    `json:"owner_id"`
	Key       string    `json:"key"`
	Members   []uint64  `json:"members"`
	CreatedAt time.Time `json:"created_at"`
	SoftDelete
}

func ( group *PushGroup ) HasMember( user_id uint64 ) ( result bool ) {
	for _ , member := range group.Members {
		if member == user_id {
			result = true
			return
		}
	}
	return
}

func ( group *PushGroup ) removeMember( user_id uint64 ) {
	kept := []uint64{}
	for _ , member := range group.Members {
		if member != user_id { kept = append( kept , member ) }
	}
	group.Members = kept
}

func cleanGroupName( name string ) ( result string , err error ) {
	result = strings.TrimSpace( name )
	if result == "" || len( []rune( result ) ) > PushGroupNameMax {
		err = ErrPushGroupName
	}
	return
}

// realMembersTx keeps only accounts that exist, once each.
func realMembersTx( tx *db.Tx , requested []uint64 ) ( members []uint64 , err error ) {
	members = []uint64{}
	seen := map[uint64]bool{}
	for _ , user_id := range requested {
		if seen[ user_id ] { continue }
		seen[ user_id ] = true
		get_err := tx.Get( db.BucketUsers , encryption.Uint64ToBytes( user_id ) , &User{} )
		if errors.Is( get_err , db.ErrNotFound ) { continue }
		if get_err != nil {
			err = get_err
			return
		}
		members = append( members , user_id )
	}
	return
}

// CreatePushGroup makes a group and its key.
func CreatePushGroup( store *db.Store , owner_id uint64 , name string , members []uint64 ) ( group *PushGroup , err error ) {
	clean , err := cleanGroupName( name )
	if err != nil { return }
	created := &PushGroup{
		ID:        encryption.GenerateURLToken( 9 ),
		Name:      clean,
		OwnerID:   owner_id,
		Key:       newRecipientKey( "g" ),
		CreatedAt: time.Now().UTC(),
	}
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		if created.Members , tx_err = realMembersTx( tx , members ); tx_err != nil { return }
		if tx_err = tx.Put( db.BucketRecipientKeys , []byte( created.Key ) , &RecipientKey{ Kind: RecipientGroup , GroupID: created.ID } ); tx_err != nil { return }
		tx_err = tx.Put( db.BucketPushGroups , []byte( created.ID ) , created )
		return
	} )
	if err != nil { return }
	group = created
	return
}

// GetPushGroup loads a live group; ErrPushGroupGone when there is none.
func GetPushGroup( store *db.Store , group_id string ) ( group *PushGroup , err error ) {
	found := &PushGroup{}
	err = store.Get( db.BucketPushGroups , []byte( group_id ) , found )
	if errors.Is( err , db.ErrNotFound ) || ( err == nil && found.Deleted() ) {
		err = ErrPushGroupGone
		return
	}
	if err != nil { return }
	group = found
	return
}

// ListPushGroups is every live group, by name.
func ListPushGroups( store *db.Store ) ( groups []*PushGroup , err error ) {
	groups = []*PushGroup{}
	err = store.ForEach( db.BucketPushGroups ,
		func() any { return &PushGroup{} } ,
		func( _ []byte , item any ) bool {
			group := item.( *PushGroup )
			if group.Deleted() == false { groups = append( groups , group ) }
			return true
		} )
	sort.Slice( groups , func( a int , b int ) bool {
		return strings.ToLower( groups[ a ].Name ) < strings.ToLower( groups[ b ].Name )
	} )
	return
}

func updatePushGroupTx( tx *db.Tx , group_id string , mutate func( group *PushGroup ) error ) ( err error ) {
	group := &PushGroup{}
	err = tx.Get( db.BucketPushGroups , []byte( group_id ) , group )
	if errors.Is( err , db.ErrNotFound ) { err = ErrPushGroupGone }
	if err != nil { return }
	if err = mutate( group ); err != nil { return }
	err = tx.Put( db.BucketPushGroups , []byte( group_id ) , group )
	return
}

func liveGroup( group *PushGroup ) ( err error ) {
	if group.Deleted() { err = ErrPushGroupGone }
	return
}

// UpdatePushGroup sets the name and the members together.
func UpdatePushGroup( store *db.Store , group_id string , name string , members []uint64 ) ( err error ) {
	clean , err := cleanGroupName( name )
	if err != nil { return }
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		real , tx_err := realMembersTx( tx , members )
		if tx_err != nil { return }
		tx_err = updatePushGroupTx( tx , group_id , func( group *PushGroup ) ( mutate_err error ) {
			if mutate_err = liveGroup( group ); mutate_err != nil { return }
			group.Name = clean
			group.Members = real
			return
		} )
		return
	} )
	return
}

// LeavePushGroup takes one person out, on their own say-so.
func LeavePushGroup( store *db.Store , group_id string , user_id uint64 ) ( err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		tx_err = updatePushGroupTx( tx , group_id , func( group *PushGroup ) ( mutate_err error ) {
			if mutate_err = liveGroup( group ); mutate_err != nil { return }
			group.removeMember( user_id )
			return
		} )
		return
	} )
	return
}

// RotatePushGroupKey ends the old key at once.
func RotatePushGroupKey( store *db.Store , group_id string ) ( key string , err error ) {
	fresh := newRecipientKey( "g" )
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		old := ""
		tx_err = updatePushGroupTx( tx , group_id , func( group *PushGroup ) ( mutate_err error ) {
			if mutate_err = liveGroup( group ); mutate_err != nil { return }
			old = group.Key
			group.Key = fresh
			return
		} )
		if tx_err != nil { return }
		if tx_err = tx.Delete( db.BucketRecipientKeys , []byte( old ) ); tx_err != nil { return }
		tx_err = tx.Put( db.BucketRecipientKeys , []byte( fresh ) , &RecipientKey{ Kind: RecipientGroup , GroupID: group_id } )
		return
	} )
	if err != nil { return }
	key = fresh
	return
}

// DeletePushGroup stops the key reaching anyone. ResolveRecipient refuses a
// deleted group, so a restore only has to take the mark off.
func DeletePushGroup( store *db.Store , group_id string , actor_id uint64 ) ( err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		tx_err = updatePushGroupTx( tx , group_id , func( group *PushGroup ) ( mutate_err error ) {
			group.markDeleted( actor_id )
			return
		} )
		return
	} )
	return
}

func RestorePushGroup( store *db.Store , group_id string , actor_id uint64 , actor_is_admin bool ) ( err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		tx_err = updatePushGroupTx( tx , group_id , func( group *PushGroup ) ( mutate_err error ) {
			mutate_err = group.unmarkDeleted( actor_id , actor_is_admin )
			return
		} )
		return
	} )
	return
}

// PurgeDeadPushGroups removes groups past their undo window, and their keys.
func PurgeDeadPushGroups( store *db.Store ) ( removed int , err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		keys := []string{}
		removed , tx_err = tx.DeleteWhere( db.BucketPushGroups ,
			func() any { return &PushGroup{} } ,
			func( _ []byte , item any ) ( match bool ) {
				group := item.( *PushGroup )
				match = group.deletedLongAgo()
				if match { keys = append( keys , group.Key ) }
				return
			} )
		if tx_err != nil { return }
		for _ , key := range keys {
			if tx_err = tx.Delete( db.BucketRecipientKeys , []byte( key ) ); tx_err != nil { return }
		}
		return
	} )
	return
}
