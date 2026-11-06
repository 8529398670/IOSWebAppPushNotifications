package models

import (
	errors "errors"
	testing "testing"
	time "time"

	db "ipb/server/db"
)

// Deleting an API key or invite link is undoable for RestoreWindow (see
// soft_delete.go). What matters, and what these pin down: a deleted row is
// dead at once, only the right people can bring it back, only for a while,
// and the purge removes it once the window has passed.

// backdate moves a deletion to just past the restore window.
func backdate( t *testing.T , store *db.Store , bucket string , id string , item any ) {
	t.Helper()
	err := store.UpdateValue( bucket , []byte( id ) ,
		func() any { return item } ,
		func( value any ) ( mutate_err error ) {
			past := time.Now().UTC().Add( -RestoreWindow - time.Second )
			switch record := value.( type ) {
			case *APIKey:
				record.DeletedAt = &past
			case *InviteLink:
				record.DeletedAt = &past
			}
			return
		} )
	if err != nil { t.Fatal( err ) }
}

func TestAPIKeySoftDelete( t *testing.T ) {
	store := testStore( t )
	admin , _ := CreateUser( store , "Admin" , RoleAdmin )
	alice , _ := CreateUser( store , "Alice" , RoleUser )
	credential , key , err := IssueAPIKey( store , alice.ID , "ci" , RoleUser , 0 )
	if err != nil { t.Fatal( err ) }

	if err := DeleteAPIKey( store , key.ID , alice.ID ); err != nil { t.Fatal( err ) }
	if found , _ := LoadAPIKey( store , credential ); found != nil {
		t.Fatal( "a deleted key still authenticates" )
	}
	if keys , _ := ListAPIKeysForUser( store , alice.ID ); len( keys ) != 0 {
		t.Fatal( "a deleted key is still listed for its owner" )
	}
	if keys , _ := ListAPIKeys( store ); len( keys ) != 0 {
		t.Fatal( "a deleted key is still in the admin listing" )
	}
	if count , _ := CountLiveAPIKeysForUser( store , alice.ID ); count != 0 {
		t.Fatal( "a deleted key still counts as live" )
	}
	if err := DeleteAPIKey( store , key.ID , alice.ID ); !errors.Is( err , db.ErrNotFound ) {
		t.Fatalf( "deleting twice: got %v, want not found" , err )
	}

	if _ , err := RestoreAPIKey( store , key.ID , alice.ID , false ); err != nil { t.Fatal( err ) }
	if found , _ := LoadAPIKey( store , credential ); found == nil {
		t.Fatal( "a restored key does not authenticate" )
	}
	if _ , err := RestoreAPIKey( store , key.ID , alice.ID , false ); !errors.Is( err , ErrRestoreGone ) {
		t.Fatalf( "restoring a key that is not deleted: got %v" , err )
	}

	// An admin's delete is the admin's to undo, not the owner's.
	DeleteAPIKey( store , key.ID , admin.ID )
	if _ , err := RestoreAPIKey( store , key.ID , alice.ID , false ); !errors.Is( err , ErrRestoreForbidden ) {
		t.Fatalf( "owner restoring an admin's delete: got %v" , err )
	}
	if _ , err := RestoreAPIKey( store , key.ID , admin.ID , true ); err != nil { t.Fatal( err ) }

	// Past the window: refused, and the purge takes it.
	DeleteAPIKey( store , key.ID , alice.ID )
	backdate( t , store , db.BucketAPIKeys , key.ID , &APIKey{} )
	if _ , err := RestoreAPIKey( store , key.ID , alice.ID , false ); !errors.Is( err , ErrRestoreExpired ) {
		t.Fatalf( "restore after the window: got %v" , err )
	}
	_ , recent , _ := IssueAPIKey( store , alice.ID , "recent" , RoleUser , 0 )
	DeleteAPIKey( store , recent.ID , alice.ID )
	if removed , _ := PurgeDeadAPIKeys( store ); removed != 1 {
		t.Fatalf( "purge removed %d rows, want 1" , removed )
	}
	if _ , err := GetAPIKey( store , recent.ID ); err != nil {
		t.Fatal( "the purge removed a deletion still inside its window" )
	}
}

func TestAPIKeyRestoreKeepsTheCap( t *testing.T ) {
	store := testStore( t )
	alice , _ := CreateUser( store , "Alice" , RoleUser )
	_ , key , _ := IssueAPIKey( store , alice.ID , "first" , RoleUser , 0 )
	DeleteAPIKey( store , key.ID , alice.ID )
	for index := 0; index < APIKeyMaxPerUser; index += 1 {
		if _ , _ , err := IssueAPIKey( store , alice.ID , "k" , RoleUser , 0 ); err != nil { t.Fatal( err ) }
	}
	if _ , err := RestoreAPIKey( store , key.ID , alice.ID , false ); !errors.Is( err , ErrAPIKeyLimit ) {
		t.Fatalf( "restore over the cap: got %v" , err )
	}
}

func TestPurgeAPIKeyIsAHardDelete( t *testing.T ) {
	store := testStore( t )
	alice , _ := CreateUser( store , "Alice" , RoleUser )
	_ , key , _ := IssueAPIKey( store , alice.ID , "ci" , RoleUser , 0 )
	if err := PurgeAPIKey( store , key.ID ); err != nil { t.Fatal( err ) }
	if _ , err := GetAPIKey( store , key.ID ); !errors.Is( err , db.ErrNotFound ) {
		t.Fatal( "a purged key is still stored" )
	}
}

func TestInviteLinkSoftDelete( t *testing.T ) {
	store := testStore( t )
	admin , _ := CreateUser( store , "Admin" , RoleAdmin )
	user , _ := CreateUser( store , "Dan" , RoleUser )
	credential , link , err := IssueInviteLinkAs( store , admin.ID , "Club" , 5 , 1 )
	if err != nil { t.Fatal( err ) }

	if err := DeleteInviteLink( store , link.ID , admin.ID ); err != nil { t.Fatal( err ) }
	if _ , err := LoadInviteLink( store , credential ); !errors.Is( err , ErrInviteLinkInvalid ) {
		t.Fatal( "a deleted link still works" )
	}
	if links , _ := ListInviteLinks( store ); len( links ) != 0 {
		t.Fatal( "a deleted link is still listed" )
	}
	if _ , err := RestoreInviteLink( store , link.ID , user.ID , false ); !errors.Is( err , ErrRestoreForbidden ) {
		t.Fatalf( "a non-admin who did not delete it restoring: got %v" , err )
	}
	if _ , err := RestoreInviteLink( store , link.ID , admin.ID , true ); err != nil { t.Fatal( err ) }
	if _ , err := LoadInviteLink( store , credential ); err != nil {
		t.Fatal( "a restored link does not work" )
	}

	DeleteInviteLink( store , link.ID , admin.ID )
	backdate( t , store , db.BucketInviteLinks , link.ID , &InviteLink{} )
	if _ , err := RestoreInviteLink( store , link.ID , admin.ID , true ); !errors.Is( err , ErrRestoreExpired ) {
		t.Fatalf( "restore after the window: got %v" , err )
	}
	if removed , _ := PurgeDeadInviteLinks( store ); removed != 1 {
		t.Fatalf( "purge removed %d links, want 1" , removed )
	}
	if _ , err := RestoreInviteLink( store , "missing" , admin.ID , true ); !errors.Is( err , ErrRestoreGone ) {
		t.Fatalf( "restoring a missing link: got %v" , err )
	}
}

func TestRenameExpect( t *testing.T ) {
	store := testStore( t )
	alice , _ := CreateUser( store , "Alice" , RoleUser )
	expect := "Alice"
	if err := RenameUser( store , alice.ID , "Alice B" , &expect ); err != nil { t.Fatal( err ) }
	stale := "Alice C"
	err := RenameUser( store , alice.ID , "Alice" , &stale )
	var refusal *RenameConflictError
	if errors.As( err , &refusal ) == false || refusal.Current != "Alice B" {
		t.Fatalf( "a stale expect: got %v" , err )
	}
	if loaded , _ := GetUser( store , alice.ID ); loaded.DisplayName != "Alice B" {
		t.Fatal( "a refused rename still changed the name" )
	}
}
