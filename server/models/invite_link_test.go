package models

import (
	errors "errors"
	filepath "path/filepath"
	testing "testing"
	time "time"

	config "ipb/server/config"
	db "ipb/server/db"
)

// testStore opens a throwaway database. The Config is built by hand rather
// than through config.Load, which would find and maybe write a real
// config.yaml.
func testStore( t *testing.T ) ( store *db.Store ) {
	t.Helper()
	cfg := &config.Config{ DatabasePath: filepath.Join( t.TempDir() , "test.db" ) }
	store , err := db.Open( cfg )
	if err != nil { t.Fatal( err ) }
	t.Cleanup( func() { store.Close() } )
	return
}

func TestNameCloseness( t *testing.T ) {
	type pair struct {
		typed, existing string
		similar         bool
	}
	pairs := []pair{
		{ "Ana" , "ana" , true },
		{ "anna marie" , "Anna-Marie" , true },
		{ "Ann" , "Anna" , true },          // prefix
		{ "Jonathon" , "Jonathan" , true }, // one letter off
		{ "Katherine" , "Catherine" , true },
		{ "Bob" , "Rob" , true },
		{ "Bob" , "Sue" , false },
		{ "Al" , "Alexander" , false }, // too short to suggest by prefix
		{ "Michael" , "Rachel" , false },
	}
	for _ , item := range pairs {
		if got := NameCloseness( item.typed , item.existing ) >= 0; got != item.similar {
			t.Errorf( "%q vs %q: similar=%v, want %v" , item.typed , item.existing , got , item.similar )
		}
	}
	if NameCloseness( "ana" , "Ana" ) != 0 {
		t.Errorf( "an exact match should score 0" )
	}
}

func TestInviteLinkJoinClaimAndCapacity( t *testing.T ) {
	store := testStore( t )
	admin , _ := CreateUser( store , "Admin" , RoleAdmin )
	credential , link , err := IssueInviteLinkAs( store , admin.ID , "Book club" , 2 , 1 )
	if err != nil { t.Fatal( err ) }

	if _ , err := LoadInviteLink( store , link.ID+".wrong" ); !errors.Is( err , ErrInviteLinkInvalid ) {
		t.Fatalf( "wrong secret accepted: %v" , err )
	}
	if _ , _ , err := JoinInviteLink( store , link.ID+".wrong" , "Eve" , time.Hour ); !errors.Is( err , ErrInviteLinkInvalid ) {
		t.Fatalf( "joined with a wrong secret: %v" , err )
	}

	session , ana , err := JoinInviteLink( store , credential , "Ana" , time.Hour )
	if err != nil || session == "" || ana.Role != RoleUser { t.Fatalf( "join: %v" , err ) }
	if _ , user := LoadSession( store , session ); user == nil || user.ID != ana.ID {
		t.Fatalf( "joining did not store a usable session" )
	}
	if _ , _ , err := JoinInviteLink( store , credential , "Ben" , time.Hour ); err != nil { t.Fatal( err ) }
	if _ , _ , err := JoinInviteLink( store , credential , "Cy" , time.Hour ); !errors.Is( err , ErrInviteLinkFull ) {
		t.Fatalf( "third join on a two-place link: %v" , err )
	}

	// Someone who joined another way is never offered, even by an exact name.
	outsider , _ := CreateUser( store , "Anabel" , RoleUser )
	loaded , _ := LoadInviteLink( store , credential )
	matches , _ := InviteMatches( store , loaded , "anna" )
	if len( matches ) != 1 || matches[ 0 ].ID != ana.ID {
		t.Fatalf( "matches for anna: %v" , matches )
	}
	if _ , _ , err := ClaimInviteAccount( store , credential , outsider.ID , SignInRules{ SessionTTL: time.Hour } ); !errors.Is( err , ErrNotInviteAccount ) {
		t.Fatalf( "claimed an account the link did not create: %v" , err )
	}
	if _ , _ , err := ClaimInviteAccount( store , credential , ana.ID , SignInRules{ SessionTTL: time.Hour } ); err != nil {
		t.Fatalf( "claim: %v" , err )
	}

	RevokeInviteLink( store , link.ID )
	if _ , _ , err := ClaimInviteAccount( store , credential , ana.ID , SignInRules{ SessionTTL: time.Hour } ); !errors.Is( err , ErrInviteLinkInvalid ) {
		t.Fatalf( "claimed through a switched-off link" )
	}
}

// A link lives only as long as its maker is an enabled admin.
func TestInviteLinkFollowsCreator( t *testing.T ) {
	store := testStore( t )
	CreateUser( store , "Owner" , RoleAdmin ) // the owner can never be disabled
	admin , _ := CreateUser( store , "Cara" , RoleAdmin )
	credential , _ , err := IssueInviteLinkAs( store , admin.ID , "Club" , 5 , 1 )
	if err != nil { t.Fatal( err ) }
	if _ , err := LoadInviteLink( store , credential ); err != nil {
		t.Fatalf( "an admin's link should load: %v" , err )
	}
	SetUserDisabled( store , admin.ID , true )
	if _ , err := LoadInviteLink( store , credential ); !errors.Is( err , ErrInviteLinkInvalid ) {
		t.Fatalf( "link still loads after its maker was disabled" )
	}

	user , _ := CreateUser( store , "Dan" , RoleUser )
	if _ , _ , err := IssueInviteLinkAs( store , user.ID , "Nope" , 5 , 1 ); !errors.Is( err , ErrInviteNotAdmin ) {
		t.Fatalf( "a plain user made an invite link: %v" , err )
	}
}

func TestPin( t *testing.T ) {
	store := testStore( t )
	user , _ := CreateUser( store , "Ana" , RoleUser )
	if err := SetUserPin( store , user.ID , "12a4" ); !errors.Is( err , ErrBadPin ) {
		t.Fatalf( "letters in a pin: %v" , err )
	}
	if err := SetUserPin( store , user.ID , "4321" ); err != nil { t.Fatal( err ) }
	user , _ = GetUser( store , user.ID )
	if user.HasPin() == false || user.CheckPin( "4321" ) == false || user.CheckPin( "1234" ) || user.CheckPin( "" ) {
		t.Fatalf( "pin check wrong" )
	}
	SetUserPin( store , user.ID , "" )
	user , _ = GetUser( store , user.ID )
	if user.HasPin() || user.CheckPin( "" ) == false {
		t.Fatalf( "clearing the pin did not work" )
	}

	guard := NewAttemptGuard[ uint64 ]( AttemptMaxFailures )
	for range AttemptMaxFailures {
		guard.Record( user.ID , false )
	}
	if guard.Locked( user.ID ) == false {
		t.Fatalf( "%d wrong PINs did not lock" , AttemptMaxFailures )
	}
}
