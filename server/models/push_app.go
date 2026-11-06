package models

import (
	errors "errors"
	sort "sort"
	strings "strings"
	time "time"

	db "ipb/server/db"
	encryption "ipb/server/encryption"
)

const (
	// PushAppNameMax is the longest name, kept short because it leads every
	// notification's title.
	PushAppNameMax = 60

	MediaIcon  = "icon"
	MediaSound = "sound"
)

var (
	ErrPushAppName  = errors.New( "an app needs a name of up to 60 characters" )
	ErrAppToken     = errors.New( "application token is invalid" )
	ErrPushAppGone  = errors.New( "no such app" )
)

// PushApp is a virtual app inside iPB: a doorbell, a server alert. Each has its
// own token, name, icon and sound, and each person can mute it on its own.
//
// The token is "<id>.<secret>" with only the sha256 of the secret stored, the
// same shape and the same reasoning as an API key: one fetch by id, one
// comparison, and a 192 bit secret needs no bcrypt. A token can do exactly one
// thing, which is send as this app, so losing one costs nothing else.
type PushApp struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	OwnerID   uint64    `json:"owner_id"`
	TokenHash string    `json:"token_hash"`
	HasIcon   bool      `json:"has_icon"`
	HasSound  bool      `json:"has_sound"`
	// MediaVersion changes with the icon or sound, so a browser asks again.
	MediaVersion int       `json:"media_version"`
	CreatedAt    time.Time `json:"created_at"`
	SoftDelete
}

// PushAppMedia is an icon or sound. It is kept apart from the app because the
// app is read on every send, and a sound can be most of a megabyte.
type PushAppMedia struct {
	ContentType string `json:"content_type"`
	Data        []byte `json:"data"`
}

func newAppSecret() ( secret string , hash string ) {
	secret = encryption.GenerateURLToken( 24 )
	hash = encryption.Sha256Hex( secret )
	return
}

func cleanAppName( name string ) ( result string , err error ) {
	result = strings.TrimSpace( name )
	if result == "" || len( []rune( result ) ) > PushAppNameMax {
		err = ErrPushAppName
	}
	return
}

// CreatePushApp returns the app and its token. The token is never stored and
// cannot be shown again; RotatePushAppToken makes another.
func CreatePushApp( store *db.Store , owner_id uint64 , name string ) ( app *PushApp , token string , err error ) {
	clean , err := cleanAppName( name )
	if err != nil { return }
	secret , hash := newAppSecret()
	app = &PushApp{
		ID:        encryption.GenerateURLToken( 9 ),
		Name:      clean,
		OwnerID:   owner_id,
		TokenHash: hash,
		CreatedAt: time.Now().UTC(),
	}
	if err = store.Put( db.BucketPushApps , []byte( app.ID ) , app ); err != nil {
		app = nil
		return
	}
	token = app.ID + "." + secret
	return
}

// GetPushApp loads a live app; ErrPushAppGone when there is none.
func GetPushApp( store *db.Store , app_id string ) ( app *PushApp , err error ) {
	found := &PushApp{}
	err = store.Get( db.BucketPushApps , []byte( app_id ) , found )
	if errors.Is( err , db.ErrNotFound ) || ( err == nil && found.Deleted() ) {
		err = ErrPushAppGone
		return
	}
	if err != nil { return }
	app = found
	return
}

// ListPushApps is every live app, by name. Everyone sees them all, because
// muting an app starts with finding it.
func ListPushApps( store *db.Store ) ( apps []*PushApp , err error ) {
	apps = []*PushApp{}
	err = store.ForEach( db.BucketPushApps ,
		func() any { return &PushApp{} } ,
		func( _ []byte , item any ) bool {
			app := item.( *PushApp )
			if app.Deleted() == false { apps = append( apps , app ) }
			return true
		} )
	sort.Slice( apps , func( a int , b int ) bool {
		return strings.ToLower( apps[ a ].Name ) < strings.ToLower( apps[ b ].Name )
	} )
	return
}

// AuthenticateAppToken is the send route's whole idea of who is calling. Every
// way of being wrong gets the same error.
func AuthenticateAppToken( store *db.Store , token string ) ( app *PushApp , err error ) {
	app_id , secret , ok := splitCredential( strings.TrimSpace( token ) )
	if ok == false {
		err = ErrAppToken
		return
	}
	found , get_err := GetPushApp( store , app_id )
	if get_err != nil {
		err = ErrAppToken
		return
	}
	if encryption.ConstantTimeEqual( found.TokenHash , encryption.Sha256Hex( secret ) ) == false {
		err = ErrAppToken
		return
	}
	app = found
	return
}

func updatePushApp( store *db.Store , app_id string , mutate func( app *PushApp ) error ) ( err error ) {
	err = store.UpdateValue( db.BucketPushApps , []byte( app_id ) ,
		func() any { return &PushApp{} } ,
		func( item any ) ( mutate_err error ) {
			mutate_err = mutate( item.( *PushApp ) )
			return
		} )
	if errors.Is( err , db.ErrNotFound ) { err = ErrPushAppGone }
	return
}

// RenamePushApp changes the name. The id, and so the token, stay.
func RenamePushApp( store *db.Store , app_id string , name string ) ( err error ) {
	clean , err := cleanAppName( name )
	if err != nil { return }
	err = updatePushApp( store , app_id , func( app *PushApp ) ( mutate_err error ) {
		if app.Deleted() {
			mutate_err = ErrPushAppGone
			return
		}
		app.Name = clean
		return
	} )
	return
}

// RotatePushAppToken ends the old token at once and returns the new one.
func RotatePushAppToken( store *db.Store , app_id string ) ( token string , err error ) {
	secret , hash := newAppSecret()
	err = updatePushApp( store , app_id , func( app *PushApp ) ( mutate_err error ) {
		if app.Deleted() {
			mutate_err = ErrPushAppGone
			return
		}
		app.TokenHash = hash
		return
	} )
	if err != nil { return }
	token = app_id + "." + secret
	return
}

// DeletePushApp stops the token working straight away. Messages it already
// sent stay in people's inboxes.
func DeletePushApp( store *db.Store , app_id string , actor_id uint64 ) ( err error ) {
	err = updatePushApp( store , app_id , func( app *PushApp ) ( mutate_err error ) {
		app.markDeleted( actor_id )
		return
	} )
	return
}

func RestorePushApp( store *db.Store , app_id string , actor_id uint64 , actor_is_admin bool ) ( err error ) {
	err = updatePushApp( store , app_id , func( app *PushApp ) ( mutate_err error ) {
		mutate_err = app.unmarkDeleted( actor_id , actor_is_admin )
		return
	} )
	return
}

func mediaKey( app_id string , kind string ) ( key []byte ) {
	key = []byte( app_id + "/" + kind )
	return
}

// SetPushAppMedia stores an icon or sound, or clears it when data is empty.
func SetPushAppMedia( store *db.Store , app_id string , kind string , content_type string , data []byte ) ( err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		app := &PushApp{}
		if tx_err = tx.Get( db.BucketPushApps , []byte( app_id ) , app ); tx_err != nil { return }
		if app.Deleted() {
			tx_err = ErrPushAppGone
			return
		}
		present := len( data ) > 0
		if present {
			tx_err = tx.Put( db.BucketPushAppMedia , mediaKey( app_id , kind ) , &PushAppMedia{ ContentType: content_type , Data: data } )
		} else {
			tx_err = tx.Delete( db.BucketPushAppMedia , mediaKey( app_id , kind ) )
		}
		if tx_err != nil { return }
		if kind == MediaIcon { app.HasIcon = present } else { app.HasSound = present }
		app.MediaVersion += 1
		tx_err = tx.Put( db.BucketPushApps , []byte( app_id ) , app )
		return
	} )
	if errors.Is( err , db.ErrNotFound ) { err = ErrPushAppGone }
	return
}

// GetPushAppMedia loads an icon or sound; db.ErrNotFound when it has none.
func GetPushAppMedia( store *db.Store , app_id string , kind string ) ( media *PushAppMedia , err error ) {
	found := &PushAppMedia{}
	if err = store.Get( db.BucketPushAppMedia , mediaKey( app_id , kind ) , found ); err != nil { return }
	media = found
	return
}

// PurgeDeadPushApps removes apps past their undo window, and their media.
func PurgeDeadPushApps( store *db.Store ) ( removed int , err error ) {
	err = store.Write( func( tx *db.Tx ) ( tx_err error ) {
		doomed := []string{}
		removed , tx_err = tx.DeleteWhere( db.BucketPushApps ,
			func() any { return &PushApp{} } ,
			func( _ []byte , item any ) ( match bool ) {
				app := item.( *PushApp )
				match = app.deletedLongAgo()
				if match { doomed = append( doomed , app.ID ) }
				return
			} )
		if tx_err != nil { return }
		for _ , app_id := range doomed {
			if tx_err = tx.Delete( db.BucketPushAppMedia , mediaKey( app_id , MediaIcon ) ); tx_err != nil { return }
			if tx_err = tx.Delete( db.BucketPushAppMedia , mediaKey( app_id , MediaSound ) ); tx_err != nil { return }
		}
		return
	} )
	return
}
