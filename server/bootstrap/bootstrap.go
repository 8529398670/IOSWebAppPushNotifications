// Package bootstrap solves the chicken-and-egg problem this auth model
// creates: only an admin can mint a login link, and on a fresh database there
// is no admin to do it.
//
// So on first boot -- and only when no enabled admin exists -- the server
// creates one and prints a one-time login link to its own logs. Whoever can
// read the container logs is already trusted with the deployment, so this
// grants nothing they did not already have, and it means a fresh deploy is
// usable without a separate setup command.
package bootstrap

import (
	fmt "fmt"
	strings "strings"

	config "ipb/server/config"
	db "ipb/server/db"
	models "ipb/server/models"
)

// EnsureFirstAdmin is a no-op once any enabled admin exists, so restarting
// the container does not keep minting new admin accounts.
//
// It also adopts an owner for a database written before the owner marker
// existed (see models.EnsureOwner). A fresh database needs no adoption: the
// admin created below becomes the owner as it is created.
func EnsureFirstAdmin( store *db.Store , cfg *config.Config , display_name string ) ( err error ) {
	if _ , err = models.EnsureOwner( store ); err != nil { return }

	exists , err := models.AnyAdminExists( store )
	if err != nil { return }
	if exists {
		return
	}

	user , err := models.CreateUser( store , display_name , models.RoleAdmin )
	if err != nil { return }

	credential , err := models.IssueLoginToken( store , user.ID , cfg.LoginTokenTTL )
	if err != nil { return }

	PrintLoginLink( cfg , fmt.Sprintf( "first-run admin %q" , display_name ) , credential )
	return
}

// PrintAPIKey writes the one moment an API key is ever visible. It lives
// beside PrintLoginLink so that every path which reveals a credential is in
// one file, with one shape and one warning.
//
// Unlike a login link this is a complete credential, not a URL; the example
// request uses the same address the links do (see linkNote).
func PrintAPIKey( cfg *config.Config , label string , credential string , expires string ) {
	line := strings.Repeat( "-" , 72 )
	fmt.Println( line )
	fmt.Printf( "  API KEY -- %s\n" , label )
	fmt.Println( line )
	fmt.Printf( "  %s\n" , credential )
	fmt.Println( line )
	fmt.Printf( "  Expires: %s\n" , expires )
	fmt.Println( "  Send it as a header:" )
	fmt.Printf( "    curl -H \"Authorization: Bearer %s\" %s/api/me\n" , credential , cfg.URL )
	linkNote( cfg )
	fmt.Println( "  It is not stored anywhere and cannot be shown again. If it leaks," )
	fmt.Println( "  revoke it: ipb manage revoke-key -key-id <id>" )
	fmt.Println( line )
}

// PrintLoginLink writes the one moment a credential is ever visible, as one
// full URL you can click. The address is server.public_url when set; without
// it the server only knows its own listen address, which linkNote says
// rather than leaving a confidently wrong host unexplained.
func PrintLoginLink( cfg *config.Config , label string , credential string ) {
	line := strings.Repeat( "-" , 72 )
	fmt.Println( line )
	fmt.Printf( "  ONE-TIME LOGIN LINK -- %s\n" , label )
	fmt.Println( line )
	fmt.Printf( "  %s/login/%s\n" , cfg.URL , credential )
	fmt.Println( line )
	fmt.Printf( "  Valid once, for %s.\n" , cfg.LoginTokenTTL )
	linkNote( cfg )
	fmt.Println( "  It is not stored anywhere and cannot be shown again -- if you lose" )
	fmt.Println( "  it, mint another with scripts/login.sh (or: ipb manage" )
	fmt.Println( "  reissue-login -user-id <id>)." )
	fmt.Println( line )
}

// PrintInviteLink shows a new invite link once. Like a login link it is
// stored only as a hash, so this is the only time it can be copied.
func PrintInviteLink( cfg *config.Config , label string , credential string , expires string ) {
	line := strings.Repeat( "-" , 72 )
	fmt.Println( line )
	fmt.Printf( "  INVITE LINK -- %s\n" , label )
	fmt.Println( line )
	fmt.Printf( "  %s/join/%s\n" , cfg.URL , credential )
	fmt.Println( line )
	fmt.Printf( "  Works until %s.\n" , expires )
	linkNote( cfg )
	fmt.Println( "  Anyone holding it can join, so share it only where you mean to." )
	fmt.Println( "  It cannot be shown again; switch it off in the admin panel." )
	fmt.Println( line )
}

// linkNote says where the address in a printed link came from, so a link
// built from 127.0.0.1 is not mistaken for one other people can open.
func linkNote( cfg *config.Config ) {
	fmt.Printf( "  Address from %s.\n" , cfg.URLSource )
}
